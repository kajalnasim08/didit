<?php
// ipn_handler.php
// Drop this at the endpoint Didit posts to (e.g., /webhooks/didit.php).
// Requires config.php in the same directory with the DIDIT_* and DB_* constants.

require_once __DIR__ . '/config.php';

/**
 * Simple logger — honors DIDIT_DEBUG_LOG and appends to LOG_PATH.
 */
function didit_log($msg) {
    $prefix = '[' . date('c') . '] ';
    $line = $prefix . $msg . PHP_EOL;
    if (defined('LOG_PATH') && LOG_PATH) {
        @file_put_contents(LOG_PATH, $line, FILE_APPEND | LOCK_EX);
    }
    if (defined('DIDIT_DEBUG_LOG') && DIDIT_DEBUG_LOG) {
        error_log($line);
    }
}

/**
 * Timing-safe comparison wrapper.
 */
function safe_equals($a, $b) {
    if (function_exists('hash_equals')) {
        return hash_equals((string)$a, (string)$b);
    }
    if (strlen($a) !== strlen($b)) return false;
    $res = $a ^ $b;
    $ret = 0;
    for ($i = strlen($res) - 1; $i >= 0; $i--) {
        $ret |= ord($res[$i]);
    }
    return $ret === 0;
}

/**
 * Get raw request body.
 */
function get_raw_body() {
    return file_get_contents('php://input');
}

/**
 * Case-insensitive header fetch. Works with getallheaders() when available, otherwise falls back to $_SERVER.
 */
function get_header_value($name) {
    // normalize
    $lname = strtolower($name);
    if (function_exists('getallheaders')) {
        $all = getallheaders();
        foreach ($all as $k => $v) {
            if (strtolower($k) === $lname) return $v;
        }
    }
    // fallback to $_SERVER
    $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
    if (isset($_SERVER[$key])) return $_SERVER[$key];
    // Some servers place Content-Type without HTTP_ prefix
    if (strtolower($name) === 'content-type' && isset($_SERVER['CONTENT_TYPE'])) return $_SERVER['CONTENT_TYPE'];
    return null;
}

/**
 * Determine if array is associative.
 */
function is_assoc_array(array $arr) {
    if (array() === $arr) return false;
    return array_keys($arr) !== range(0, count($arr) - 1);
}

/**
 * Recursively sort object keys (associative arrays) for canonical JSON.
 * Arrays (numeric) preserve order.
 */
function canonicalize_value($v) {
    if (is_array($v)) {
        if (is_assoc_array($v)) {
            // associative: sort keys and canonicalize each value
            $keys = array_keys($v);
            sort($keys, SORT_STRING);
            $out = [];
            foreach ($keys as $k) {
                $out[$k] = canonicalize_value($v[$k]);
            }
            return $out;
        } else {
            // numeric array: preserve order, canonicalize elements
            $out = [];
            foreach ($v as $item) {
                $out[] = canonicalize_value($item);
            }
            return $out;
        }
    }
    // scalars — preserve as-is. json_encode will handle types.
    return $v;
}

/**
 * Canonical JSON: parse, recursively sort object keys, and re-encode with stable JSON flags.
 * Returns canonical JSON string on success, or false on parse failure.
 */
function canonical_json($rawJson) {
    $decoded = json_decode($rawJson, true);
    if ($decoded === null && json_last_error() !== JSON_ERROR_NONE) {
        return false;
    }
    $canon = canonicalize_value($decoded);
    // Use flags to preserve unicode and slashes; preserve zero fraction for floats when available.
    $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
    if (defined('JSON_PRESERVE_ZERO_FRACTION')) $flags |= JSON_PRESERVE_ZERO_FRACTION;
    // Compact deterministic encoding
    $encoded = json_encode($canon, $flags);
    return $encoded;
}

/**
 * Verify Didit signature.
 * - prefers DIDIT_SIGNATURE_HEADER (X-Signature-V2) which uses canonical JSON
 * - falls back to legacy X-Signature which signs raw body bytes
 *
 * Returns array: [bool $ok, string $usedAlgo, string $computedSig]
 */
function verify_signature($rawBody) {
    $sigHeaderName = defined('DIDIT_SIGNATURE_HEADER') ? DIDIT_SIGNATURE_HEADER : 'X-Signature-V2';
    $timestampHeaderName = defined('DIDIT_TIMESTAMP_HEADER') ? DIDIT_TIMESTAMP_HEADER : 'X-Timestamp';
    $sigValue = get_header_value($sigHeaderName);
    $timestampValue = get_header_value($timestampHeaderName);

    // Validate timestamp if present and configured
    if (defined('DIDIT_TIMESTAMP_TOLERANCE') && DIDIT_TIMESTAMP_TOLERANCE > 0) {
        if (empty($timestampValue)) {
            didit_log('Missing timestamp header: ' . $timestampHeaderName);
            return [false, 'timestamp_missing', ''];
        }
        // Accept integer unix seconds or ISO8601 parseable string
        if (is_numeric($timestampValue)) {
            $ts = (int)$timestampValue;
        } else {
            $ts = strtotime($timestampValue);
            if ($ts === false) {
                didit_log('Invalid timestamp format: ' . $timestampValue);
                return [false, 'timestamp_invalid', ''];
            }
        }
        $now = time();
        if (abs($now - $ts) > DIDIT_TIMESTAMP_TOLERANCE) {
            didit_log("Timestamp outside tolerance: header={$timestampValue} (ts={$ts}) now={$now}");
            return [false, 'timestamp_skew', ''];
        }
    }

    // Preferred: X-Signature-V2 (canonical JSON)
    if (!empty($sigValue)) {
        // Signature header might come as "sha256=..." or just hex. Extract hex portion.
        if (strpos($sigValue, '=') !== false) {
            list($algoTag, $hex) = explode('=', $sigValue, 2);
            $sigHex = $hex;
        } else {
            $sigHex = $sigValue;
        }

        // Try canonical JSON first
        $canonical = canonical_json($rawBody);
        if ($canonical !== false) {
            $expected = hash_hmac('sha256', $canonical, DIDIT_WEBHOOK_SECRET);
            if (safe_equals($expected, $sigHex)) {
                return [true, 'v2_canonical', $expected];
            }
            // If canonical fails or mismatch, fall through to legacy raw body check below as fallback
            didit_log('Signature V2 mismatch using canonical JSON');
        } else {
            didit_log('Canonical JSON failed to parse; cannot verify X-Signature-V2');
            // fall back to raw-body verification if needed below
        }
    }

    // Fallback: try legacy header names and raw-body signature
    $legacyHeaders = ['X-Signature', 'X-Signature-Simple'];
    foreach ($legacyHeaders as $h) {
        $v = get_header_value($h);
        if (empty($v)) continue;
        $sig = (strpos($v, '=') !== false) ? explode('=', $v, 2)[1] : $v;
        $expected = hash_hmac('sha256', $rawBody, DIDIT_WEBHOOK_SECRET);
        if (safe_equals($expected, $sig)) {
            return [true, 'legacy_raw', $expected];
        }
    }

    return [false, 'signature_mismatch', ''];
}

/**
 * Minimal payload validation — adjust required keys to suit your integration.
 */
function validate_payload(array $data, array $required = ['order_id','transaction_id','status','amount','currency']) {
    $missing = [];
    foreach ($required as $k) {
        if (!array_key_exists($k, $data) || $data[$k] === '' || $data[$k] === null) {
            $missing[] = $k;
        }
    }
    return $missing;
}

/**
 * Main handler flow
 */
try {
    // Ensure POST
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        header('Allow: POST');
        echo 'Method Not Allowed';
        exit;
    }

    // Enforce HTTPS if configured
    if (defined('REQUIRE_HTTPS') && REQUIRE_HTTPS) {
        $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
                   || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https');
        if (!$isHttps) {
            http_response_code(403);
            echo 'HTTPS required';
            didit_log('Rejected non-HTTPS request');
            exit;
        }
    }

    $raw = get_raw_body();
    if ($raw === '' || $raw === null) {
        http_response_code(400);
        echo 'Empty body';
        didit_log('Empty request body');
        exit;
    }

    // Verify signature & timestamp
    list($ok, $reason, $computed) = verify_signature($raw);
    if (!$ok) {
        http_response_code(403);
        echo 'Invalid signature or timestamp';
        didit_log('Signature verification failed: ' . $reason);
        exit;
    }

    // Parse payload
    $payload = json_decode($raw, true);
    if (!is_array($payload)) {
        http_response_code(400);
        echo 'Invalid JSON payload';
        didit_log('Invalid JSON after signature verification; raw: ' . substr($raw, 0, 2000));
        exit;
    }

    // Validate minimal keys
    $missing = validate_payload($payload);
    if (!empty($missing)) {
        http_response_code(400);
        echo 'Missing fields: ' . implode(',', $missing);
        didit_log('Missing payload fields: ' . implode(',', $missing) . ' payload: ' . json_encode($payload));
        exit;
    }

    // Connect to DB (PDO)
    $pdo = new PDO(DB_DSN, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);

    // Idempotency check: has this transaction been processed?
    $tx = (string)$payload['transaction_id'];
    $stmt = $pdo->prepare('SELECT id FROM ' . WEBHOOK_IDEMPOTENCY_TABLE . ' WHERE transaction_id = :tx LIMIT 1');
    $stmt->execute([':tx' => $tx]);
    if ($stmt->fetch()) {
        // Already processed — acknowledge
        http_response_code(200);
        echo 'Already processed';
        didit_log('Duplicate webhook for tx=' . $tx);
        exit;
    }

    $pdo->beginTransaction();

    // Insert audit log
    $insertLog = $pdo->prepare('INSERT INTO ' . WEBHOOK_IDEMPOTENCY_TABLE . ' (transaction_id, order_id, payload, created_at) VALUES (:tx, :order, :payload, NOW())');
    $insertLog->execute([
        ':tx' => $tx,
        ':order' => $payload['order_id'],
        ':payload' => json_encode($payload),
    ]);

    // Lock and fetch the order row
    $orderSelect = $pdo->prepare('SELECT id, total_amount, currency, status FROM orders WHERE external_order_id = :external LIMIT 1 FOR UPDATE');
    $orderSelect->execute([':external' => $payload['order_id']]);
    $order = $orderSelect->fetch();

    if (!$order) {
        // Unknown order: rollback and decide policy (here we return 400)
        $pdo->rollBack();
        http_response_code(400);
        echo 'Order not found';
        didit_log('Order not found: ' . $payload['order_id'] . ' tx=' . $tx);
        exit;
    }

    // Validate amount and currency
    $receivedAmount = (float)$payload['amount'];
    $expectedAmount = (float)$order['total_amount'];
    if ($receivedAmount !== $expectedAmount || $payload['currency'] !== $order['currency']) {
        $pdo->rollBack();
        http_response_code(400);
        echo 'Amount or currency mismatch';
        didit_log('Amount/currency mismatch for order ' . $payload['order_id'] . ' tx=' . $tx . ' received=' . $receivedAmount . ' ' . $payload['currency'] . ' expected=' . $expectedAmount . ' ' . $order['currency']);
        exit;
    }

    // Map Didit status to local order statuses (customize as necessary)
    $mapping = [
        'paid' => 'paid',
        'completed' => 'paid',
        'captured' => 'paid',
        'failed' => 'failed',
        'refunded' => 'refunded',
        'pending' => 'pending',
    ];
    $incomingStatus = strtolower((string)$payload['status']);
    $newStatus = $mapping[$incomingStatus] ?? null;

    if ($newStatus === null) {
        // Unknown status — log and acknowledge without changing order
        $pdo->commit();
        http_response_code(200);
        echo 'Unknown status logged';
        didit_log('Unknown status from Didit: ' . $payload['status'] . ' for order ' . $payload['order_id'] . ' tx=' . $tx);
        exit;
    }

    // Update order only if different
    if ($order['status'] !== $newStatus) {
        $update = $pdo->prepare('UPDATE orders SET status = :status, transaction_id = :tx, updated_at = NOW() WHERE id = :id');
        $update->execute([
            ':status' => $newStatus,
            ':tx' => $tx,
            ':id' => $order['id'],
        ]);
    }

    $pdo->commit();

    // Respond 200 and log
    http_response_code(200);
    echo 'OK';
    didit_log('Processed webhook: order=' . $payload['order_id'] . ' tx=' . $tx . ' status=' . $newStatus . ' (sig verified)');

} catch (Exception $e) {
    if (isset($pdo) && $pdo->inTransaction()) {
        $pdo->rollBack();
    }
    didit_log('Exception while processing webhook: ' . $e->getMessage() . ' raw=' . substr($raw ?? '', 0, 2000));
    http_response_code(500);
    echo 'Server error';
    exit;
}
