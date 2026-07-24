<?php
// sign_payload.php
// Local helper to produce canonical JSON + signature for testing the handler.
// Usage: php sign_payload.php > output.txt
// Then use output.txt as the body and include X-Signature-V2 and X-Timestamp headers.

$payload = [
    'order_id' => 'ORD123',
    'transaction_id' => 'TX' . rand(1000,9999),
    'status' => 'paid',
    'amount' => 100.00,
    'currency' => 'USD',
    'metadata' => ['customer' => 'test@example.com']
];

function is_assoc_array(array $arr) {
    if (array() === $arr) return false;
    return array_keys($arr) !== range(0, count($arr) - 1);
}

function canonicalize_value($v) {
    if (is_array($v)) {
        if (is_assoc_array($v)) {
            $keys = array_keys($v);
            sort($keys, SORT_STRING);
            $out = [];
            foreach ($keys as $k) {
                $out[$k] = canonicalize_value($v[$k]);
            }
            return $out;
        } else {
            $out = [];
            foreach ($v as $item) $out[] = canonicalize_value($item);
            return $out;
        }
    }
    return $v;
}

$canon = json_encode(canonicalize_value($payload), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | (defined('JSON_PRESERVE_ZERO_FRACTION') ? JSON_PRESERVE_ZERO_FRACTION : 0));
$secret = 'replace_with_your_didit_webhook_secret_here';
$sig = hash_hmac('sha256', $canon, $secret);
$timestamp = time();

echo "===CANONICAL_JSON===\n";
echo $canon . "\n\n";
echo "===SIG===\n";
echo $sig . "\n\n";
echo "===TIMESTAMP===\n";
echo $timestamp . "\n";
