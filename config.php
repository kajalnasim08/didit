<?php
// config.php
// Edit these values for your environment.

// DIDIT webhook secret (set this to the secret from your Didit dashboard)
define('DIDIT_WEBHOOK_SECRET', 'replace_with_your_didit_webhook_secret_here');

// Signature & timestamp header names used by Didit (recommended)
define('DIDIT_SIGNATURE_HEADER', 'X-Signature-V2');
define('DIDIT_TIMESTAMP_HEADER', 'X-Timestamp');

// HMAC algorithm used (for reference)
define('DIDIT_HMAC_ALGO', 'sha256');

// How many seconds of clock skew to allow for the timestamp header (default 5 minutes)
define('DIDIT_TIMESTAMP_TOLERANCE', 300);

// Path to a log file for webhook events (ensure web server can write to it)
define('LOG_PATH', __DIR__ . '/didit_webhook.log');

// Require HTTPS for webhook endpoints (recommended: true in production)
define('REQUIRE_HTTPS', true);

// Database (PDO) settings - update to match your DB
define('DB_DSN', 'mysql:host=127.0.0.1;dbname=your_db;charset=utf8mb4');
define('DB_USER', 'db_user');
define('DB_PASS', 'db_pass');

// Table used to store webhook audit/idempotency records
define('WEBHOOK_IDEMPOTENCY_TABLE', 'webhook_logs');

// Toggle detailed logging (useful for debugging; set false in production)
define('DIDIT_DEBUG_LOG', true);

// End of config.php
