<?php
// debug_test.php - diagnostic runner to show which step (include, DB, normalize, send) fails/hangs.
// Usage (CLI):
//   C:\xampp\php\php.exe "C:\xampp\htdocs\NEW\debug_test.php" 09518609962 "Hello from server"

ini_set('display_errors', 1);
error_reporting(E_ALL);

// Include config and send_sms first (no output before includes)
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/gateway_config.php';
require_once __DIR__ . '/API/send_sms.php';

// small helper to print status and flush
function step($msg) {
    echo "[" . date('H:i:s') . "] " . $msg . PHP_EOL;
    if (function_exists('fastcgi_finish_request')) { fastcgi_finish_request(); }
    @flush();
    @ob_flush();
}

step('start');

$phone = $argv[1] ?? null;
$message = $argv[2] ?? null;

if (!$phone || !$message) {
    step('usage: php debug_test.php 09518609962 "Hello from server"');
    exit(1);
}

step('checking curl extension');
if (!extension_loaded('curl')) {
    step('ERROR: curl extension not loaded in PHP CLI. Run: php -m to confirm.');
    exit(1);
}
step('curl OK');

step('normalize phone');
$normalized = null;
if (function_exists('normalize_ph_number')) {
    try {
        $normalized = normalize_ph_number($phone);
    } catch (Throwable $e) {
        step('normalize_ph_number threw: ' . $e->getMessage());
    }
} elseif (function_exists('normalizePhone')) {
    try { $normalized = normalizePhone($phone); } catch (Throwable $e) { step('normalizePhone threw: ' . $e->getMessage()); }
}
step('normalized -> ' . var_export($normalized, true));
if (empty($normalized)) {
    step('ERROR: phone normalization failed');
    exit(1);
}

step('calling sendSMS (this will perform an HTTP call to gateway)');
try {
    $res = sendSMS($normalized, $message, 'SMMS', 'Debug', $db ?? null);
} catch (Throwable $e) {
    step('sendSMS threw exception: ' . $e->getMessage());
    exit(1);
}
step('sendSMS returned: ' . json_encode($res));

step('done');