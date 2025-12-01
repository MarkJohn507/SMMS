<?php
// gateway_webhook_debug.php
// Debug endpoint: logs headers + body to a file for inspection.
// Deploy under your public folder and register this URL on the device, then send an SMS.

$logFile = __DIR__ . '/webhook_debug.log';
$ts = date('c');

// collect headers (case insensitive)
$headers = [];
if (function_exists('getallheaders')) {
    foreach (getallheaders() as $k => $v) $headers[$k] = $v;
} else {
    foreach ($_SERVER as $k => $v) {
        if (substr($k, 0, 5) === 'HTTP_') {
            $name = str_replace(' ', '-', ucwords(str_replace('_', ' ', strtolower(substr($k,5)))));
            $headers[$name] = $v;
        }
    }
}

$body = file_get_contents('php://input');

// also capture raw POST variables if any
$postVars = $_POST;

// Build log entry
$entry = "=== $ts ===\nREQUEST LINE: {$_SERVER['REQUEST_METHOD']} {$_SERVER['REQUEST_URI']}\n\nHEADERS:\n";
foreach ($headers as $k => $v) $entry .= "$k: $v\n";
$entry .= "\nCONTENT-TYPE: " . ($_SERVER['CONTENT_TYPE'] ?? '') . "\n\nBODY (raw):\n" . $body . "\n\n";
if (!empty($postVars)) {
    $entry .= "BODY (parsed \$_POST):\n" . print_r($postVars, true) . "\n\n";
}
file_put_contents($logFile, $entry, FILE_APPEND | LOCK_EX);

header('Content-Type: application/json');
echo json_encode(['ok' => true, 'logged_to' => $logFile]);