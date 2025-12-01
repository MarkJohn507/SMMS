<?php
// send_one_cli.php
// CLI test: attempt to send a single sms_queue row via your existing sendSMS() function
// Usage: php send_one_cli.php <id>
// Example: php send_one_cli.php 8

if (php_sapi_name() !== 'cli') { echo "Run from CLI\n"; exit(1); }
$id = (int)($argv[1] ?? 0);
if ($id <= 0) { echo "Usage: php send_one_cli.php <id>\n"; exit(1); }

require_once __DIR__ . '/gateway_config.php';
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/API/send_sms.php';

echo "Using GATEWAY_BASE=" . (defined('GATEWAY_BASE') ? GATEWAY_BASE : getenv('GATEWAY_BASE')) . PHP_EOL;
echo "Using GATEWAY_AUTH_TYPE=" . (defined('GATEWAY_AUTH_TYPE') ? GATEWAY_AUTH_TYPE : getenv('GATEWAY_AUTH_TYPE')) . PHP_EOL;
echo "Using GATEWAY_USERNAME=" . (defined('GATEWAY_USERNAME') ? GATEWAY_USERNAME : getenv('GATEWAY_USERNAME')) . PHP_EOL;

try {
    $row = $db->fetch("SELECT * FROM sms_queue WHERE id = ? LIMIT 1", [$id]);
} catch (Throwable $e) {
    echo "DB select failed: " . $e->getMessage() . PHP_EOL;
    exit(1);
}
if (!$row) {
    echo "Row id={$id} not found\n";
    exit(1);
}
echo "Row: id={$row['id']} recipient={$row['recipient']} status={$row['status']} attempts={$row['attempts']}\n";

try {
    $res = sendSMS($row['recipient'], $row['body']);
} catch (Throwable $e) {
    $res = ['ok'=>false,'error'=>'exception: '.$e->getMessage(),'raw'=>null,'http'=>0,'message_id'=>null];
}

echo "sendSMS result: " . print_r($res, true) . PHP_EOL;

// If you want to update DB here uncomment below (optional):
/*
if (!empty($res['ok'])) {
    $db->query("UPDATE sms_queue SET status='sent', provider_response = ?, external_id = ?, attempts = attempts + 1, updated_at = NOW() WHERE id = ?", [$res['raw'] ?? null, $res['message_id'] ?? null, $id]);
    echo "Marked sent in DB\n";
} else {
    $db->query("UPDATE sms_queue SET status='queued', attempts = attempts + 1, last_error = ?, provider_response = ?, updated_at = NOW() WHERE id = ?", [$res['error'] ?? null, $res['raw'] ?? null, $id]);
    echo "Updated DB as failed/queued\n";
}
*/