<?php
// process_queue.php
// CLI worker to process sms_queue and deliver to Android gateway device.
// Enhanced with logging for debugging. Run from CLI: php process_queue.php
// Back up original file before replacing.

if (php_sapi_name() !== 'cli') {
    echo "This script is intended to be run from CLI only.\n";
    exit(1);
}

$logFile = __DIR__ . '/process_queue.log';
function logw($msg) {
    global $logFile;
    $line = "[".date('c')."] " . $msg . PHP_EOL;
    // append to file
    @file_put_contents($logFile, $line, FILE_APPEND);
    // also echo to stdout
    echo $msg . PHP_EOL;
}

// bootstrap
logw("process_queue.php START (pid=" . getmypid() . ")");

// load gateway config and app config
try {
    require_once __DIR__ . '/gateway_config.php';
} catch (Throwable $e) {
    logw("ERROR: failed to include gateway_config.php: " . $e->getMessage());
    exit(1);
}

try {
    require_once __DIR__ . '/config.php'; // should define $db or provide DB wrapper used by app
} catch (Throwable $e) {
    logw("ERROR: failed to include config.php: " . $e->getMessage());
    exit(1);
}

try {
    require_once __DIR__ . '/API/send_sms.php';
} catch (Throwable $e) {
    logw("ERROR: failed to include API/send_sms.php: " . $e->getMessage());
    exit(1);
}

// Basic credential fallback helpful for CLI envs (only if not defined)
if (!defined('GATEWAY_BASE')) {
    define('GATEWAY_BASE', getenv('GATEWAY_BASE') ?: 'https://api.sms-gate.app/3rdparty/v1');
}
if (!defined('GATEWAY_AUTH_TYPE')) {
    define('GATEWAY_AUTH_TYPE', getenv('GATEWAY_AUTH_TYPE') ?: 'basic');
}
if (!defined('GATEWAY_USERNAME')) {
    $gw_user = getenv('GATEWAY_USERNAME');
    if ($gw_user !== false && $gw_user !== '') define('GATEWAY_USERNAME', $gw_user);
}
if (!defined('GATEWAY_PASSWORD')) {
    $gw_pass = getenv('GATEWAY_PASSWORD');
    if ($gw_pass !== false && $gw_pass !== '') define('GATEWAY_PASSWORD', $gw_pass);
}

// Sanity: check DB object existence
if (!isset($db)) {
    logw("ERROR: DB object \$db not found (config.php should provide it).");
    exit(1);
}

// settings
$maxAttempts = 6;
$batchSize = 50;

// fetch queued rows
try {
    $rows = $db->fetchAll("SELECT * FROM sms_queue WHERE status IN ('queued','sending') AND attempts < ? ORDER BY created_at ASC LIMIT ?", [$maxAttempts, $batchSize]) ?: [];
    logw("Found " . count($rows) . " queued rows (limit={$batchSize}).");
} catch (Throwable $e) {
    logw("ERROR: DB select failed: " . $e->getMessage());
    exit(1);
}

foreach ($rows as $r) {
    $id = (int)$r['id'];
    $to = $r['recipient'] ?? '';
    $body = $r['body'] ?? '';

    logw("Processing id={$id} to={$to} attempts={$r['attempts']} status={$r['status']}");

    // mark sending
    try {
        $db->query("UPDATE sms_queue SET status = 'sending', updated_at = NOW() WHERE id = ?", [$id]);
    } catch (Throwable $e) {
        logw("WARN: failed to mark sending for id {$id}: " . $e->getMessage());
        // continue - attempt send anyway, but it may cause duplicate sends if concurrent
    }

    // call gateway
    try {
        $result = _sendToGateway($to, $body);
    } catch (Throwable $e) {
        $result = ['ok' => false, 'raw' => null, 'http' => 0, 'error' => 'exception: '.$e->getMessage(), 'message_id' => null];
    }

    logw("id={$id} _sendToGateway result: " . json_encode($result));

    // persist result
    try {
        if (!empty($result['ok'])) {
            $db->query("UPDATE sms_queue SET status = 'sent', provider_response = ?, external_id = ?, attempts = attempts + 1, updated_at = NOW() WHERE id = ?", [$result['raw'], $result['message_id'], $id]);
            $db->query("INSERT INTO sms_events (queue_id, event_type, event_payload, created_at) VALUES (?, 'sent', ?, NOW())", [$id, json_encode($result)]);
            logw("id={$id} marked sent, message_id={$result['message_id']}");
        } else {
            $err = is_scalar($result['error']) ? $result['error'] : json_encode($result['error']);
            $raw = $result['raw'] ?? null;
            $db->query("UPDATE sms_queue SET status = 'queued', attempts = attempts + 1, last_error = ?, provider_response = ?, updated_at = NOW() WHERE id = ?", [$err, $raw, $id]);
            $db->query("INSERT INTO sms_events (queue_id, event_type, event_payload, created_at) VALUES (?, 'send_failed', ?, NOW())", [$id, json_encode($result)]);
            logw("id={$id} send failed, error={$err}");
        }
    } catch (Throwable $e) {
        logw("ERROR: DB update failed for id {$id}: " . $e->getMessage());
    }

    // short sleep to avoid hammering gateway
    usleep(200000);
}

logw("process_queue.php DONE.");
exit(0);