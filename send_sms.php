<?php
// process_queue.php
// Run from CLI (cron): php process_queue.php
// Processes messages with status = queued or sending, up to X attempts.

if (php_sapi_name() !== 'cli') {
    echo "Run from CLI\n";
    exit;
}
require_once __DIR__ . '/gateway_config.php';
require_once __DIR__ . '/config.php'; // DB $db

$maxAttempts = 5;
$batchSize = 10;

$rows = $db->fetchAll("SELECT * FROM sms_queue WHERE status IN ('queued','sending') AND attempts < ? ORDER BY created_at ASC LIMIT ?", [$maxAttempts, $batchSize]);

foreach ($rows as $r) {
    $id = (int)$r['id'];
    $to = $r['recipient'];
    $body = $r['body'];

    // set to sending
    $db->query("UPDATE sms_queue SET status = 'sending', updated_at = NOW() WHERE id = ?", [$id]);

    $result = sendToGateway($to, $body); // use same helper as send_sms.php (copy it or include a common file)
    if ($result['ok']) {
        $db->query("UPDATE sms_queue SET status = 'sent', provider_response = ?, external_id = ?, attempts = attempts + 1, updated_at = NOW() WHERE id = ?", [$result['raw'], $result['message_id'], $id]);
        // optionally log event in sms_events
        $db->query("INSERT INTO sms_events (queue_id, event_type, event_payload) VALUES (?, 'sent', ?)", [$id, json_encode($result)]);
    } else {
        $db->query("UPDATE sms_queue SET status = 'queued', attempts = attempts + 1, last_error = ?, provider_response = ?, updated_at = NOW() WHERE id = ?", [$result['error'], $result['raw'], $id]);
        // exponential backoff is implicit by not processing immediately next run; you can add next_try timestamp
    }
}

// NOTE: implement sendToGateway() helper in a shared include or paste same function here.