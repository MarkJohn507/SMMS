<?php
// webhook.php
// Receives POST webhooks from the Android gateway device. Configure the same secret on the device.

require_once __DIR__ . '/gateway_config.php';
require_once __DIR__ . '/config.php';
header('Content-Type: application/json; charset=utf-8');

$token = $_SERVER['HTTP_X_GATEWAY_TOKEN'] ?? ($_SERVER['HTTP_X_API_TOKEN'] ?? '');
if ($token !== (GATEWAY_WEBHOOK_SECRET ?? null)) {
    http_response_code(403);
    echo json_encode(['error' => 'invalid token']);
    exit;
}

$raw = file_get_contents('php://input');
$data = json_decode($raw, true);
if (!$data) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid json']);
    exit;
}

// shape: { "event":"sms:received", "payload": { ... } }
$event = $data['event'] ?? null;
$payload = $data['payload'] ?? $data;

if ($event === 'sms:received' || ($payload['messageType'] ?? '') === 'incoming' || ($payload['type'] ?? '') === 'incoming') {
    $messageId = $payload['messageId'] ?? $payload['id'] ?? null;
    $from = $payload['phoneNumber'] ?? $payload['from'] ?? null;
    $text = $payload['text'] ?? ($payload['content']['text'] ?? null);
    $sim = isset($payload['simNumber']) ? (int)$payload['simNumber'] : null;
    try {
        $db->query("INSERT INTO sms_inbound (provider_message_id, sender, body, sim_number, received_at, raw_payload) VALUES (?, ?, ?, ?, NOW(), ?)",
            [$messageId, $from, $text, $sim, $raw]);
    } catch (Throwable $e) {
        error_log("webhook: failed insert inbound: " . $e->getMessage());
    }
    echo json_encode(['ok' => true]);
    exit;
}

// other events (sent, delivered, failed)
if ($event !== null) {
    try {
        $db->query("INSERT INTO sms_events (queue_id, event_type, event_payload, created_at) VALUES (?, ?, ?, NOW())", [null, $event, $raw]);
    } catch (Throwable $e) {
        error_log("webhook: failed insert event: " . $e->getMessage());
    }
}

echo json_encode(['ok' => true]);