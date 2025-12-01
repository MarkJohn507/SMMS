<?php
// public/gateway_webhook.php
// Webhook receiver for Android SMS Gateway device (Local or Cloud).
// - Verifies HMAC signature (if configured)
// - Optionally decrypts encrypted payloads if passphrase set
// - Inserts incoming SMS into sms_inbound and stores events in sms_events
//
// Place this file where it's publicly reachable (HTTPS) and set the same secret in the app.

require_once __DIR__ . '/../gateway_config.php';
require_once __DIR__ . '/../config.php'; // your DB wrapper $db
header('Content-Type: application/json; charset=utf-8');

// Helper to get headers (case-insensitive)
function get_all_headers_lower() {
    $result = [];
    if (function_exists('getallheaders')) {
        foreach (getallheaders() as $k => $v) $result[strtolower($k)] = $v;
        return $result;
    }
    foreach ($_SERVER as $name => $value) {
        if (substr($name, 0, 5) == 'HTTP_') {
            $header = str_replace(' ', '-', strtolower(str_replace('_', ' ', substr($name, 5))));
            $result[$header] = $value;
        }
    }
    return $result;
}

// Quick human-friendly GET response so visiting the URL in a browser doesn't show "invalid json"
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    echo json_encode([
        'ok' => true,
        'info' => 'Webhook endpoint. Send POST with JSON body (event/payload).'
    ]);
    exit;
}

// read raw body
$raw = file_get_contents('php://input') ?: '';
$headers = get_all_headers_lower();

// Content-Type helper
$contentType = $_SERVER['CONTENT_TYPE'] ?? $headers['content-type'] ?? '';

// config values
$sigHeader = strtolower(GATEWAY_WEBHOOK_SIG_HEADER ?? 'x-gateway-signature');
$tsHeader = strtolower(GATEWAY_WEBHOOK_TS_HEADER ?? 'x-gateway-timestamp');
$secret = defined('GATEWAY_WEBHOOK_SECRET') ? (GATEWAY_WEBHOOK_SECRET ?: null) : null;
$passphrase = defined('GATEWAY_WEBHOOK_PASSPHRASE') ? (GATEWAY_WEBHOOK_PASSPHRASE ?: null) : null;
$hmacAlgo = defined('GATEWAY_WEBHOOK_HMAC_ALGO') ? (GATEWAY_WEBHOOK_HMAC_ALGO ?: 'sha256') : 'sha256';

// If POST but empty body -> clear error
if ($_SERVER['REQUEST_METHOD'] === 'POST' && trim($raw) === '') {
    http_response_code(400);
    echo json_encode(['error' => 'empty_body', 'message' => 'Request body is empty. POST JSON payload.']);
    exit;
}

// 1) Verify signature if secret configured
if ($secret) {
    $sig = $headers[$sigHeader] ?? null;
    $ts = $headers[$tsHeader] ?? '';
    if (!$sig) {
        http_response_code(403);
        echo json_encode(['error' => 'missing signature header']);
        exit;
    }
    // compute expected HMAC over raw + ts
    $expected_raw = hash_hmac($hmacAlgo, $raw . $ts, $secret, true);
    $expected_b64 = base64_encode($expected_raw);
    $expected_hex = bin2hex($expected_raw);

    $verified = false;
    if (hash_equals($expected_b64, $sig)) $verified = true;
    if (!$verified && hash_equals($expected_hex, preg_replace('/^0x/', '', $sig))) $verified = true;

    if (!$verified) {
        http_response_code(403);
        error_log('gateway_webhook: signature mismatch');
        echo json_encode(['error' => 'invalid signature']);
        exit;
    }

    // optional: timestamp skew check (prevent replay). Accept +/- 5 minutes
    if (is_numeric($ts)) {
        $skew = abs(time() - (int)$ts);
        if ($skew > 300) {
            error_log("gateway_webhook: timestamp skew too large: $skew seconds");
            http_response_code(403);
            echo json_encode(['error' => 'timestamp_skew_too_large']);
            exit;
        }
    }
}

// 2) Detect and decrypt encrypted payloads if the body starts with $ (app encryption format)
$payload_json = null;
if (strlen($raw) > 0 && $raw[0] === '$') {
    if (!$passphrase) {
        http_response_code(400);
        echo json_encode(['error' => 'payload encrypted but server passphrase not configured']);
        exit;
    }
    // Format: $aes-256-cbc/pbkdf2-sha1$params$salt$encryptedBase64
    $parts = explode('$', $raw, 5); // ["", alg, params, salt, encrypted]
    if (count($parts) < 5) {
        http_response_code(400);
        echo json_encode(['error' => 'invalid encrypted format']);
        exit;
    }
    $alg = $parts[1];
    $paramsStr = $parts[2];
    $saltB64 = $parts[3];
    $encryptedB64 = $parts[4];

    // parse params, e.g. "i=300000"
    $params = [];
    foreach (explode(',', $paramsStr) as $p) {
        $kv = explode('=', $p, 2);
        if (count($kv) == 2) $params[trim($kv[0])] = trim($kv[1]);
    }
    $iter = isset($params['i']) ? (int)$params['i'] : 300000;

    $salt = base64_decode($saltB64, true);
    if ($salt === false) { http_response_code(400); echo json_encode(['error'=>'invalid salt']); exit; }

    // IV is derived from salt (truncate/pad to 16 bytes)
    $iv = substr($salt, 0, 16);
    if (strlen($iv) < 16) {
        http_response_code(400); echo json_encode(['error'=>'invalid iv length']); exit;
    }

    // derive key using PBKDF2-SHA1 -> 32 bytes
    if (!function_exists('hash_pbkdf2')) {
        http_response_code(500); echo json_encode(['error'=>'server missing hash_pbkdf2']); exit;
    }
    $key = hash_pbkdf2('sha1', $passphrase, $salt, $iter, 32, true);

    $encrypted = base64_decode($encryptedB64, true);
    if ($encrypted === false) { http_response_code(400); echo json_encode(['error'=>'invalid encrypted blob']); exit; }

    $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    if ($decrypted === false) {
        http_response_code(400); echo json_encode(['error'=>'decryption_failed']); exit;
    }
    $payload_json = $decrypted;
} else {
    // If device sent form-encoded body with JSON in a field (payload=...), handle that
    if (stripos($contentType, 'application/x-www-form-urlencoded') !== false) {
        parse_str($raw, $postArr);
        if (!empty($postArr['payload'])) {
            $payload_json = $postArr['payload'];
        } elseif (!empty($postArr['data'])) {
            $payload_json = $postArr['data'];
        } else {
            // fallback to raw
            $payload_json = $raw;
        }
    } else {
        $payload_json = $raw;
    }
}

// 3) parse JSON
$data = json_decode($payload_json, true);
if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid json', 'json_error' => json_last_error_msg()]);
    exit;
}

// 4) handle events
$event = $data['event'] ?? null;
$payload = $data['payload'] ?? $data;

try {
    if ($event === 'sms:received' || ($payload['type'] ?? '') === 'incoming' || ($payload['messageType'] ?? '') === 'incoming') {
        $messageId = $payload['messageId'] ?? $payload['id'] ?? null;
        $from = $payload['phoneNumber'] ?? $payload['from'] ?? null;
        $text = $payload['text'] ?? ($payload['message'] ?? null);
        $simNumber = isset($payload['simNumber']) ? (int)$payload['simNumber'] : null;
        $receivedAt = $payload['receivedAt'] ?? date('Y-m-d H:i:s');

        // persist inbound message (sms_inbound)
        $db->query("INSERT INTO sms_inbound (provider_message_id, sender, body, sim_number, received_at, raw_payload) VALUES (?, ?, ?, ?, ?, ?)",
            [$messageId, $from, $text, $simNumber, $receivedAt, $payload_json]);

        echo json_encode(['ok' => true]);
        exit;
    }

    // status events: sms:sent, sms:delivered, sms:failed
    if ($event !== null && strpos($event, 'sms:') === 0) {
        // store event in sms_events for later processing
        $db->query("INSERT INTO sms_events (queue_id, event_type, event_payload, created_at) VALUES (?, ?, ?, NOW())",
            [null, $event, json_encode($payload)]);
        echo json_encode(['ok' => true]);
        exit;
    }

    // fallback: echo ok
    echo json_encode(['ok' => true]);
    exit;
} catch (Throwable $e) {
    error_log('gateway_webhook: exception ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'server_error']);
    exit;
}