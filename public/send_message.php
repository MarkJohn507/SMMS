<?php
// public/send_message.php
// Validates recipients to PH numbers only, normalizes them to +63XXXXXXXXXX,
// then forwards the request to the local Android gateway device API (/message).
// On invalid recipients returns HTTP 400 with JSON listing invalid numbers.

header('Content-Type: application/json; charset=utf-8');

// device API endpoint (change host/port if needed)
$deviceApi = 'http://127.0.0.1:8080/message'; // replace 127.0.0.1 if device on other host

$raw = file_get_contents('php://input');
if (!$raw) {
    http_response_code(400);
    echo json_encode(['error' => 'empty_body', 'message' => 'Request body is empty.']);
    exit;
}

$data = json_decode($raw, true);
if ($data === null) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid_json', 'json_error' => json_last_error_msg()]);
    exit;
}

$numbers = $data['phoneNumbers'] ?? [];
if (!is_array($numbers) || count($numbers) === 0) {
    http_response_code(400);
    echo json_encode(['error' => 'missing_recipients', 'message' => 'phoneNumbers array is required.']);
    exit;
}

// Normalization function: accept +63..., 63..., 0... and normalize to +63XXXXXXXXXX
function normalize_ph_number(string $n): ?string {
    // strip spaces, dashes, parentheses
    $s = preg_replace('/[^\d\+]/', '', trim($n));
    // +63XXXXXXXXXX
    if (preg_match('/^\+63([0-9]{10})$/', $s, $m)) return '+63' . $m[1];
    // 63XXXXXXXXXX
    if (preg_match('/^63([0-9]{10})$/', $s, $m)) return '+63' . $m[1];
    // 0XXXXXXXXXX (e.g. 09171234567)
    if (preg_match('/^0([0-9]{10})$/', $s, $m)) return '+63' . $m[1];
    return null;
}

$valid = [];
$invalid = [];
foreach ($numbers as $n) {
    $norm = normalize_ph_number((string)$n);
    if ($norm === null) $invalid[] = (string)$n;
    else $valid[] = $norm;
}

if (count($invalid) > 0) {
    http_response_code(400);
    echo json_encode([
        'error' => 'invalid_recipients',
        'invalid' => array_values($invalid),
        'message' => 'Only Philippine mobile numbers are accepted. Use +63XXXXXXXXXX, 63XXXXXXXXXX or 0XXXXXXXXXX formats.'
    ]);
    exit;
}

// Build payload for device (use valid normalized numbers)
$devicePayload = $data;
$devicePayload['phoneNumbers'] = array_values($valid);
$deviceBody = json_encode($devicePayload);

// Forward to device API (curl)
$ch = curl_init($deviceApi);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
curl_setopt($ch, CURLOPT_POSTFIELDS, $deviceBody);

// If your device requires basic auth, set it here:
// curl_setopt($ch, CURLOPT_USERPWD, 'sms:PqtXvS14');

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$err = curl_error($ch);
curl_close($ch);

if ($response === false) {
    http_response_code(502);
    echo json_encode(['error' => 'device_request_failed', 'message' => $err]);
    exit;
}

// Relay device response code + body to the client (or map to your preferred format)
http_response_code($httpCode ? $httpCode : 200);
echo $response;
exit;