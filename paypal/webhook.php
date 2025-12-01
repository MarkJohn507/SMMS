<?php
// paypal/webhook.php
// PayPal Webhook endpoint: verifies the signature with PayPal and processes events.
// You must configure a webhook in PayPal developer dashboard and set PAYPAL_WEBHOOK_ID in config.php.

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../paypal/paypal_client.php'; // uses composer
require_once __DIR__ . '/../includes/audit.php';
require_once __DIR__ . '/../includes/notifications.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

// Read raw POST body
$body = file_get_contents('php://input');
if (!$body) {
    http_response_code(400);
    echo 'Missing body';
    exit;
}

$event = json_decode($body, true);
if ($event === null) {
    http_response_code(400);
    echo 'Invalid JSON';
    exit;
}

// Collect required headers PayPal sends
$transmission_id = $_SERVER['HTTP_PAYPAL_TRANSMISSION_ID'] ?? ($_SERVER['PAYPAL_TRANSMISSION_ID'] ?? '');
$transmission_time = $_SERVER['HTTP_PAYPAL_TRANSMISSION_TIME'] ?? ($_SERVER['PAYPAL_TRANSMISSION_TIME'] ?? '');
$cert_url = $_SERVER['HTTP_PAYPAL_CERT_URL'] ?? ($_SERVER['PAYPAL_CERT_URL'] ?? '');
$auth_algo = $_SERVER['HTTP_PAYPAL_AUTH_ALGO'] ?? ($_SERVER['PAYPAL_AUTH_ALGO'] ?? '');
$transmission_sig = $_SERVER['HTTP_PAYPAL_TRANSMISSION_SIG'] ?? ($_SERVER['PAYPAL_TRANSMISSION_SIG'] ?? '');

// Basic validation
if (empty($transmission_id) || empty($transmission_sig) || empty($cert_url) || empty($auth_algo) || empty($transmission_time)) {
    http_response_code(400);
    echo 'Missing PayPal webhook headers';
    exit;
}

if (!defined('PAYPAL_WEBHOOK_ID') || PAYPAL_WEBHOOK_ID === '') {
    error_log('paypal/webhook: PAYPAL_WEBHOOK_ID not configured in config.php');
    http_response_code(500);
    echo 'Webhook not configured';
    exit;
}

// Obtain access token via OAuth (client credentials)
$token = null;
$base = (defined('PAYPAL_MODE') && PAYPAL_MODE === 'live') ? 'https://api.paypal.com' : 'https://api.sandbox.paypal.com';
$tokenUrl = $base . '/v1/oauth2/token';
$clientId = PAYPAL_CLIENT_ID;
$clientSecret = PAYPAL_CLIENT_SECRET;

$ch = curl_init($tokenUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_USERPWD, $clientId . ':' . $clientSecret);
curl_setopt($ch, CURLOPT_POSTFIELDS, 'grant_type=client_credentials');
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/json', 'Accept-Language: en_US']);
$tokenResp = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
if ($tokenResp === false || $httpCode !== 200) {
    error_log('paypal/webhook: failed to obtain oauth token: ' . curl_error($ch) . ' http:' . $httpCode . ' resp:' . $tokenResp);
    http_response_code(500);
    echo 'Failed to verify webhook (token)';
    curl_close($ch);
    exit;
}
curl_close($ch);

$tr = json_decode($tokenResp, true);
if (!isset($tr['access_token'])) {
    error_log('paypal/webhook: invalid token response: ' . $tokenResp);
    http_response_code(500);
    echo 'Failed to verify webhook (token)';
    exit;
}
$accessToken = $tr['access_token'];

// Build verify payload
$verifyPayload = json_encode([
    'transmission_id' => $transmission_id,
    'transmission_time' => $transmission_time,
    'cert_url' => $cert_url,
    'auth_algo' => $auth_algo,
    'transmission_sig' => $transmission_sig,
    'webhook_id' => PAYPAL_WEBHOOK_ID,
    'webhook_event' => $event
]);

// Call PayPal verify-webhook-signature endpoint
$verifyUrl = $base . '/v1/notifications/verify-webhook-signature';
$ch2 = curl_init($verifyUrl);
curl_setopt($ch2, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch2, CURLOPT_POST, true);
curl_setopt($ch2, CURLOPT_POSTFIELDS, $verifyPayload);
curl_setopt($ch2, CURLOPT_HTTPHEADER, [
    'Content-Type: application/json',
    'Authorization: Bearer ' . $accessToken
]);
$verifyResp = curl_exec($ch2);
$code2 = curl_getinfo($ch2, CURLINFO_HTTP_CODE);
if ($verifyResp === false || $code2 !== 200) {
    error_log('paypal/webhook: verify call failed: ' . curl_error($ch2) . ' http:' . $code2 . ' resp:' . $verifyResp);
    http_response_code(500);
    echo 'Failed to verify webhook (paypal API)';
    curl_close($ch2);
    exit;
}
curl_close($ch2);

$vr = json_decode($verifyResp, true);
if (!isset($vr['verification_status']) || $vr['verification_status'] !== 'SUCCESS') {
    error_log('paypal/webhook: verification failed: ' . $verifyResp);
    http_response_code(400);
    echo 'Webhook verification failed';
    exit;
}

// Verified — process event (handle common events)
$eventType = $event['event_type'] ?? '';
$resource = $event['resource'] ?? [];

try {
    global $db;

    if ($eventType === 'PAYMENT.CAPTURE.COMPLETED' || $eventType === 'PAYMENT.CAPTURE.DENIED' || $eventType === 'PAYMENT.CAPTURE.REFUNDED') {
        // resource has capture id and amount
        $captureId = $resource['id'] ?? null;
        $amount = $resource['amount']['value'] ?? null;
        $currency = $resource['amount']['currency_code'] ?? null;

        // Attempt to find a payments row that references this capture id in notes or receipt_number
        if ($captureId) {
            // Look for payment with notes containing this capture id
            $row = $db->fetch("SELECT * FROM payments WHERE notes LIKE ? OR receipt_number = ? LIMIT 1", ["%{$captureId}%", $captureId]);
            if ($row) {
                // Update status depending on event
                $newStatus = 'paid';
                if ($eventType === 'PAYMENT.CAPTURE.DENIED') $newStatus = 'failed';
                if ($eventType === 'PAYMENT.CAPTURE.REFUNDED') $newStatus = 'refunded';

                $db->query("UPDATE payments SET status = ?, updated_at = NOW() WHERE payment_id = ?", [$newStatus, $row['payment_id']]);
                logAudit($db, $row['vendor_id'], "Payment status updated via PayPal webhook: {$eventType}", 'payments', $row['payment_id'], null, "capture:{$captureId}");
            } else {
                // No existing payment row: optionally create one (depends on your workflow).
                // We'll create a pending record with notes indicating it came from webhook.
                $vendorId = null;
                // If resource has payer info, attempt to map to user (best-effort)
                if (!empty($resource['supplementary_data']['related_ids']['order_id'])) {
                    // If you stored mapping order_id -> pending payment in DB, use it. (Not implemented here)
                }

                // Log it
                error_log("paypal/webhook: capture {$captureId} not found in payments; event={$eventType}");
                // Optionally insert or notify admins
            }
        }
    } elseif ($eventType === 'CHECKOUT.ORDER.APPROVED') {
        // Optional: handle if you want to capture automatically via webhook
        // Here we only log
        error_log('paypal/webhook: CHECKOUT.ORDER.APPROVED event received: ' . json_encode($resource));
    } else {
        // Log unknown events
        error_log('paypal/webhook: unhandled event ' . $eventType);
    }
} catch (Throwable $e) {
    error_log('paypal/webhook processing failed: ' . $e->getMessage());
    http_response_code(500);
    echo 'Processing failed';
    exit;
}

// Return 200
http_response_code(200);
echo 'OK';