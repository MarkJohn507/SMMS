<?php
// API/send_sms.php
// Synchronous SMS sender that calls the configured gateway directly.
// (This is your existing file, with only $url updated to POST to the cloud endpoint '/message'.)

require_once __DIR__ . '/../gateway_config.php';
require_once __DIR__ . '/../config.php';

if (!function_exists('normalize_ph_number')) {
    if (file_exists(__DIR__ . '/../includes/phone_utils.php')) {
        require_once __DIR__ . '/../includes/phone_utils.php';
    }
}

if (!function_exists('normalize_ph_number')) {
    /**
     * Normalize phone numbers:
     * - Accepts generic E.164 numbers: +{country}{subscriber} (7..15 digits)
     * - Converts local Philippine formats:
     *     09XXXXXXXXX -> +63XXXXXXXXX
     *     63XXXXXXXXX  -> +63XXXXXXXXX
     * - If ALLOW_ONLY_PH_NUMBERS is false, allow digit-only numbers (7..15 digits) and
     *   prefix a '+' so they become E.164-like.
     *
     * Returns normalized E.164 string (with leading '+') or null if invalid.
     */
    function normalize_ph_number(?string $raw): ?string {
        if (empty($raw)) return null;

        // Keep only digits and leading '+'
        $p = trim((string)$raw);
        $p = preg_replace('/[^\d\+]/', '', $p);
        if ($p === '') return null;

        // 1) Already E.164 (generic): + followed by 7..15 digits
        if (strpos($p, '+') === 0) {
            if (preg_match('/^\+\d{7,15}$/', $p)) {
                return $p;
            }
            return null;
        }

        // 2) Local Philippine: 09XXXXXXXXX (11 digits starting with 09)
        if (preg_match('/^0\d{10}$/', $p) && strpos($p, '09') === 0) {
            return '+63' . substr($p, 1);
        }

        // 3) Philippines without plus: 63XXXXXXXXX
        if (preg_match('/^63\d{9,10}$/', $p)) {
            return '+' . $p;
        }

        // 4) Fallback when you explicitly allow non-PH numbers:
        //    Accept plain digits of reasonable length and prefix '+'
        if (defined('ALLOW_ONLY_PH_NUMBERS') && ALLOW_ONLY_PH_NUMBERS === false) {
            if (preg_match('/^\d{7,15}$/', $p)) {
                return '+' . $p;
            }
        }

        // Otherwise invalid
        return null;
    }
}

if (!function_exists('send_sms') && function_exists('sendSMS')) {
    function send_sms($phone, $message, $from = null, $subject = null, $db = null) {
        $res = sendSMS($phone, $message, $from, $subject, $db);
        if (is_array($res)) return !empty($res['ok']);
        return (bool)$res;
    }
}

if (!function_exists('sendSMS') && function_exists('send_sms')) {
    function sendSMS($phone, $message, $from = null, $subject = null, $db = null) {
        $res = send_sms($phone, $message);
        if (is_bool($res)) return ['ok' => $res, 'raw' => null, 'http' => 0, 'error' => $res ? null : 'gateway_error', 'message_id' => null];
        if (is_array($res)) return $res;
        return ['ok' => false, 'raw' => null, 'http' => 0, 'error' => 'unknown_response', 'message_id' => null];
    }
}

function _sendToGateway(string $to, string $text): array {
    $base = defined('GATEWAY_BASE') ? rtrim(GATEWAY_BASE, '/') : null;
    $authType = defined('GATEWAY_AUTH_TYPE') ? strtolower(GATEWAY_AUTH_TYPE) : 'basic';
    $timeout = defined('GATEWAY_HTTP_TIMEOUT') ? (int)GATEWAY_HTTP_TIMEOUT : 60;
    $payloadStyle = defined('GATEWAY_PAYLOAD_STYLE') ? strtolower(GATEWAY_PAYLOAD_STYLE) : 'textmessage';

    if (empty($base)) {
        $msg = 'gateway_base_not_configured';
        error_log("send_sms: " . $msg);
        return ['ok' => false, 'raw' => null, 'http' => 0, 'error' => $msg, 'message_id' => null];
    }
    if (empty($to) || trim($text) === '') {
        $msg = 'invalid_parameters';
        error_log("send_sms: " . $msg);
        return ['ok' => false, 'raw' => null, 'http' => 0, 'error' => $msg, 'message_id' => null];
    }

    try {
        $rand = bin2hex(random_bytes(4));
    } catch (Throwable $e) {
        $rand = substr(md5(uniqid('', true)), 0, 8);
    }
    $payloadId = 'srv-' . time() . '-' . $rand;

    switch ($payloadStyle) {
        case 'textmessage':
            $payload = [
                'id' => $payloadId,
                'phoneNumbers' => [$to],
                'textMessage' => ['type' => 'text', 'text' => $text],
                'withDeliveryReport' => true
            ];
            break;
        case 'message':
            $payload = [
                'id' => $payloadId,
                'phoneNumbers' => [$to],
                'message' => ['type' => 'text', 'text' => $text],
                'withDeliveryReport' => true
            ];
            break;
        case 'content':
        default:
            $payload = [
                'id' => $payloadId,
                'phoneNumbers' => [$to],
                'content' => ['type' => 'text', 'text' => $text],
                'withDeliveryReport' => true
            ];
            break;
    }

    // IMPORTANT CHANGE: send to cloud '/message' endpoint
    $url = rtrim($base, '/') . '/message';

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, max(5, min(10, $timeout - 2)));

    $headers = ['Content-Type: application/json'];

    if ($authType === 'basic') {
        if (defined('GATEWAY_USERNAME') && defined('GATEWAY_PASSWORD') && GATEWAY_USERNAME !== '' && GATEWAY_PASSWORD !== '') {
            curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
            curl_setopt($ch, CURLOPT_USERPWD, GATEWAY_USERNAME . ':' . GATEWAY_PASSWORD);
        }
    } elseif ($authType === 'bearer') {
        if (defined('GATEWAY_TOKEN') && GATEWAY_TOKEN !== '') {
            $headers[] = 'Authorization: Bearer ' . GATEWAY_TOKEN;
        }
    }

    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    $resp = curl_exec($ch);
    $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);

    $out = ['ok' => false, 'raw' => $resp, 'http' => $http, 'error' => $err ?: null, 'message_id' => null];

    if ($resp === false) {
        $out['error'] = $err ?: 'curl_failed';
        error_log('send_sms: curl failed: ' . $out['error']);
        return $out;
    }

    $json = json_decode($resp, true);
    if ($http >= 200 && $http < 300) {
        $out['ok'] = true;
        if (is_array($json)) {
            $out['message_id'] = $json['messageId'] ?? $json['id'] ?? $json['result']['id'] ?? $json['id'] ?? null;
        }
        if (empty($out['message_id'])) $out['message_id'] = $payloadId;
        return $out;
    } else {
        $out['error'] = is_string($resp) ? $resp : json_encode($json);
        error_log('send_sms: gateway returned http=' . $http . ' resp=' . substr((string)$resp, 0, 2000));
        return $out;
    }
}

function sendSMS($phone, $message, $from = null, $subject = null, $db = null) {
    $to = null;
    if (function_exists('normalize_ph_number')) {
        try {
            $to = normalize_ph_number((string)$phone);
        } catch (Throwable $e) {
            $to = null;
            error_log("sendSMS: normalize_ph_number threw: " . $e->getMessage());
        }
    }

    if ($to === null) {
        if (defined('ALLOW_ONLY_PH_NUMBERS') && ALLOW_ONLY_PH_NUMBERS === false) {
            $filtered = '';
            $phone = trim((string)$phone);
            foreach (str_split($phone) as $c) {
                if ($c === '+' || ctype_digit($c)) $filtered .= $c;
            }
            $to = $filtered !== '' ? $filtered : null;
        }
    }

    if (empty($to)) {
        error_log('sendSMS: recipient invalid after normalization: ' . var_export($phone, true));
        return ['ok' => false, 'raw' => null, 'http' => 0, 'error' => 'invalid_recipient', 'message_id' => null];
    }

    if (trim((string)$message) === '') {
        error_log('sendSMS: empty message');
        return ['ok' => false, 'raw' => null, 'http' => 0, 'error' => 'empty_message', 'message_id' => null];
    }

    $result = _sendToGateway($to, $message);

    $logMsg = sprintf("sendSMS: to=%s ok=%s http=%s error=%s message_id=%s",
        $to,
        $result['ok'] ? '1' : '0',
        $result['http'] ?? '0',
        is_scalar($result['error']) ? $result['error'] : json_encode($result['error']),
        $result['message_id'] ?? ''
    );
    error_log($logMsg);

    return $result;
}