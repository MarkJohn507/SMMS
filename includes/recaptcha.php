<?php
// Simple Google reCAPTCHA v2/v3 verification helper.
// Add RECAPTCHA_SECRET to your config.php

if (!function_exists('verifyRecaptcha')) {
    function verifyRecaptcha(string $token, string $remoteIp = null, float $minScore = 0.5): bool {
        if (empty(RECAPTCHA_SECRET)) {
            // If not configured, fail-open for compatibility, but log
            error_log("reCAPTCHA secret not configured");
            return true;
        }
        $data = [
            'secret' => RECAPTCHA_SECRET,
            'response' => $token,
        ];
        if ($remoteIp) $data['remoteip'] = $remoteIp;

        $opts = [
            "http" => [
                "method" => "POST",
                "header" => "Content-Type: application/x-www-form-urlencoded\r\n",
                "content" => http_build_query($data),
                "timeout" => 5,
            ]
        ];
        $context = stream_context_create($opts);
        $resp = @file_get_contents('https://www.google.com/recaptcha/api/siteverify', false, $context);
        if ($resp === false) {
            error_log("reCAPTCHA verification request failed");
            return false;
        }
        $json = json_decode($resp, true);
        if (!is_array($json)) {
            error_log("reCAPTCHA invalid response");
            return false;
        }
        // v3 returns 'score', v2 returns 'success' boolean.
        if (isset($json['success']) && $json['success'] === true) {
            if (isset($json['score'])) {
                return ($json['score'] >= $minScore);
            }
            return true;
        }
        return false;
    }
}