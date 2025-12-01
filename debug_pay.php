<?php
// DEBUG - temporary: show which PayPal settings are present (do NOT log/print secrets)

$paypal_present = [
    'PAYPAL_ENABLED' => defined('PAYPAL_ENABLED') ? (bool)PAYPAL_ENABLED : null,
    'PAYPAL_CLIENT_ID_SET' => !empty(getenv('PAYPAL_CLIENT_ID')) || (defined('PAYPAL_CLIENT_ID') && !empty(PAYPAL_CLIENT_ID)),
    'PAYPAL_CLIENT_SECRET_SET' => !empty(getenv('PAYPAL_CLIENT_SECRET')) || (defined('PAYPAL_CLIENT_SECRET') && !empty(PAYPAL_CLIENT_SECRET)),
    'PAYPAL_MODE' => getenv('PAYPAL_MODE') ?: (defined('PAYPAL_MODE') ? PAYPAL_MODE : null),
];

error_log('PayPal config presence: ' . json_encode($paypal_present, JSON_PRETTY_PRINT));

// end debug
?>