<?php
// paypal/paypal_client.php
// Helper to create a PayPal SDK client. Place this file in the paypal/ directory.
//
// Requires composer install: composer require paypal/paypal-checkout-sdk

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

// Ensure Composer autoload is available
$composerAutoload = __DIR__ . '/../vendor/autoload.php';
if (!file_exists($composerAutoload)) {
    throw new \RuntimeException('Composer autoload not found. Run "composer install" in project root.');
}
require_once $composerAutoload;

use PayPalCheckoutSdk\Core\PayPalHttpClient as SdkPayPalHttpClient;
use PayPalCheckoutSdk\Core\SandboxEnvironment;
use PayPalCheckoutSdk\Core\ProductionEnvironment;

/**
 * Patched client to avoid PHP 8.2 "Creation of dynamic property ... $curlCls is deprecated".
 * The upstream SDK writes to $this->curlCls; pre-declare it here so it's not "dynamic".
 */
if (!class_exists('PatchedPayPalHttpClient', false)) {
    class PatchedPayPalHttpClient extends SdkPayPalHttpClient
    {
        /** @var mixed|null */
        public $curlCls = null;
    }
}

/**
 * Returns a configured PayPalHttpClient instance.
 * Throws RuntimeException when credentials are missing.
 */
function getPayPalClient(): SdkPayPalHttpClient {
    if (!defined('PAYPAL_CLIENT_ID') || !defined('PAYPAL_CLIENT_SECRET') || PAYPAL_CLIENT_ID === '' || PAYPAL_CLIENT_SECRET === '') {
        throw new \RuntimeException('PayPal credentials not configured (PAYPAL_CLIENT_ID/PAYPAL_CLIENT_SECRET).');
    }

    $clientId = PAYPAL_CLIENT_ID;
    $clientSecret = PAYPAL_CLIENT_SECRET;
    $mode = defined('PAYPAL_MODE') ? strtolower(PAYPAL_MODE) : 'sandbox';

    if ($mode === 'live' || $mode === 'production') {
        $env = new ProductionEnvironment($clientId, $clientSecret);
    } else {
        $env = new SandboxEnvironment($clientId, $clientSecret);
    }

    // Return the patched client to avoid dynamic property deprecation notices
    return new PatchedPayPalHttpClient($env);
}