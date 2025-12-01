<?php
/**
 * includes/billing_bootstrap.php
 *
 * Cronless billing enforcement triggered by page views.
 * - Runs for the CURRENT logged-in vendor only
 * - Throttled via session to once per interval
 *
 * Requirements:
 *   require_once 'includes/billing.php';
 *   require_once 'includes/auth_roles.php';
 *
 * Tuning:
 *   define('BILLING_BOOTSTRAP_INTERVAL_MINUTES', 1440); // default daily
 */

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

require_once __DIR__ . '/billing.php';
require_once __DIR__ . '/auth_roles.php';

if (!function_exists('billing_bootstrap_run')) {
    function billing_bootstrap_run($db): void
    {
        if (empty($_SESSION['user_id'])) return;

        $uid = (int)$_SESSION['user_id'];

        // Only for vendors
        try {
            if (!function_exists('userIsInRole') || !userIsInRole($db, $uid, 'vendor')) {
                return;
            }
        } catch (Throwable $e) {
            error_log('billing_bootstrap role check failed: ' . $e->getMessage());
            return;
        }

        // Throttle: default once per 24 hours (1440 minutes). Override via constant.
        $intervalMin = defined('BILLING_BOOTSTRAP_INTERVAL_MINUTES') ? (int)BILLING_BOOTSTRAP_INTERVAL_MINUTES : 1440;
        $intervalMin = max(15, $intervalMin); // lower bound to avoid hammering

        $now = time();
        $lastRun = isset($_SESSION['billing_bootstrap_last_run']) ? (int)$_SESSION['billing_bootstrap_last_run'] : 0;

        if ($lastRun && ($now - $lastRun) < ($intervalMin * 60)) {
            return; // still within throttle window
        }

        try {
            // 1) Make sure current-month invoices exist for this vendor’s active leases
            ensureMonthlyInvoices($db, $uid);

            // 2) Auto-terminate leases past grace period (no penalties)
            autoTerminateLeasesPastGrace($db, $uid);

            // 3) Send in-app reminders (before due, on due, last grace day)
            sendPaymentReminders($db, $uid);

            $_SESSION['billing_bootstrap_last_run'] = $now;
        } catch (Throwable $e) {
            error_log('billing_bootstrap_run failed: ' . $e->getMessage());
        }
    }
}

// Kick it off
try {
    billing_bootstrap_run($db);
} catch (Throwable $e) {
    // swallow; never break page render
}