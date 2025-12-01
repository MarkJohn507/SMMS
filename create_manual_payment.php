<?php
// create_manual_payment.php
// Server-side handler for inline manual cash payment creation.
// This file is intended to be included/POSTed from manage_payments.php inline form.
//
// Improvements:
// - Stronger validation and clearer error messages.
// - Better lease resolution (prefer active lease for stall, otherwise try vendor-specific lease).
// - More detailed server-side logging on DB errors and a reference token returned to the user to help debugging.
// - Defensive transaction handling using the same PDO instance.

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/csrf.php';
require_once 'includes/audit.php';
require_once 'includes/notifications.php';
require_once 'includes/helpers.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

// Helper to redirect back with flash
function redirect_back($key, $msg, $to = 'manage_payments.php') {
    $_SESSION[$key] = $msg;
    header('Location: ' . $to);
    exit;
}

$uid = (int)($_SESSION['user_id'] ?? 0);
if (!$uid) redirect_back('staff_error', 'Not authenticated.');

try {
    // Use DB-authoritative role checks (avoid stale session flags)
    $is_accountant = function_exists('userIsInRole') ? userIsInRole($db, $uid, 'accountant') : false;
    $is_market_manager = function_exists('userIsInRole') ? userIsInRole($db, $uid, 'market_manager') : false;
    $is_super_admin = function_exists('userIsInRole') ? userIsInRole($db, $uid, 'super_admin') : false;
    $is_admin = function_exists('isAdmin') ? isAdmin() : false;
} catch (Throwable $e) {
    error_log("create_manual_payment roles: " . $e->getMessage());
    $is_accountant = $is_market_manager = $is_super_admin = $is_admin = false;
}

if (!($is_accountant || $is_market_manager || $is_admin || $is_super_admin)) {
    redirect_back('staff_error', 'You do not have permission to create manual payments.');
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !csrf_validate_request()) {
    redirect_back('staff_error', 'Invalid request (CSRF).');
}

// Read inputs
$stall_id = isset($_POST['stall_id']) ? (int)$_POST['stall_id'] : 0;
$vendor_id = isset($_POST['vendor_id']) ? (int)$_POST['vendor_id'] : 0;
$amount_raw = isset($_POST['amount']) ? trim($_POST['amount']) : '';
// sanitize numeric input (allow commas)
$amount = (float) str_replace(',', '', $amount_raw);
$payment_date = isset($_POST['payment_date']) ? trim($_POST['payment_date']) : date('Y-m-d');
$payment_type = isset($_POST['payment_type']) ? sanitize($_POST['payment_type']) : 'rent';
$notes = isset($_POST['notes']) ? trim($_POST['notes']) : '';
$from_page = isset($_POST['from_page']) ? $_POST['from_page'] : 'manage_payments.php';

// Validation
if ($stall_id <= 0) redirect_back('staff_error', 'Please select a stall.', $from_page);
if ($vendor_id <= 0) redirect_back('staff_error', 'Vendor selection is required.', $from_page);
if ($amount <= 0) redirect_back('staff_error', 'Please provide a valid amount.', $from_page);
if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $payment_date)) redirect_back('staff_error', 'Invalid payment date.', $from_page);

// Stall exists and market
try {
    $stall = $db->fetch("SELECT stall_id, market_id FROM stalls WHERE stall_id = ? LIMIT 1", [$stall_id]);
    if (!$stall) redirect_back('staff_error', 'Stall not found.', $from_page);
    $stall_market_id = isset($stall['market_id']) ? (int)$stall['market_id'] : null;
} catch (Throwable $e) {
    error_log("create_manual_payment stall lookup: " . $e->getMessage());
    redirect_back('staff_error', 'Server error.');
}

// Scoped markets for user - reuse same logic as other pages
function getUserScopedMarketIds_local($db, $userId) {
    $ids = [];
    try { $rows = $db->fetchAll("SELECT market_id FROM market_managers WHERE user_id = ?", [$userId]) ?: []; foreach ($rows as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id']; } catch (Throwable $e) {}
    try { $rows2 = $db->fetchAll("SELECT market_id FROM markets WHERE created_by = ?", [$userId]) ?: []; foreach ($rows2 as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id']; } catch (Throwable $e) {}
    try { $rows3 = $db->fetchAll("SELECT DISTINCT market_id FROM user_roles WHERE user_id = ? AND market_id IS NOT NULL AND status = 'active'", [$userId]) ?: []; foreach ($rows3 as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id']; } catch (Throwable $e) {}
    return array_values(array_unique(array_map('intval', $ids)));
}

if (!$is_super_admin) {
    $user_markets = getUserScopedMarketIds_local($db, $uid);
    if (!empty($user_markets)) {
        if ($stall_market_id === null || !in_array($stall_market_id, $user_markets, true)) {
            redirect_back('staff_error', 'You do not have permission to create a payment for this stall.', $from_page);
        }
    } else {
        if ($is_market_manager || $is_accountant) {
            redirect_back('staff_error', 'You are not assigned to any market.', $from_page);
        }
    }
}

// Validate vendor exists and is vendor and has lease in market (or at least has lease in the market)
try {
    $vrow = $db->fetch("SELECT user_id, role, email, full_name FROM users WHERE user_id = ? LIMIT 1", [$vendor_id]);
    if (!$vrow || (($vrow['role'] ?? '') !== 'vendor')) {
        redirect_back('staff_error', 'Selected user is not a vendor.', $from_page);
    }
    if ($stall_market_id !== null) {
        $hasLease = $db->fetch("SELECT 1 FROM leases l JOIN stalls s ON l.stall_id = s.stall_id WHERE l.vendor_id = ? AND s.market_id = ? LIMIT 1", [$vendor_id, $stall_market_id]);
        if (!$hasLease) {
            redirect_back('staff_error', 'Selected vendor does not have a lease in this market. Please choose a vendor assigned to this market.', $from_page);
        }
    }
} catch (Throwable $e) {
    error_log("create_manual_payment vendor validate: " . $e->getMessage());
    redirect_back('staff_error', 'Server error validating vendor.', $from_page);
}

// Find active lease for stall (prefer matching vendor). If none, try to find any lease for that vendor in that stall.
// This makes the insertion more likely to succeed and avoids creating payments without context.
$lease_id = null;
$lease_row = null;
try {
    $lease_row = $db->fetch("SELECT lease_id, vendor_id FROM leases WHERE stall_id = ? AND status = 'active' LIMIT 1", [$stall_id]);
    if ($lease_row && !empty($lease_row['lease_id'])) {
        $lease_id = (int)$lease_row['lease_id'];
    } else {
        // try to find a lease for this stall owned by the selected vendor (any status)
        $lease2 = $db->fetch("SELECT lease_id, vendor_id FROM leases WHERE stall_id = ? AND vendor_id = ? LIMIT 1", [$stall_id, $vendor_id]);
        if ($lease2 && !empty($lease2['lease_id'])) {
            $lease_id = (int)$lease2['lease_id'];
            $lease_row = $lease2;
        } else {
            // no specific lease found for the stall; leave lease_id null — we'll detect DB constraint failures and return a useful message.
            $lease_id = null;
        }
    }
} catch (Throwable $e) {
    error_log("create_manual_payment lease lookup: " . $e->getMessage());
    redirect_back('staff_error', 'Server error.');
}

// Ensure due_date is provided for DB (manual cash => use payment date as due_date)
$due_date = $payment_date;

// Insert payment and mark as paid
try {
    $pdo = $db->pdo();
    $pdo->beginTransaction();

    $receipt_number = 'RCT-' . date('Ymd') . '-' . str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    $sql = "INSERT INTO payments (lease_id, vendor_id, amount, payment_type, payment_method, due_date, payment_date, status, receipt_number, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'paid', ?, ?, NOW(), NOW())";
    $params = [
        $lease_id !== null ? $lease_id : null,
        $vendor_id,
        $amount,
        $payment_type,
        'cash',
        $due_date,               // <-- ensure non-null due_date (use payment date)
        $payment_date,
        $receipt_number,
        $notes ?: ("Manual cash payment by " . ($_SESSION['full_name'] ?? $uid))
    ];

    // Execute insert and capture DB exceptions with helpful logging
    try {
        $db->query($sql, $params);
        $new_payment_id = $db->lastInsertId();
    } catch (Throwable $e) {
        // Build a reference id for support and log full error + context
        $err_ref = 'payerr_' . bin2hex(random_bytes(6));
        error_log("create_manual_payment insert failed [ref={$err_ref}]: " . $e->getMessage() . " SQL=" . $sql . " PARAMS=" . json_encode($params));
        // If common cause is likely missing lease_id NOT NULL, provide a clearer user message
        $msg = 'Failed to record manual payment (database error).';
        if (stripos($e->getMessage(), 'NOT NULL') !== false || stripos($e->getMessage(), 'cannot be null') !== false) {
            $msg = 'Failed to record manual payment: the system requires an active lease for this stall. Please ensure the stall has an active lease or create a lease before recording cash payments.';
        } else {
            // Generic guidance
            $msg .= ' Please try again or contact support and provide reference code: ' . $err_ref;
        }
        // rollback and return
        $pdo->rollBack();
        redirect_back('staff_error', $msg, $from_page);
    }

    // Audit
    logAudit($db, $uid, 'Manual cash payment created', 'payments', $new_payment_id, null, json_encode([
        'stall_id' => $stall_id,
        'lease_id' => $lease_id,
        'vendor_id' => $vendor_id,
        'amount' => $amount,
        'payment_date' => $payment_date,
        'receipt' => $receipt_number
    ]));

    // Optionally update lease vendor_id if lease exists and differs from selected vendor
    if ($lease_id && isset($lease_row['vendor_id']) && ((int)$lease_row['vendor_id'] !== (int)$vendor_id)) {
        try {
            $db->query("UPDATE leases SET vendor_id = ? WHERE lease_id = ?", [$vendor_id, $lease_id]);
        } catch (Throwable $e) {
            // Non-fatal: log and continue
            error_log("create_manual_payment: updating lease vendor failed: " . $e->getMessage());
        }
    }

    // Notify vendor (best-effort)
    try {
        if (function_exists('createNotification')) {
            createNotification($db, $vendor_id, 'Manual Payment Recorded', "A cash payment of " . formatCurrency($amount) . " was recorded and assigned to your account. Receipt: {$receipt_number}", 'success', 'payment', $new_payment_id, 'payments');
        }
        $vendorRow = $db->fetch("SELECT email, full_name FROM users WHERE user_id = ? LIMIT 1", [$vendor_id]);
        if ($vendorRow && !empty($vendorRow['email'])) {
            $subject = "Manual Payment Recorded (Receipt: {$receipt_number})";
            $body = "Hello " . ($vendorRow['full_name'] ?? '') . ",\n\nA cash payment of " . formatCurrency($amount) . " was recorded and assigned to your account on " . date('Y-m-d', strtotime($payment_date)) . ".\n\nReceipt: {$receipt_number}\n\nRegards,\n" . (defined('APP_NAME') ? APP_NAME : 'Admin');
            @mail($vendorRow['email'], $subject, $body, "From: " . (defined('MAIL_FROM') ? MAIL_FROM : 'no-reply@example.com'));
        }
    } catch (Throwable $e) {
        error_log("create_manual_payment notify: " . $e->getMessage());
    }

    $pdo->commit();
    redirect_back('staff_success', "Manual cash payment recorded (Receipt: {$receipt_number}).", $from_page);
} catch (Throwable $e) {
    // ensure rollback and log
    try { $db->pdo()->rollBack(); } catch (Throwable $_) {}
    $err_ref = 'payerr_' . bin2hex(random_bytes(6));
    error_log("create_manual_payment transaction failed [ref={$err_ref}]: " . $e->getMessage());
    redirect_back('staff_error', 'Failed to record manual payment. Please try again or contact support with reference: ' . $err_ref, $from_page);
}