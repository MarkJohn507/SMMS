<?php
// manage_payments.php (FULL FIX with toaster + manual cash application to existing unpaid invoice)
// - Manual cash payments are ONLY allowed in Vendor Lookup tab.
// - Payments tab has no manual cash actions and includes a sort filter.
// - Manual cash applies to the oldest unpaid invoice (pending/partial/overdue) for the selected stall/lease.
// - Capped to remaining balance if entered amount > remaining.
// - Only stalls with unpaid invoices are shown in the manual cash form.
// - Fixes layout so the manual cash card isn't stretched.
// - Adds toast notifications for $success and $errors.
// - Avoids invalid date formatting for empty payment_date by showing "—".

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/csrf.php';
require_once 'includes/notifications.php';
require_once 'includes/helpers.php'; // sanitize, formatDate, formatCurrency, getStatusBadge

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

/* ---------- Helpers ---------- */
function safe_html($val): string {
    if (is_array($val)) {
        return htmlspecialchars(json_encode($val, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }
    return htmlspecialchars((string)$val);
}
function db_col_exists($db, string $table, string $col): bool {
    try {
        return (bool)$db->fetch("SELECT 1 FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? AND column_name=? LIMIT 1", [$table, $col]);
    } catch (Throwable $e) { return false; }
}
function generate_receipt_number($db, $baseDate = null): string {
    $baseDate = $baseDate ?: date('Ymd');
    $attempts = 0;
    do {
        $candidate = 'RCT-' . $baseDate . '-' . strtoupper(substr(bin2hex(random_bytes(4)), -6));
        $dup = $db->fetch("SELECT payment_id FROM payments WHERE receipt_number=? LIMIT 1", [$candidate]);
        if (!$dup) return $candidate;
        $attempts++;
    } while ($attempts < 5);
    return 'RCT-' . $baseDate . '-' . time();
}

/* ---------- Roles / Access ---------- */
if (function_exists('refreshSessionRoles')) {
    try { refreshSessionRoles($db); } catch (Throwable $e) { error_log("manage_payments: refreshSessionRoles failed: ".$e->getMessage()); }
}

$uid = (int)($_SESSION['user_id'] ?? 0);
if (!$uid) redirect('login.php');

$normalizedRoles = [];
try {
    if (function_exists('_fetchUserRoleNames')) {
        $normalizedRoles = _fetchUserRoleNames($uid, $db) ?: [];
    } elseif (!empty($_SESSION['roles']) && is_array($_SESSION['roles'])) {
        $normalizedRoles = $_SESSION['roles'];
    }
} catch (Throwable $e) {
    error_log("manage_payments: failed to fetch role names for user {$uid}: ".$e->getMessage());
    $normalizedRoles = $_SESSION['roles'] ?? [];
}
$normalizedRoles = array_map('strtolower', $normalizedRoles);
$is_accountant     = in_array('accountant', $normalizedRoles, true);
$is_market_manager = in_array('market_manager', $normalizedRoles, true);

$can_access = $is_accountant || $is_market_manager;
if (!$can_access) {
    http_response_code(403);
    echo "Forbidden";
    exit;
}

$page_title = 'Manage Payments';
$errors = [];
$success = '';

/* ---------- Market scoping ---------- */
function getUserScopedMarketIds($db, int $userId): array {
    $ids = [];
    try { $rows = $db->fetchAll("SELECT market_id FROM market_managers WHERE user_id = ?", [$userId]) ?: []; foreach ($rows as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id']; } catch (Throwable $e) {}
    try { $rows = $db->fetchAll("SELECT market_id FROM markets WHERE created_by = ?", [$userId]) ?: []; foreach ($rows as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id']; } catch (Throwable $e) {}
    try { $rows = $db->fetchAll("SELECT DISTINCT market_id FROM user_roles WHERE user_id = ? AND market_id IS NOT NULL AND status='active'", [$userId]) ?: []; foreach ($rows as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id']; } catch (Throwable $e) {}
    return array_values(array_unique($ids));
}
$user_scoped_market_ids = getUserScopedMarketIds($db, $uid);
$is_scoped_user = ($is_market_manager || $is_accountant);

/* ---------- Filters / Tab ---------- */
$status_filter          = isset($_GET['status']) ? sanitize($_GET['status']) : 'all';
$vendor_filter          = isset($_GET['vendor']) ? (int)$_GET['vendor'] : 0;
$payment_method_filter  = isset($_GET['payment_method']) ? sanitize($_GET['payment_method']) : 'all';
$search                 = isset($_GET['search']) ? sanitize($_GET['search']) : '';
$date_from              = isset($_GET['date_from']) ? sanitize($_GET['date_from']) : '';
$date_to                = isset($_GET['date_to']) ? sanitize($_GET['date_to']) : '';
$active_tab             = isset($_GET['tab']) ? sanitize($_GET['tab']) : 'payments';

$sort = isset($_GET['sort']) ? strtolower(trim(sanitize($_GET['sort']))) : 'due_desc';
$allowedSorts = ['due_desc','due_asc','amount_desc','amount_asc','status_asc','status_desc','method_asc','method_desc',
                 'vendor_asc','vendor_desc','paid_desc','paid_asc','created_desc','created_asc'];
if (!in_array($sort, $allowedSorts, true)) $sort = 'due_desc';

/* ---------- Vendors list (scoped) ---------- */
try {
    if (!empty($user_scoped_market_ids)) {
        $ph = implode(',', array_fill(0, count($user_scoped_market_ids), '?'));
        $vendors = $db->fetchAll("
            SELECT DISTINCT u.user_id, u.full_name
            FROM users u
            JOIN leases l ON u.user_id = l.vendor_id
            JOIN stalls s ON l.stall_id = s.stall_id
            WHERE s.market_id IN ($ph) AND u.status='active'
            ORDER BY u.full_name
        ", $user_scoped_market_ids) ?: [];
    } else { $vendors = []; }
} catch (Throwable $e) { error_log("manage_payments vendors: ".$e->getMessage()); $vendors = []; }

/* ---------- Stalls list (scoped) ---------- */
try {
    if (!empty($user_scoped_market_ids)) {
        $ph = implode(',', array_fill(0, count($user_scoped_market_ids), '?'));
        $available_stalls = $db->fetchAll("
            SELECT s.stall_id, s.stall_number, m.market_name,
                   EXISTS(SELECT 1 FROM leases l WHERE l.stall_id = s.stall_id AND l.status='active') AS has_active_lease
            FROM stalls s
            JOIN markets m ON s.market_id = m.market_id
            WHERE s.market_id IN ($ph)
            ORDER BY m.market_name, s.stall_number
        ", $user_scoped_market_ids) ?: [];
    } else { $available_stalls = []; }
} catch (Throwable $e) { error_log("manage_payments stalls: ".$e->getMessage()); $available_stalls = []; }

/* ---------- Vendor lookup parameters ---------- */
$vendor_lookup_id   = isset($_GET['lookup_vendor']) ? (int)$_GET['lookup_vendor'] : (isset($_GET['lookup_vendor_select']) ? (int)$_GET['lookup_vendor_select'] : 0);
$vendor_search_text = isset($_GET['lookup_search']) ? sanitize($_GET['lookup_search']) : '';

/* ---------- Manual cash payment (apply to existing unpaid invoice) ---------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create_manual_payment'])) {
    if (!csrf_validate_request()) {
        $errors[] = 'Invalid CSRF token.';
    } else {
        $manual_vendor_id = (int)($_POST['vendor_id'] ?? 0);
        $manual_stall_id  = (int)($_POST['stall_id'] ?? 0);
        $manual_amount    = (float)($_POST['amount'] ?? 0);
        $manual_date      = sanitize($_POST['payment_date'] ?? '') ?: date('Y-m-d');
        $manual_notes     = sanitize($_POST['notes'] ?? '');
        $redirect_to      = $_POST['from_page'] ?? 'manage_payments.php?tab=vendor&lookup_vendor='.$manual_vendor_id;

        if ($manual_vendor_id <= 0 || $manual_stall_id <= 0) $errors[] = 'Vendor and stall are required.';
        if ($manual_amount <= 0) $errors[] = 'Amount must be greater than zero.';
        if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $manual_date)) $errors[] = 'Invalid payment date.';

        // Scope check
        if (empty($errors) && $is_scoped_user && !empty($user_scoped_market_ids)) {
            $stallMarketRow = $db->fetch("SELECT market_id FROM stalls WHERE stall_id=? LIMIT 1", [$manual_stall_id]);
            $stMarketId = (int)($stallMarketRow['market_id'] ?? 0);
            if (!$stMarketId || !in_array($stMarketId, $user_scoped_market_ids, true)) {
                $errors[] = 'You do not have permission for this stall.';
            }
        }

        if (empty($errors)) {
            try {
                // Find active lease
                $leaseRow = $db->fetch("
                    SELECT l.lease_id, l.monthly_rent, l.vendor_id
                    FROM leases l
                    WHERE l.vendor_id=? AND l.stall_id=? AND l.status='active'
                    LIMIT 1
                ", [$manual_vendor_id, $manual_stall_id]);

                if (!$leaseRow) {
                    $errors[] = 'No active lease found for vendor & stall.';
                } else {
                    $lease_id = (int)$leaseRow['lease_id'];

                    // Find earliest unpaid invoice
                    $unpaidPayment = $db->fetch("
                        SELECT * FROM payments
                        WHERE lease_id=? AND status IN ('pending','partial','overdue')
                        ORDER BY due_date ASC, payment_id ASC
                        LIMIT 1
                    ", [$lease_id]);

                    $hasAmountPaidCol = db_col_exists($db, 'payments', 'amount_paid');

                    $db->beginTransaction();

                    if ($unpaidPayment) {
                        $payment_id    = (int)$unpaidPayment['payment_id'];
                        $invoice_amount= (float)$unpaidPayment['amount'];
                        $already_paid  = $hasAmountPaidCol ? (float)$unpaidPayment['amount_paid'] : 0.0;
                        $remaining     = max(0.0, round($invoice_amount - $already_paid, 2));
                        $applied_amount = min($manual_amount, $remaining);
                        $new_paid_total = $already_paid + $applied_amount;
                        $epsilon = 0.00001;
                        $new_status = ($new_paid_total + $epsilon >= $invoice_amount) ? 'paid' : 'partial';
                        $receipt_number = $unpaidPayment['receipt_number'] ?: generate_receipt_number($db, date('Ymd', strtotime($manual_date)));

                        if ($manual_amount > $remaining) {
                            $manual_notes .= ($manual_notes ? ' ' : '') . '[Amount capped to remaining balance '.number_format($remaining, 2).']';
                        }

                        $updateSql = "
                            UPDATE payments
                               SET payment_date=?,
                                   payment_method='cash',
                                   status=?,
                                   receipt_number=?,
                                   notes=CONCAT(COALESCE(notes,''), '\n[Manual Cash] ', ?),
                                   updated_at=NOW()
                        ";
                        $updateVals = [$manual_date, $new_status, $receipt_number, $manual_notes];

                        if ($hasAmountPaidCol) {
                            $updateSql .= ", amount_paid=? ";
                            $updateVals[] = number_format($new_paid_total, 2, '.', '');
                        }

                        $updateSql .= " WHERE payment_id=? LIMIT 1";
                        $updateVals[] = $payment_id;

                        if (!$db->query($updateSql, $updateVals)) {
                            throw new Exception('Failed updating existing unpaid invoice.');
                        }

                        logAudit($db, $uid, 'Manual Cash Applied', 'payments', $payment_id, null,
                                 "applied={$applied_amount}; status={$new_status}");

                        $success = ($new_status === 'paid')
                            ? 'Manual payment recorded and invoice marked Paid.'
                            : 'Manual payment recorded as partial. Remaining balance updated.';

                    } else {
                        // No unpaid invoice exists (fallback new record)
                        $new_amount = $manual_amount;
                        $due_date   = $manual_date;
                        $status     = 'paid';
                        $receipt_number = generate_receipt_number($db, date('Ymd', strtotime($manual_date)));

                        $insertSql = "
                            INSERT INTO payments
                              (lease_id, vendor_id, amount, amount_paid, payment_date, due_date,
                               payment_type, payment_method, status, receipt_number, notes, created_at, updated_at, currency)
                            VALUES (?, ?, ?, ?, ?, ?, 'rent', 'cash', ?, ?, ?, NOW(), NOW(), 'PHP')
                        ";
                        $vals = [
                            $lease_id,
                            $manual_vendor_id,
                            number_format($new_amount, 2, '.', ''),
                            number_format($new_amount, 2, '.', ''), // amount_paid = amount
                            $manual_date,
                            $due_date,
                            $status,
                            $receipt_number,
                            "[Manual Cash New] ".$manual_notes
                        ];
                        if (!$db->query($insertSql, $vals)) {
                            throw new Exception('Failed to create new manual payment record.');
                        }
                        $newPaymentId = (int)$db->lastInsertId();
                        logAudit($db, $uid, 'Manual Cash Created New Payment', 'payments', $newPaymentId, null, null);
                        $success = 'Manual payment recorded as a new invoice (no prior unpaid invoice existed).';
                    }

                    $db->commit();

                    if ($manual_vendor_id > 0 && function_exists('createNotification')) {
                        try {
                            createNotification(
                                $db,
                                $manual_vendor_id,
                                'Payment Recorded',
                                "A manual cash payment of ".formatCurrency($manual_amount)." has been recorded.",
                                'success',
                                'payment',
                                null,
                                'payments'
                            );
                        } catch (Throwable $e) {}
                    }

                    header('Location: manage_payments.php?tab=vendor&lookup_vendor='.$manual_vendor_id);
                    exit;
                }
            } catch (Throwable $e) {
                try { $db->rollBack(); } catch (Throwable $e2) {}
                error_log("manual payment failed: ".$e->getMessage());
                $errors[] = 'Failed recording manual payment.';
            }
        }
    }
}

/* ---------- Payments list (display only; no manual cash actions) ---------- */
$sql = "
    SELECT p.*, l.business_name, s.stall_number, m.market_name, u.full_name AS vendor_name, p.vendor_id
    FROM payments p
    JOIN leases l ON p.lease_id = l.lease_id
    JOIN stalls s ON l.stall_id = s.stall_id
    JOIN markets m ON s.market_id = m.market_id
    LEFT JOIN users u ON p.vendor_id = u.user_id
    WHERE 1=1
";
$params = [];
if ($status_filter !== 'all')            { $sql .= " AND p.status = ?";        $params[] = $status_filter; }
if ($vendor_filter > 0)                  { $sql .= " AND p.vendor_id = ?";     $params[] = $vendor_filter; }
if ($payment_method_filter !== 'all') {
    if ($payment_method_filter === 'paypal') {
        $sql .= " AND (p.payment_method='paypal' OR p.payment_method='online')";
    } else {
        $sql .= " AND p.payment_method = ?";
        $params[] = $payment_method_filter;
    }
}
if ($date_from) { $sql .= " AND p.due_date >= ?"; $params[] = $date_from; }
if ($date_to)   { $sql .= " AND p.due_date <= ?"; $params[] = $date_to; }
if ($search) {
    $sql .= " AND (l.business_name LIKE ? OR u.full_name LIKE ? OR s.stall_number LIKE ? OR p.receipt_number LIKE ?)";
    $like = "%{$search}%";
    $params = array_merge($params, [$like,$like,$like,$like]);
}
if ($is_scoped_user) {
    if (!empty($user_scoped_market_ids)) {
        $ph = implode(',', array_fill(0, count($user_scoped_market_ids), '?'));
        $sql .= " AND s.market_id IN ($ph)";
        $params = array_merge($params, $user_scoped_market_ids);
    } else { $sql .= " AND 0=1"; }
}

$sortOrder = "p.due_date DESC";
switch ($sort) {
    case 'due_asc':      $sortOrder = "p.due_date ASC"; break;
    case 'amount_desc':  $sortOrder = "p.amount DESC"; break;
    case 'amount_asc':   $sortOrder = "p.amount ASC"; break;
    case 'status_asc':   $sortOrder = "p.status ASC"; break;
    case 'status_desc':  $sortOrder = "p.status DESC"; break;
    case 'method_asc':   $sortOrder = "p.payment_method ASC"; break;
    case 'method_desc':  $sortOrder = "p.payment_method DESC"; break;
    case 'vendor_asc':   $sortOrder = "u.full_name ASC"; break;
    case 'vendor_desc':  $sortOrder = "u.full_name DESC"; break;
    case 'paid_desc':    $sortOrder = "p.payment_date DESC"; break;
    case 'paid_asc':     $sortOrder = "p.payment_date ASC"; break;
    case 'created_desc': $sortOrder = "p.created_at DESC"; break;
    case 'created_asc':  $sortOrder = "p.created_at ASC"; break;
}
$sql .= " ORDER BY ".$sortOrder;

try { $payments = $db->fetchAll($sql, $params) ?: []; } catch (Throwable $e) { error_log("manage_payments list fetch failed: ".$e->getMessage()); $payments = []; }

/* ---------- CSV Export ---------- */
if (isset($_GET['export']) && $_GET['export'] === 'csv') {
    $export_sql = "
        SELECT
            p.receipt_number,
            COALESCE(u.full_name,'-') AS vendor_name,
            l.business_name,
            s.stall_number,
            m.market_name,
            p.amount,
            p.payment_method,
            p.due_date,
            p.payment_date,
            p.status,
            p.notes
        FROM payments p
        LEFT JOIN leases l ON p.lease_id = l.lease_id
        LEFT JOIN stalls s ON l.stall_id = s.stall_id
        LEFT JOIN markets m ON s.market_id = m.market_id
        LEFT JOIN users u ON p.vendor_id = u.user_id
        WHERE 1=1
    ";
    $export_params = [];
    if ($status_filter !== 'all')           { $export_sql .= " AND p.status=?";         $export_params[] = $status_filter; }
    if ($vendor_filter > 0)                 { $export_sql .= " AND p.vendor_id=?";      $export_params[] = $vendor_filter; }
    if ($payment_method_filter !== 'all') {
        if ($payment_method_filter === 'paypal') {
            $export_sql .= " AND (p.payment_method='paypal' OR p.payment_method='online')";
        } else {
            $export_sql .= " AND p.payment_method=?";
            $export_params[] = $payment_method_filter;
        }
    }
    if ($date_from) { $export_sql .= " AND p.due_date >= ?"; $export_params[] = $date_from; }
    if ($date_to)   { $export_sql .= " AND p.due_date <= ?"; $export_params[] = $date_to; }
    if ($search) {
        $export_sql .= " AND (l.business_name LIKE ? OR u.full_name LIKE ? OR s.stall_number LIKE ? OR p.receipt_number LIKE ?)";
        $like = "%{$search}%";
        $export_params = array_merge($export_params, [$like,$like,$like,$like]);
    }
    if ($is_scoped_user) {
        if (!empty($user_scoped_market_ids)) {
            $ph = implode(',', array_fill(0, count($user_scoped_market_ids), '?'));
            $export_sql .= " AND s.market_id IN ($ph)";
            $export_params = array_merge($export_params, $user_scoped_market_ids);
        } else { $export_sql .= " AND 0=1"; }
    }
    $export_sql .= " ORDER BY ".$sortOrder;
    try { $rows = $db->fetchAll($export_sql, $export_params) ?: []; } catch (Throwable $e) { $rows = []; }

    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="payments_export_'.date('Y-m-d_His').'.csv"');
    $out = fopen('php://output','w');
    fputcsv($out, ['Receipt Number','Vendor Name','Business Name','Stall Number','Market','Amount','Payment Method','Due Date','Paid Date','Status','Notes']);
    foreach ($rows as $r) {
        fputcsv($out, [
            $r['receipt_number'] ?: '-',
            $r['vendor_name'],
            $r['business_name'],
            $r['stall_number'],
            $r['market_name'],
            $r['amount'],
            ucfirst(str_replace('_',' ',$r['payment_method'])),
            $r['due_date'],
            $r['payment_date'] ?: '—',
            ucfirst($r['status']),
            strip_tags($r['notes'] ?? '')
        ]);
    }
    fclose($out);
    exit;
}

/* ---------- Stats ---------- */
$stats_sql = "
    SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN p.status='paid'    THEN p.amount ELSE 0 END) AS total_paid,
        SUM(CASE WHEN p.status='pending' THEN p.amount ELSE 0 END) AS total_pending,
        SUM(CASE WHEN p.status='overdue' THEN p.amount ELSE 0 END) AS total_overdue,
        SUM(CASE WHEN p.status='partial' THEN p.amount ELSE 0 END) AS total_partial
    FROM payments p
    JOIN leases l ON p.lease_id = l.lease_id
    JOIN stalls s ON l.stall_id = s.stall_id
    WHERE 1=1
";
$stats_params = [];
if ($vendor_filter > 0) { $stats_sql .= " AND p.vendor_id=?"; $stats_params[] = $vendor_filter; }
if ($is_scoped_user) {
    if (!empty($user_scoped_market_ids)) {
        $ph = implode(',', array_fill(0, count($user_scoped_market_ids), '?'));
        $stats_sql .= " AND s.market_id IN ($ph)";
        $stats_params = array_merge($stats_params, $user_scoped_market_ids);
    } else { $stats_sql .= " AND 0=1"; }
}
try { $stats = $db->fetch($stats_sql, $stats_params) ?: []; } catch (Throwable $e) { $stats = []; }
$stats = array_merge(['total'=>0,'total_paid'=>0,'total_pending'=>0,'total_overdue'=>0,'total_partial'=>0], $stats);

/* ---------- Vendor Lookup Tab Data ---------- */
$vendor_matches = [];
$vendor_tab_data = [
    'vendor'=>null,'leases'=>[],'payments'=>[],
    'overdue_count'=>0,'overdue_amount'=>0.0,'pending_count'=>0,'pending_amount'=>0.0
];

if ($active_tab === 'vendor') {
    try {
        if ($vendor_search_text !== '') {
            if ($is_scoped_user && !empty($user_scoped_market_ids)) {
                $ph = implode(',', array_fill(0, count($user_scoped_market_ids), '?'));
                $vendor_matches = $db->fetchAll("
                    SELECT DISTINCT u.user_id, u.full_name, u.username, u.email
                    FROM users u
                    JOIN leases l ON u.user_id = l.vendor_id
                    JOIN stalls s ON l.stall_id = s.stall_id
                    WHERE (u.full_name LIKE ? OR u.username LIKE ?)
                      AND s.market_id IN ($ph)
                    ORDER BY u.full_name LIMIT 50
                ", array_merge(["%{$vendor_search_text}%","%{$vendor_search_text}%"], $user_scoped_market_ids)) ?: [];
            }
        }
        if ($vendor_lookup_id > 0) {
            $vendor = $db->fetch("SELECT user_id, full_name, email, username FROM users WHERE user_id=? LIMIT 1", [$vendor_lookup_id]);
            if ($vendor) {
                $vendor_tab_data['vendor'] = $vendor;
                $vid = (int)$vendor['user_id'];

                $leaseSql = "
                    SELECT l.*, s.stall_id, s.stall_number, s.market_id, m.market_name
                    FROM leases l
                    JOIN stalls s ON l.stall_id = s.stall_id
                    JOIN markets m ON s.market_id = m.market_id
                    WHERE l.vendor_id=?
                ";
                $leaseParams = [$vid];
                if ($is_scoped_user && !empty($user_scoped_market_ids)) {
                    $ph = implode(',', array_fill(0, count($user_scoped_market_ids), '?'));
                    $leaseSql .= " AND s.market_id IN ($ph)";
                    $leaseParams = array_merge($leaseParams, $user_scoped_market_ids);
                } else { $leaseSql .= " AND 0=1"; }
                $vendor_tab_data['leases'] = $db->fetchAll($leaseSql." ORDER BY l.status DESC, l.lease_start_date DESC", $leaseParams) ?: [];

                $paymentSql = "
                    SELECT p.*, l.stall_id, s.stall_number, s.market_id, m.market_name
                    FROM payments p
                    LEFT JOIN leases l ON p.lease_id = l.lease_id
                    LEFT JOIN stalls s ON l.stall_id = s.stall_id
                    LEFT JOIN markets m ON s.market_id = m.market_id
                    WHERE p.vendor_id=?
                ";
                $paymentParams = [$vid];
                if ($is_scoped_user && !empty($user_scoped_market_ids)) {
                    $ph = implode(',', array_fill(0, count($user_scoped_market_ids), '?'));
                    $paymentSql .= " AND s.market_id IN ($ph)";
                    $paymentParams = array_merge($paymentParams, $user_scoped_market_ids);
                } else { $paymentSql .= " AND 0=1"; }
                $vendor_tab_data['payments'] = $db->fetchAll($paymentSql." ORDER BY p.due_date DESC, p.payment_date DESC", $paymentParams) ?: [];

                foreach ($vendor_tab_data['payments'] as $p) {
                    $status = strtolower($p['status'] ?? '');
                    $amt    = (float)($p['amount'] ?? 0);
                    $due    = $p['due_date'] ?? null;
                    if ($status !== 'paid' && $due && $due < date('Y-m-d')) {
                        $vendor_tab_data['overdue_count']++;
                        $vendor_tab_data['overdue_amount'] += $amt;
                    }
                    if ($status === 'pending') {
                        $vendor_tab_data['pending_count']++;
                        $vendor_tab_data['pending_amount'] += $amt;
                    }
                }
            }
        }
    } catch (Throwable $e) {
        error_log("manage_payments vendor lookup failed: ".$e->getMessage());
        $errors[] = 'Vendor lookup failed.';
    }
}

/* ---------- Render ---------- */
include 'includes/header.php';
include 'includes/admin_sidebar.php';

// Toast CSS
?>
<style>
  .toast-host { position: fixed; top: 16px; right: 16px; z-index: 9999; display: flex; flex-direction: column; gap: 10px; pointer-events: none; }
  .toast { min-width: 260px; max-width: 380px; background: #1f2937; color: #fff; border-radius: 8px; box-shadow: 0 8px 24px rgba(0,0,0,0.16);
           padding: 12px 14px; display: flex; align-items: flex-start; gap: 10px; pointer-events: auto; opacity: 0; transform: translateY(-8px);
           transition: opacity 180ms ease, transform 180ms ease; border-left: 4px solid #3b82f6; font-size: 14px; line-height: 1.35; }
  .toast.show { opacity: 1; transform: translateY(0); }
  .toast.success { border-left-color: #10b981; }
  .toast.error   { border-left-color: #ef4444; }
  .toast.warn    { border-left-color: #f59e0b; }
  .toast-info    { border-left-color: #3b82f6; }
  .toast .toast-title { font-weight: 600; margin-bottom: 2px; }
  .toast .toast-close { margin-left: auto; background: transparent; border: none; color: #fff; opacity: 0.8; cursor: pointer; font-size: 16px; line-height: 1; }
  .toast .toast-close:hover { opacity: 1; }
</style>
<?php
$preserve = [];
foreach (['status','vendor','payment_method','date_from','date_to','search','sort'] as $k) {
    if (isset(${$k}) && ${$k} !== '' && ${$k} !== 'all' && ${$k} !== 0) $preserve[$k] = ${$k};
}
$payments_tab_url = 'manage_payments.php?'.http_build_query(array_merge($preserve, ['tab'=>'payments']));
$vendor_tab_url   = 'manage_payments.php?'.http_build_query(array_merge($preserve, ['tab'=>'vendor']));
?>
<div class="max-w-7xl mx-auto p-4 md:p-6">

  <!-- Tabs -->
  <div class="mb-6 flex flex-wrap gap-2">
    <a href="<?= safe_html($payments_tab_url) ?>"
       class="px-6 py-2.5 rounded-lg font-medium transition <?= $active_tab==='payments' ? 'bg-blue-600 text-white shadow' : 'bg-gray-100 text-gray-800 hover:bg-gray-200' ?>">
      Payments
    </a>
    <a href="<?= safe_html($vendor_tab_url) ?>"
       class="px-6 py-2.5 rounded-lg font-medium transition <?= $active_tab==='vendor' ? 'bg-blue-600 text-white shadow' : 'bg-gray-100 text-gray-800 hover:bg-gray-200' ?>">
      Vendor Lookup
    </a>
  </div>

  <!-- Messages (kept for accessibility; toasts will also show) -->
  <?php if ($errors): ?>
    <div class="mb-6 space-y-3">
      <?php foreach ($errors as $e): ?>
        <div class="bg-red-50 border-l-4 border-red-500 text-red-800 px-4 py-3 rounded flex gap-2">
          <strong>Error:</strong> <span><?= safe_html($e) ?></span>
        </div>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>
  <?php if ($success): ?>
    <div class="mb-6 bg-green-50 border-l-4 border-green-500 text-green-800 px-4 py-3 rounded">
      <?= safe_html($success) ?>
    </div>
  <?php endif; ?>

  <?php if ($active_tab === 'payments'): ?>
    <!-- Filters -->
    <form method="GET" class="bg-white p-6 rounded-lg shadow mb-6 border border-gray-200">
      <input type="hidden" name="tab" value="payments">
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
        <div>
          <label class="text-sm font-semibold mb-2 block">Status</label>
          <select name="status" class="w-full border rounded px-3 py-2">
            <option value="all">All</option>
            <option value="pending" <?= $status_filter==='pending'?'selected':''; ?>>Pending</option>
            <option value="paid" <?= $status_filter==='paid'?'selected':''; ?>>Paid</option>
            <option value="overdue" <?= $status_filter==='overdue'?'selected':''; ?>>Overdue</option>
            <option value="partial" <?= $status_filter==='partial'?'selected':''; ?>>Partial</option>
          </select>
        </div>
        <div>
          <label class="text-sm font-semibold mb-2 block">Vendor</label>
          <select name="vendor" class="w-full border rounded px-3 py-2">
            <option value="0">All Vendors</option>
            <?php foreach ($vendors as $v): ?>
              <option value="<?= (int)$v['user_id'] ?>" <?= $vendor_filter==$v['user_id']?'selected':''; ?>>
                <?= safe_html($v['full_name']) ?>
              </option>
            <?php endforeach; ?>
          </select>
        </div>
        <div>
          <label class="text-sm font-semibold mb-2 block">Payment Method</label>
          <select name="payment_method" class="w-full border rounded px-3 py-2">
            <option value="all">All</option>
            <option value="cash" <?= $payment_method_filter==='cash'?'selected':''; ?>>Cash</option>
            <option value="paypal" <?= $payment_method_filter==='paypal'?'selected':''; ?>>PayPal</option>
          </select>
        </div>
        <div>
          <label class="text-sm font-semibold mb-2 block">Date From</label>
          <input type="date" name="date_from" value="<?= safe_html($date_from) ?>" class="w-full border rounded px-3 py-2">
        </div>
        <div>
          <label class="text-sm font-semibold mb-2 block">Date To</label>
          <input type="date" name="date_to" value="<?= safe_html($date_to) ?>" class="w-full border rounded px-3 py-2">
        </div>
        <div class="lg:col-span-2">
          <label class="text-sm font-semibold mb-2 block">Search</label>
          <input type="text" name="search" value="<?= safe_html($search) ?>" placeholder="Business / Vendor / Stall / Receipt"
                 class="w-full border rounded px-3 py-2">
        </div>
        <div>
          <label class="text-sm font-semibold mb-2 block">Sort</label>
          <select name="sort" class="w-full border rounded px-3 py-2">
            <option value="due_desc"     <?= $sort==='due_desc'?'selected':''; ?>>Due Date (Newest)</option>
            <option value="due_asc"      <?= $sort==='due_asc'?'selected':''; ?>>Due Date (Oldest)</option>
            <option value="amount_desc"  <?= $sort==='amount_desc'?'selected':''; ?>>Amount (High → Low)</option>
            <option value="amount_asc"   <?= $sort==='amount_asc'?'selected':''; ?>>Amount (Low → High)</option>
            <option value="status_asc"   <?= $sort==='status_asc'?'selected':''; ?>>Status (A → Z)</option>
            <option value="status_desc"  <?= $sort==='status_desc'?'selected':''; ?>>Status (Z → A)</option>
            <option value="method_asc"   <?= $sort==='method_asc'?'selected':''; ?>>Method (A → Z)</option>
            <option value="method_desc"  <?= $sort==='method_desc'?'selected':''; ?>>Method (Z → A)</option>
            <option value="vendor_asc"   <?= $sort==='vendor_asc'?'selected':''; ?>>Vendor (A → Z)</option>
            <option value="vendor_desc"  <?= $sort==='vendor_desc'?'selected':''; ?>>Vendor (Z → A)</option>
            <option value="paid_desc"    <?= $sort==='paid_desc'?'selected':''; ?>>Paid Date (Newest)</option>
            <option value="paid_asc"     <?= $sort==='paid_asc'?'selected':''; ?>>Paid Date (Oldest)</option>
            <option value="created_desc" <?= $sort==='created_desc'?'selected':''; ?>>Created (Newest)</option>
            <option value="created_asc"  <?= $sort==='created_asc'?'selected':''; ?>>Created (Oldest)</option>
          </select>
        </div>
      </div>
      <div class="flex flex-wrap gap-3">
        <button class="px-6 py-2 bg-blue-600 text-white rounded">Apply Filters</button>
        <a href="manage_payments.php" class="px-6 py-2 bg-gray-200 rounded">Reset</a>
        <button type="button" onclick="exportToCSV()" class="px-6 py-2 bg-green-600 text-white rounded">Export CSV</button>
      </div>
    </form>

    <!-- Payments table (no manual cash action column) -->
    <div class="bg-white rounded-lg shadow border border-gray-200 overflow-hidden">
      <?php if ($payments): ?>
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead class="bg-gray-50 border-b">
              <tr>
                <th class="py-3 px-4 text-left font-semibold">Receipt</th>
                <th class="py-3 px-4 text-left font-semibold">Vendor / Business</th>
                <th class="py-3 px-4 text-left font-semibold">Stall / Market</th>
                <th class="py-3 px-4 text-left font-semibold">Amount</th>
                <th class="py-3 px-4 text-left font-semibold">Due</th>
                <th class="py-3 px-4 text-left font-semibold">Paid</th>
                <th class="py-3 px-4 text-left font-semibold">Method</th>
                <th class="py-3 px-4 text-left font-semibold">Status</th>
              </tr>
            </thead>
            <tbody class="divide-y">
              <?php foreach ($payments as $p): ?>
                <tr class="hover:bg-blue-50">
                  <td class="py-3 px-4"><?= safe_html($p['receipt_number'] ?: '—') ?></td>
                  <td class="py-3 px-4">
                    <div class="font-medium"><?= safe_html($p['vendor_name'] ?: '—') ?></div>
                    <div class="text-xs text-gray-500"><?= safe_html($p['business_name'] ?: '') ?></div>
                  </td>
                  <td class="py-3 px-4">
                    <div class="font-medium"><?= safe_html($p['stall_number'] ?: '—') ?></div>
                    <div class="text-xs text-gray-500"><?= safe_html($p['market_name'] ?: '—') ?></div>
                  </td>
                  <td class="py-3 px-4 font-bold"><?= formatCurrency($p['amount']) ?></td>
                  <td class="py-3 px-4"><?= formatDate($p['due_date']) ?></td>
                  <td class="py-3 px-4"><?= !empty($p['payment_date']) ? formatDate($p['payment_date']) : '—' ?></td>
                  <td class="py-3 px-4"><?= safe_html(ucfirst(str_replace('_',' ',$p['payment_method']))) ?></td>
                  <td class="py-3 px-4"><?= getStatusBadge($p['status']) ?></td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      <?php else: ?>
        <div class="p-8 text-center text-gray-600">No payments found for current filters.</div>
      <?php endif; ?>
    </div>

  <?php else: /* Vendor Lookup Tab */ ?>

    <!-- Vendor Search -->
    <div class="bg-white p-6 rounded-lg shadow mb-6 border border-gray-200">
      <h3 class="font-semibold text-lg mb-4 flex items-center gap-2">
        <svg class="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
        </svg>
        Vendor Search
      </h3>
      <form method="GET" class="flex flex-wrap gap-3">
        <?php foreach ($preserve as $k=>$v): ?>
          <input type="hidden" name="<?= safe_html($k) ?>" value="<?= safe_html($v) ?>">
        <?php endforeach; ?>
        <input type="hidden" name="tab" value="vendor">
        <input type="text" name="lookup_search" value="<?= safe_html($vendor_search_text) ?>" placeholder="Name or username"
               class="flex-1 border rounded px-3 py-2">
        <button class="px-5 py-2 bg-blue-600 text-white rounded">Search</button>
      </form>
    </div>

    <!-- Matches -->
    <?php if ($vendor_search_text !== ''): ?>
      <div class="bg-white p-6 rounded-lg shadow mb-6 border border-gray-200">
        <div class="mb-4">
          <span class="font-medium text-gray-700">Matches:</span>
          <span class="ml-2 px-2 py-1 bg-blue-100 text-blue-800 rounded-full text-xs font-bold"><?= count($vendor_matches) ?></span>
        </div>
        <?php if ($vendor_matches): ?>
          <ul class="space-y-3">
            <?php foreach ($vendor_matches as $m): ?>
              <li class="p-4 border rounded hover:border-blue-400 hover:bg-blue-50 transition">
                <div class="flex flex-col md:flex-row md:items-center justify-between gap-3">
                  <div>
                    <div class="font-semibold text-gray-900">
                      <?= safe_html($m['full_name']) ?> <span class="text-sm text-gray-500">@<?= safe_html($m['username']) ?></span>
                    </div>
                    <div class="text-sm text-gray-600"><?= safe_html($m['email'] ?? '—') ?></div>
                  </div>
                  <div>
                    <a class="px-4 py-2 bg-indigo-600 text-white rounded text-sm"
                       href="<?= safe_html('manage_payments.php?'.http_build_query(array_merge($preserve,['tab'=>'vendor','lookup_vendor'=>(int)$m['user_id']]))) ?>">
                      Select
                    </a>
                  </div>
                </div>
              </li>
            <?php endforeach; ?>
          </ul>
        <?php else: ?>
          <div class="text-sm text-gray-600">No vendor found matching "<?= safe_html($vendor_search_text) ?>".</div>
        <?php endif; ?>
      </div>
    <?php endif; ?>

    <!-- Vendor detail & manual payment -->
    <?php if ($vendor_tab_data['vendor']):
        $v = $vendor_tab_data['vendor'];
        // Filter active leases with at least one unpaid invoice (pending / partial / overdue)
        $raw_active_leases = array_filter($vendor_tab_data['leases'], fn($L)=>strtolower($L['status'] ?? '')==='active');
        $eligible_leases = [];
        foreach ($raw_active_leases as $L) {
            $unpaidCnt = $db->fetch("SELECT COUNT(*) c FROM payments WHERE lease_id=? AND status IN ('pending','partial','overdue')", [(int)$L['lease_id']]);
            if ((int)($unpaidCnt['c'] ?? 0) > 0) $eligible_leases[] = $L;
        }
    ?>
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div class="lg:col-span-2 space-y-6">
          <!-- Vendor Summary -->
            <div class="bg-white p-6 rounded-lg shadow border border-gray-200">
              <h4 class="font-semibold text-gray-900 mb-2">
                <?= safe_html($v['full_name']) ?> <span class="text-sm text-gray-500">@<?= safe_html($v['username']) ?></span>
              </h4>
              <div class="text-sm text-gray-600 mb-4">
                Email: <?= safe_html($v['email'] ?: '—') ?> • Vendor ID: <?= (int)$v['user_id'] ?>
              </div>
              <div class="flex gap-8 text-sm">
                <div>
                  <div class="text-xs text-gray-500">Overdue</div>
                  <div class="font-bold text-red-600 text-lg"><?= (int)$vendor_tab_data['overdue_count'] ?></div>
                  <div><?= formatCurrency($vendor_tab_data['overdue_amount']) ?></div>
                </div>
                <div>
                  <div class="text-xs text-gray-500">Pending</div>
                  <div class="font-bold text-yellow-600 text-lg"><?= (int)$vendor_tab_data['pending_count'] ?></div>
                  <div><?= formatCurrency($vendor_tab_data['pending_amount']) ?></div>
                </div>
              </div>
            </div>

          <!-- Leases -->
          <div class="bg-white p-6 rounded-lg shadow border border-gray-200">
            <h5 class="font-semibold mb-3">Leases</h5>
            <?php if ($vendor_tab_data['leases']): ?>
              <div class="overflow-x-auto">
                <table class="w-full text-sm">
                  <thead class="bg-gray-50 text-left">
                    <tr>
                      <th class="py-2 px-3">Market</th>
                      <th class="py-2 px-3">Stall</th>
                      <th class="py-2 px-3">Status</th>
                      <th class="py-2 px-3">Period</th>
                      <th class="py-2 px-3">Monthly Rent</th>
                    </tr>
                  </thead>
                  <tbody class="divide-y">
                    <?php foreach ($vendor_tab_data['leases'] as $L): ?>
                      <tr class="hover:bg-gray-50">
                        <td class="py-2 px-3"><?= safe_html($L['market_name'] ?? '—') ?></td>
                        <td class="py-2 px-3 font-medium"><?= safe_html($L['stall_number'] ?? '—') ?></td>
                        <td class="py-2 px-3">
                          <span class="px-2 py-1 rounded-full bg-blue-100 text-blue-700 text-xs">
                            <?= safe_html(ucfirst($L['status'] ?? '—')) ?>
                          </span>
                        </td>
                        <td class="py-2 px-3 text-xs text-gray-600">
                          <?= safe_html(($L['lease_start_date'] ?? '—').' → '.($L['lease_end_date'] ?? '—')) ?>
                        </td>
                        <td class="py-2 px-3 font-semibold"><?= formatCurrency($L['monthly_rent'] ?? 0) ?></td>
                      </tr>
                    <?php endforeach; ?>
                  </tbody>
                </table>
              </div>
            <?php else: ?>
              <div class="text-sm text-gray-600">No leases within your scoped markets.</div>
            <?php endif; ?>
          </div>

          <!-- Recent Payments -->
          <div class="bg-white p-6 rounded-lg shadow border border-gray-200">
            <h5 class="font-semibold mb-3">Recent Payments</h5>
            <?php if ($vendor_tab_data['payments']): ?>
              <div class="overflow-x-auto">
                <table class="w-full text-sm">
                  <thead class="bg-gray-50 text-left">
                    <tr>
                      <th class="py-2 px-3">Receipt</th>
                      <th class="py-2 px-3">Stall / Market</th>
                      <th class="py-2 px-3">Amount</th>
                      <th class="py-2 px-3">Due</th>
                      <th class="py-2 px-3">Paid</th>
                      <th class="py-2 px-3">Status</th>
                    </tr>
                  </thead>
                  <tbody class="divide-y">
                    <?php foreach ($vendor_tab_data['payments'] as $p): ?>
                      <tr class="hover:bg-gray-50">
                        <td class="py-2 px-3 font-medium"><?= safe_html($p['receipt_number'] ?: '—') ?></td>
                        <td class="py-2 px-3">
                          <div class="font-medium"><?= safe_html($p['stall_number'] ?? '—') ?></div>
                          <div class="text-xs text-gray-500"><?= safe_html($p['market_name'] ?? '—') ?></div>
                        </td>
                        <td class="py-2 px-3 font-semibold"><?= formatCurrency($p['amount'] ?? 0) ?></td>
                        <td class="py-2 px-3"><?= formatDate($p['due_date'] ?? null) ?></td>
                        <td class="py-2 px-3"><?= !empty($p['payment_date']) ? formatDate($p['payment_date']) : '—' ?></td>
                        <td class="py-2 px-3"><?= getStatusBadge($p['status'] ?? '') ?></td>
                      </tr>
                    <?php endforeach; ?>
                  </tbody>
                </table>
              </div>
            <?php else: ?>
              <div class="text-sm text-gray-600">No payments found in scoped markets.</div>
            <?php endif; ?>
          </div>
        </div>

        <!-- Manual Cash Payment (not stretched; only eligible stalls) -->
        <div class="bg-gradient-to-br from-indigo-50 to-blue-50 p-6 rounded-lg shadow border border-indigo-200 self-start max-w-md w-full">
          <h5 class="font-semibold text-lg mb-2">Create Manual Cash Payment</h5>
          <p class="text-sm text-gray-600 mb-4">Apply a manual cash payment to the vendor's existing unpaid invoice.</p>
          <?php if (empty($eligible_leases)): ?>
            <div class="bg-red-50 border-l-4 border-red-500 text-red-700 p-3 rounded text-sm">
              No eligible stalls with unpaid invoices for this vendor.
            </div>
          <?php else: ?>
            <form method="POST" class="space-y-3">
              <?php echo csrf_field(); ?>
              <input type="hidden" name="create_manual_payment" value="1">
              <input type="hidden" name="vendor_id" value="<?= (int)$v['user_id'] ?>">
              <input type="hidden" name="from_page" value="<?= safe_html('manage_payments.php?'.http_build_query(array_merge($preserve,['tab'=>'vendor','lookup_vendor'=>(int)$v['user_id']]))) ?>">

              <div>
                <label class="text-sm font-medium mb-1 block">Stall *</label>
                <select name="stall_id" required class="w-full border rounded px-3 py-2 text-sm">
                  <option value="">Select stall with unpaid invoice</option>
                  <?php foreach ($eligible_leases as $L): ?>
                    <option value="<?= (int)$L['stall_id'] ?>">
                      <?= safe_html($L['market_name'].' — '.$L['stall_number']) ?>
                    </option>
                  <?php endforeach; ?>
                </select>
                <p class="text-xs text-gray-500 mt-1">Only stalls with pending/partial/overdue invoices appear.</p>
              </div>
              <div>
                <label class="text-sm font-medium mb-1 block">Amount *</label>
                <input type="number" name="amount" step="0.01" min="0.01" required class="w-full border rounded px-3 py-2 text-sm" placeholder="0.00">
              </div>
              <div>
                <label class="text-sm font-medium mb-1 block">Payment Date *</label>
                <input type="date" name="payment_date" value="<?= date('Y-m-d') ?>" required class="w-full border rounded px-3 py-2 text-sm">
              </div>
              <div>
                <label class="text-sm font-medium mb-1 block">Notes (optional)</label>
                <textarea name="notes" rows="3" class="w-full border rounded px-3 py-2 text-sm"></textarea>
              </div>
              <button class="w-full bg-indigo-600 hover:bg-indigo-700 text-white rounded px-4 py-2 text-sm font-medium">
                Record Cash Payment
              </button>
            </form>
          <?php endif; ?>
        </div>
      </div>
    <?php endif; ?>
  <?php endif; ?>
</div>

<!-- Toast Container -->
<div id="toastHost" class="toast-host" aria-live="polite" aria-atomic="true"></div>

<script>
function exportToCSV(){
  const url=new URL(window.location.href);
  url.searchParams.set('export','csv');
  window.location.href=url.toString();
}
(function(){
  const host = document.getElementById('toastHost');
  if (!host) return;

  function escapeHtml(str) {
    try { return String(str).replace(/[&<>"'`=\/]/g, s => map[s] || s); }
    catch { return String(str); }
  }
  const map = {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;','/':'&#x2F;','`':'&#x60;','=':'&#x3D;'};

  function showToast(message, opts = {}) {
    const { title = '', type = 'info', duration = 3500, sticky = false } = opts;
    const el = document.createElement('div');
    el.className = `toast ${type === 'success' ? 'success' : type === 'error' ? 'error' : type === 'warn' ? 'warn' : 'toast-info'}`;
    el.innerHTML = `
      <div style="flex:1;">
        ${title ? `<div class="toast-title">${escapeHtml(title)}</div>` : ''}
        <div class="toast-body">${escapeHtml(message)}</div>
      </div>
      <button class="toast-close" aria-label="Close">&times;</button>
    `;
    const closeBtn = el.querySelector('.toast-close');
    const remove = () => { el.classList.remove('show'); setTimeout(() => el.remove(), 180); };
    closeBtn.addEventListener('click', remove);
    host.appendChild(el);
    requestAnimationFrame(() => el.classList.add('show'));
    if (!sticky) setTimeout(remove, duration);
    return el;
  }
  window.showToast = showToast;

  <?php if (!empty($success)): ?>
    showToast(<?php echo json_encode($success); ?>, { title: 'Success', type: 'success' });
  <?php endif; ?>
  <?php if (!empty($errors) && is_array($errors)): foreach ($errors as $e): ?>
    showToast(<?php echo json_encode($e); ?>, { title: 'Error', type: 'error' });
  <?php endforeach; endif; ?>
})();
</script>

<?php include 'includes/footer.php'; ?>