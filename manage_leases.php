<?php
require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/csrf.php';
require_once 'includes/notifications.php';
require_once 'includes/inspector_utils.php';
require_once 'includes/helpers.php'; // formatCurrency, formatDate

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

$page_title = 'Manage Leases';
$error = '';
$success = '';

$active_tab = isset($_GET['tab']) ? strtolower(trim($_GET['tab'])) : 'leases';
if (!in_array($active_tab, ['leases','applications'], true)) $active_tab = 'leases';

/* ------------------ Helpers ------------------ */
function getManagedMarketIds($db, int $userId): array {
    $ids = [];
    try {
        $rows = $db->fetchAll("SELECT market_id FROM market_managers WHERE user_id = ?", [$userId]) ?: [];
        foreach ($rows as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id'];
    } catch (Throwable $e) { error_log($e->getMessage()); }
    if (empty($ids)) {
        try {
            $rows = $db->fetchAll("SELECT market_id FROM markets WHERE created_by = ?", [$userId]) ?: [];
            foreach ($rows as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id'];
        } catch (Throwable $e) { error_log($e->getMessage()); }
    }
    return array_values(array_unique($ids));
}

function ensure_can_manage_lease($db, ?int $leaseId = null, ?int $stallId = null, ?int $marketId = null) {
    $uid = $_SESSION['user_id'] ?? null;
    if (!$uid) redirect('login.php');

    $adminRoles = ['super_admin', 'municipal_admin', 'issuer_admin', 'admin', 'agency_admin'];
    foreach ($adminRoles as $r) {
        if (function_exists('userIsInRole') && userIsInRole($db, $uid, $r)) return true;
    }
    if (function_exists('userHasPermission')) {
        try {
            if (userHasPermission($db, $uid, 'manage_markets') || userHasPermission($db, $uid, 'manage_leases')) return true;
        } catch (Throwable $e) { error_log($e->getMessage()); }
    }
    try {
        if (function_exists('userIsInRole') && userIsInRole($db, $uid, 'market_manager')) {
            $managed = getManagedMarketIds($db, $uid);
            if ($marketId !== null) {
                if (in_array((int)$marketId, $managed, true)) return true;
                http_response_code(403); echo "Forbidden: you do not have permissions to manage leases for this market."; exit;
            }
            if ($stallId !== null) {
                $row = $db->fetch("SELECT market_id FROM stalls WHERE stall_id = ? LIMIT 1", [$stallId]);
                $mId = $row['market_id'] ?? null;
                if ($mId !== null && in_array((int)$mId, $managed, true)) return true;
                http_response_code(403); echo "Forbidden: you do not have permissions to manage this stall."; exit;
            }
            if ($leaseId !== null) {
                $row = $db->fetch("SELECT s.market_id FROM leases l JOIN stalls s ON l.stall_id = s.stall_id WHERE l.lease_id = ? LIMIT 1", [$leaseId]);
                $mId = $row['market_id'] ?? null;
                if ($mId !== null && in_array((int)$mId, $managed, true)) return true;
                http_response_code(403); echo "Forbidden: you do not have permissions to manage this lease."; exit;
            }
            http_response_code(403); echo "Forbidden: scope is missing for lease management."; exit;
        }
    } catch (Throwable $e) { error_log($e->getMessage()); }
    http_response_code(403); echo "Forbidden: you do not have permissions to manage leases."; exit;
}

if (!function_exists('formatCurrency')) { function formatCurrency($amount){ return '₱'.number_format((float)$amount,2); } }
if (!function_exists('formatDate')) {
    function formatDate($date, $withTime=false){
        if (!$date || $date==='0000-00-00' || $date==='0000-00-00 00:00:00') return '-';
        $fmt = $withTime ? 'M j, Y g:i A' : 'M j, Y';
        $ts = strtotime($date);
        return $ts ? date($fmt, $ts) : '-';
    }
}
if (!function_exists('getStatusBadge')) {
    function getStatusBadge($status){
        $status=strtolower(trim($status));
        $map=[
            'active'=>'bg-green-100 text-green-700',
            'expired'=>'bg-yellow-100 text-yellow-700',
            'terminated'=>'bg-red-100 text-red-700',
            'pending'=>'bg-amber-100 text-amber-700',
            'termination_requested'=>'bg-orange-100 text-orange-700'
        ];
        $cls=$map[$status]??'bg-gray-100 text-gray-700';
        return "<span class='px-2 py-1 rounded text-xs font-semibold {$cls}'>".htmlspecialchars(ucwords(str_replace('_',' ',$status)))."</span>";
    }
}

/* Role flags */
$uid = $_SESSION['user_id'] ?? null;
$isMarketManager = false;
try { if ($uid && function_exists('userIsInRole') && userIsInRole($db, $uid, 'market_manager')) $isMarketManager = true; } catch (Throwable $e) { error_log($e->getMessage()); }

/* ---------------- Automatic renewal on page load ----------------
   Behavior:
   - On every page load, for active leases within the manager's scope (or admin scope), auto-renew by +1 month IF:
     * The lease has at least one PAID invoice (proof of payments exist), AND
     * The lease has NO unpaid invoices (no pending/partial/overdue), AND
     * The lease end date is today or in the past (<= CURDATE()).
   - Renewal creates a new monthly invoice (payments row) for the new period with status 'pending'.
   - Amount used for the new invoice:
     * If lease.monthly_rent is set, use it (this is the "modified new monthly rent").
     * Otherwise, fallback to stall.monthly_rent as the default.
   - Idempotency: Do not insert duplicate invoices for the same month. We check if a payments row already exists with due_date in the new month.
*/
function autoRenewEligibleLeases($db, int $actorUserId, ?array $scopeMarketIds = null) {
    // Build scope filter
    $scopeFilter = '';
    $params = [];
    if (!empty($scopeMarketIds)) {
        $ph = implode(',', array_fill(0, count($scopeMarketIds), '?'));
        $scopeFilter = " AND s.market_id IN ($ph) ";
        $params = array_merge($params, $scopeMarketIds);
    }

    // Find candidate active leases that should auto-renew now
    $sql = "
        SELECT l.lease_id, l.vendor_id, l.stall_id, l.monthly_rent, l.lease_end_date, l.lease_start_date,
               s.monthly_rent AS stall_default_rent
        FROM leases l
        JOIN stalls s ON l.stall_id = s.stall_id
        WHERE l.status='active'
          {$scopeFilter}
          AND (
              l.lease_end_date IS NULL
              OR l.lease_end_date='0000-00-00'
              OR l.lease_end_date <= CURDATE()
          )
          AND EXISTS (
              SELECT 1 FROM payments p
              WHERE p.lease_id = l.lease_id
                AND LOWER(TRIM(p.status))='paid'
          )
          AND NOT EXISTS (
              SELECT 1 FROM payments p2
              WHERE p2.lease_id = l.lease_id
                AND LOWER(TRIM(p2.status)) IN ('pending','partial','overdue')
          )
        LIMIT 300
    ";
    $candidates = $db->fetchAll($sql, $params) ?: [];
    if (!$candidates) return 0;

    $renewed = 0;
    foreach ($candidates as $cand) {
        $leaseId   = (int)$cand['lease_id'];
        $vendorId  = (int)$cand['vendor_id'];
        $stallId   = (int)$cand['stall_id'];
        $currEnd   = $cand['lease_end_date'];
        $startDate = $cand['lease_start_date'];

        $base = (!empty($currEnd) && $currEnd!=='0000-00-00') ? $currEnd
               : ((!empty($startDate) && $startDate!=='0000-00-00') ? $startDate : date('Y-m-d'));
        $newEnd = date('Y-m-d', strtotime($base.' +1 month'));

        // Determine rent to charge for the new invoice
        $rent = null;
        if (isset($cand['monthly_rent']) && $cand['monthly_rent'] !== null && (float)$cand['monthly_rent'] > 0) {
            $rent = (float)$cand['monthly_rent'];
        } else {
            $rent = (float)($cand['stall_default_rent'] ?? 0);
        }
        if ($rent <= 0) {
            // Skip if we cannot determine a valid rent
            continue;
        }

        try {
            $db->beginTransaction();

            // Lock lease row to avoid races
            $lock = $db->fetch("SELECT lease_end_date FROM leases WHERE lease_id=? AND status='active' FOR UPDATE", [$leaseId]);
            if (!$lock) { $db->rollBack(); continue; }

            // Recompute newEnd from locked value
            $lockedEnd = $lock['lease_end_date'];
            $baseLocked = (!empty($lockedEnd) && $lockedEnd!=='0000-00-00') ? $lockedEnd : $base;
            $newEnd = date('Y-m-d', strtotime($baseLocked.' +1 month'));

            // Update lease end date
            $okLease = $db->query("UPDATE leases SET lease_end_date=?, updated_at=NOW() WHERE lease_id=? AND status='active'", [$newEnd, $leaseId]);
            if (!$okLease) { $db->rollBack(); continue; }

            // Determine due date for the new invoice: set to newEnd (end of the renewed month)
            $dueDate = $newEnd;

            // Idempotency: check if there is already an invoice for this lease in the same year-month of dueDate
            $ym = date('Y-m', strtotime($dueDate));
            $exists = $db->fetch("
                SELECT payment_id FROM payments
                WHERE lease_id = ?
                  AND DATE_FORMAT(due_date, '%Y-%m') = ?
                LIMIT 1
            ", [$leaseId, $ym]);

            if (!$exists) {
                // Insert new pending invoice
                $okPay = $db->query("
                    INSERT INTO payments
                        (lease_id, vendor_id, amount, amount_paid, payment_date, due_date,
                         payment_type, payment_method, status, receipt_number, notes, created_at, updated_at, currency)
                    VALUES (?, ?, ?, 0, NULL, ?, 'rent', 'online', 'pending', NULL, '[Auto-renew invoice on page load]', NOW(), NOW(), 'PHP')
                ", [$leaseId, $vendorId, number_format($rent, 2, '.', ''), $dueDate]);
                if (!$okPay) { $db->rollBack(); continue; }
            }

            // Optional notification
            if (function_exists('createNotification')) {
                try {
                    createNotification($db, $vendorId, 'Lease Auto-Renewed',
                        "Your lease was auto-renewed. New end date: {$newEnd}. A new invoice has been generated for ".formatCurrency($rent).".",
                        'info', 'lease', $leaseId, 'leases');
                } catch (Throwable $e) { /* ignore */ }
            }

            logAudit($db, $actorUserId, 'Lease Auto-Renewed', 'leases', $leaseId, null, "new_end={$newEnd}, amount={$rent}");
            $db->commit();
            $renewed++;
        } catch (Throwable $e) {
            error_log("autoRenewEligibleLeases: ".$e->getMessage());
            try { $db->rollBack(); } catch (Throwable $e2) {}
        }
    }
    return $renewed;
}

/* Run auto-renew on page load (no cron), scoped to manager markets if applicable */
try {
    $scopeIds = null;
    if ($isMarketManager) {
        $scopeIds = getManagedMarketIds($db, (int)$uid);
    }
    $renewCount = autoRenewEligibleLeases($db, (int)$uid, $scopeIds);
    if ($renewCount > 0) {
        $success = "Auto-renewed {$renewCount} eligible lease(s) and generated monthly invoices.";
    }
} catch (Throwable $e) {
    error_log("page-load auto renew failed: ".$e->getMessage());
}

/* ---------------- Actions: Terminate, Create Lease ---------------- */

/* Terminate lease */
if (isset($_GET['terminate']) && !empty($_GET['terminate'])) {
    $lease_id = (int)$_GET['terminate'];
    if ($lease_id <= 0) {
        $error = 'Invalid lease selected.';
    } else {
        ensure_can_manage_lease($db, $lease_id, null, null);
        $lease = $db->fetch("
            SELECT l.*, s.stall_id, s.market_id, s.stall_number, l.vendor_id,
                   (SELECT COUNT(*) FROM payments p WHERE p.lease_id = l.lease_id AND LOWER(TRIM(p.status)) IN ('pending','overdue','partial')) AS pending_payments
            FROM leases l
            JOIN stalls s ON l.stall_id = s.stall_id
            WHERE l.lease_id = ? LIMIT 1
        ", [$lease_id]);
        if (!$lease) {
            $error = 'Lease not found.';
        } elseif (!empty($lease['pending_payments'])) {
            $error = 'Cannot terminate lease: there are pending or overdue payments.';
        } elseif ($isMarketManager && (int)$lease['pending_payments'] === 0) {
            $error = 'Cannot terminate: this lease is fully paid. Contact an administrator if termination is necessary.';
        } else {
            try {
                $ok = $db->query("UPDATE leases SET status = 'terminated', updated_at = NOW() WHERE lease_id = ?", [$lease_id]);
                if ($ok) {
                    try { if (!empty($lease['stall_id'])) $db->query("UPDATE stalls SET status = 'available' WHERE stall_id = ?", [$lease['stall_id']]); } catch (Throwable $_e) {}
                    if (!empty($lease['vendor_id']) && function_exists('createNotification')) {
                        try { createNotification($db, $lease['vendor_id'], 'Lease Terminated', "Your lease (ID: {$lease_id}) for stall " . ($lease['stall_number'] ?? '') . " has been terminated.", 'warning', 'lease', $lease_id, 'leases'); } catch (Throwable $_e) {}
                    }
                    logAudit($db, $uid, 'Lease Terminated', 'leases', $lease_id, null, null);
                    $_SESSION['flash_success'] = 'Lease terminated successfully.';
                    header('Location: manage_leases.php?tab=leases'); exit;
                } else { $error = 'Failed to terminate lease.'; }
            } catch (Throwable $e) { error_log($e->getMessage()); $error = 'Failed to terminate lease. Please try again later.'; }
        }
    }
}

/* Create lease (converted from application) */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create_lease'])) {
    if (!csrf_validate_request()) {
        $error = 'Invalid CSRF token.';
    } else {
        $application_id = (int)$_POST['application_id'] ?? 0;
        $lease_start_date = sanitize($_POST['lease_start_date'] ?? '') ?: null;
        $lease_end_date = sanitize($_POST['lease_end_date'] ?? '') ?: null;
        $monthly_rent = isset($_POST['monthly_rent']) && $_POST['monthly_rent'] !== '' ? (float)$_POST['monthly_rent'] : null;

        if ($application_id <= 0) {
            $error = 'Invalid application selected.';
        } elseif (empty($lease_start_date)) {
            $error = 'Please provide a lease start date.';
        } elseif ($lease_end_date !== null && $lease_end_date !== '' && strtotime($lease_end_date) <= strtotime($lease_start_date)) {
            $error = 'Lease end date must be after start date.';
        } else {
            $app = $db->fetch("
                SELECT a.*, s.stall_id, s.stall_number, s.market_id, s.monthly_rent AS stall_default_rent, u.user_id as vendor_id
                FROM applications a
                JOIN stalls s ON a.stall_id = s.stall_id
                JOIN users u  ON a.vendor_id = u.user_id
                WHERE a.application_id = ? LIMIT 1
            ", [$application_id]);
            if (!$app) {
                $error = 'Application not found.';
            } else {
                try { ensure_can_manage_lease($db, null, (int)$app['stall_id'], (int)$app['market_id']); } catch (Throwable $e) { $error = 'Permission check failed.'; }

                if (empty($error)) {
                    $existing = $db->fetch("SELECT lease_id FROM leases WHERE stall_id = ? AND status = 'active' LIMIT 1", [$app['stall_id']]);
                    if ($existing && !empty($existing['lease_id'])) {
                        $error = 'Cannot create lease: an active lease already exists for this stall (Lease ID: ' . (int)$existing['lease_id'] . ').';
                    }
                }
                if (empty($error)) {
                    $monthly_rent = $monthly_rent !== null ? $monthly_rent : ($app['proposal_monthly_rent'] ?? $app['stall_default_rent'] ?? 0);
                    if (empty($lease_end_date)) $lease_end_date = date('Y-m-d', strtotime($lease_start_date . ' +1 month'));
                }

                if (empty($error)) {
                    $db->beginTransaction();
                    try {
                        $sql = "INSERT INTO leases (stall_id, vendor_id, business_name, business_type, lease_start_date, lease_end_date, monthly_rent, status, created_at, updated_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?, 'active', NOW(), NOW())";
                        $ok = $db->query($sql, [
                            $app['stall_id'],
                            $app['vendor_id'],
                            $app['business_name'],
                            $app['business_type'],
                            $lease_start_date,
                            $lease_end_date,
                            $monthly_rent,
                        ]);
                        if (!$ok) throw new Exception('Insert lease failed');

                        $lease_id = (int)$db->lastInsertId();

                        $db->query("UPDATE stalls SET status = 'occupied' WHERE stall_id = ?", [$app['stall_id']]);
                        $db->query("UPDATE applications SET status = 'approved', admin_notes = CONCAT(COALESCE(admin_notes,''), ?) WHERE application_id = ?", ["\n[Converted to lease ID: {$lease_id} by manager {$uid}]", $application_id]);
                        $db->query("UPDATE applications SET status = 'cancelled', admin_notes = CONCAT(COALESCE(admin_notes,''), ?) WHERE stall_id = ? AND application_id <> ?", ["\n[Auto-cancelled due to lease creation ID: {$lease_id}]", $app['stall_id'], $application_id]);

                        $db->commit();

                        // Notifications
                        if (function_exists('createNotification')) {
                            try { createNotification($db, $app['vendor_id'], 'Lease Created', "Your lease has been created (Lease ID: {$lease_id}). Start: {$lease_start_date}", 'success', 'lease', $lease_id, 'leases'); } catch (Throwable $_e) {}
                            try {
                                $others = $db->fetchAll("SELECT vendor_id, application_id FROM applications WHERE stall_id = ? AND application_id <> ?", [$app['stall_id'], $application_id]) ?: [];
                                foreach ($others as $o) {
                                    if (!empty($o['vendor_id'])) {
                                        createNotification($db, (int)$o['vendor_id'], 'Application Cancelled', "Your application (#{$o['application_id']}) was cancelled because a lease was created for this stall.", 'warning', 'application', (int)$o['application_id'], 'applications');
                                    }
                                }
                            } catch (Throwable $_e) {}
                        }

                        schedulePreLeaseInspections($db, $lease_id, (int)$app['stall_id'], (int)$app['market_id'], $lease_start_date, (string)$app['stall_number']);

                        logAudit($db, $uid, 'Lease Created', 'leases', $lease_id, null, "From application #{$application_id}");
                        $success = 'Lease created successfully. Pre-lease inspections have been scheduled.';
                    } catch (Throwable $e) { $db->rollBack(); error_log($e->getMessage()); $error = 'Failed to create lease.'; }
                }
            }
        }
    }
}

/* ---------- Stats / Filters / Queries ---------- */
$uid = $_SESSION['user_id'] ?? null;
$isMarketManager = $uid && function_exists('userIsInRole') && userIsInRole($db, $uid, 'market_manager');

try {
    $stats_sql = "SELECT 
        COUNT(*) AS `total`,
        SUM(CASE WHEN `status` = 'active' THEN 1 ELSE 0 END) AS `active`,
        SUM(CASE WHEN `status` = 'expired' THEN 1 ELSE 0 END) AS `expired`,
        SUM(CASE WHEN `status` = 'terminated' THEN 1 ELSE 0 END) AS `terminated_count`,
        SUM(CASE WHEN `status` = 'active' THEN monthly_rent ELSE 0 END) AS `monthly_revenue`,
        SUM(CASE WHEN `status` = 'active' AND DATEDIFF(lease_end_date, CURDATE()) BETWEEN 1 AND 30 THEN 1 ELSE 0 END) AS `expiring_soon`
        FROM leases";
    if (!empty($isMarketManager)) {
        $managedIds = getManagedMarketIds($db, $uid);
        if (!empty($managedIds)) {
            $placeholders = implode(',', array_fill(0, count($managedIds), '?'));
            $stats = $db->fetch($stats_sql . " WHERE stall_id IN (SELECT stall_id FROM stalls WHERE market_id IN ($placeholders))", $managedIds) ?: [];
        } else {
            $stats = ['total'=>0,'active'=>0,'expired'=>0,'terminated_count'=>0,'monthly_revenue'=>0.0,'expiring_soon'=>0];
        }
    } else {
        $stats = $db->fetch($stats_sql) ?: [];
    }
} catch (Throwable $e) {
    error_log("manage_leases: stats query failed: " . $e->getMessage());
    $stats = ['total'=>0,'active'=>0,'expired'=>0,'terminated_count'=>0,'monthly_revenue'=>0.0,'expiring_soon'=>0];
}

$stats = [
    'total' => (int)($stats['total'] ?? 0),
    'active' => (int)($stats['active'] ?? 0),
    'expired' => (int)($stats['expired'] ?? 0),
    'terminated' => (int)($stats['terminated_count'] ?? 0),
    'monthly_revenue' => (float)($stats['monthly_revenue'] ?? 0.0),
    'expiring_soon' => (int)($stats['expiring_soon'] ?? 0),
];

$status_filter   = isset($_GET['status']) ? sanitize($_GET['status']) : 'all';
$search          = isset($_GET['search']) ? sanitize($_GET['search']) : '';
$expiring_filter = isset($_GET['expiring']) ? sanitize($_GET['expiring']) : '';
$balance_filter  = isset($_GET['balance']) ? strtolower(trim(sanitize($_GET['balance']))) : ''; // '', 'paid', 'unpaid'

// Sort filter: whitelist fields
$sort = isset($_GET['sort']) ? strtolower(trim(sanitize($_GET['sort']))) : '';
$dir  = isset($_GET['dir']) ? strtolower(trim(sanitize($_GET['dir']))) : '';
$allowedSorts = [
    'start_desc', 'start_asc', 'end_desc', 'end_asc',
    'rent_desc',  'rent_asc',  'balance_desc', 'balance_asc',
    'vendor_asc', 'vendor_desc'
];
if (!in_array($sort, $allowedSorts, true)) {
    if ($dir === 'asc') $sort = 'start_asc';
    elseif ($dir === 'desc') $sort = 'start_desc';
    else $sort = 'start_desc';
}

/* Applications list */
$proposal_search     = isset($_GET['proposal_search']) ? sanitize($_GET['proposal_search']) : '';
$proposal_market_id  = isset($_GET['proposal_market_id']) ? (int)$_GET['proposal_market_id'] : 0;
$proposal_stall_id   = isset($_GET['proposal_stall_id']) ? (int)$_GET['proposal_stall_id'] : 0;
$proposal_pref_start = isset($_GET['proposal_pref_start']) ? sanitize($_GET['proposal_pref_start']) : '';

$app_sql = "
    SELECT
        a.application_id, a.vendor_id, a.business_name, a.business_type, a.status AS app_status, a.application_date,
        NULLIF(a.preferred_start_date,'0000-00-00') AS preferred_start_date,
        a.admin_notes,
        s.stall_id, s.stall_number, s.monthly_rent as default_rent,
        s.market_id, m.market_name, u.full_name as vendor_name
    FROM applications a
    JOIN stalls s   ON a.stall_id = s.stall_id
    JOIN markets m  ON s.market_id = m.market_id
    JOIN users u    ON a.vendor_id = u.user_id
    WHERE LOWER(TRIM(a.status)) = 'pending'
";
$app_params = [];
try {
    $markets = [];
    if ($isMarketManager) {
        $managedIds = getManagedMarketIds($db, $uid);
        if (!empty($managedIds)) {
            $ph = implode(',', array_fill(0, count($managedIds), '?'));
            $markets = $db->fetchAll("SELECT market_id, market_name FROM markets WHERE market_id IN ($ph) ORDER BY market_name", $managedIds) ?: [];
            $app_sql .= " AND s.market_id IN ($ph)";
            $app_params = array_merge($app_params, $managedIds);
        }
    } else {
        $markets = $db->fetchAll("SELECT market_id, market_name FROM markets ORDER BY market_name") ?: [];
    }
    if ($proposal_market_id > 0) { $app_sql .= " AND s.market_id = ?"; $app_params[] = $proposal_market_id; }
    if ($proposal_stall_id > 0)  { $app_sql .= " AND s.stall_id = ?"; $app_params[] = $proposal_stall_id; }
    if (!empty($proposal_search)) {
        $ps = "%{$proposal_search}%";
        $app_sql .= " AND (a.business_name LIKE ? OR u.full_name LIKE ? OR s.stall_number LIKE ?)";
        $app_params[] = $ps; $app_params[] = $ps; $app_params[] = $ps;
    }
    if (!empty($proposal_pref_start) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $proposal_pref_start)) {
        $app_sql .= " AND NULLIF(a.preferred_start_date,'0000-00-00') >= ?";
        $app_params[] = $proposal_pref_start;
    }
    $app_sql .= " ORDER BY preferred_start_date IS NULL, preferred_start_date ASC, a.application_date DESC, a.application_id DESC LIMIT 300";
    $approved_apps = $db->fetchAll($app_sql, $app_params) ?: [];
} catch (Throwable $e) { $approved_apps = []; }

/* Leases list with balance + sort filter */
$leases = [];
try {
    $sql = "SELECT l.*, s.stall_number, s.stall_size, m.market_name, m.location,
                   u.full_name as vendor_name, u.email, u.contact_number,
                   DATEDIFF(l.lease_end_date, CURDATE()) as days_remaining,
                   (SELECT COUNT(*) FROM payments WHERE lease_id = l.lease_id AND LOWER(TRIM(status)) IN ('pending','overdue','partial')) as pending_payments,
                   COALESCE((
                       SELECT SUM((p.amount - COALESCE(p.amount_paid,0)))
                       FROM payments p
                       WHERE p.lease_id = l.lease_id
                         AND LOWER(TRIM(p.status)) IN ('pending','partial','overdue')
                   ), 0) AS balance_amount
            FROM leases l
            JOIN stalls s ON l.stall_id = s.stall_id
            JOIN markets m ON s.market_id = m.market_id
            JOIN users u ON l.vendor_id = u.user_id
            WHERE 1=1";
    $params = [];
    if ($status_filter !== 'all') { $sql .= " AND l.status = ?"; $params[] = $status_filter; }
    if ($expiring_filter === 'yes') { $sql .= " AND l.status = 'active' AND DATEDIFF(l.lease_end_date, CURDATE()) BETWEEN 1 AND 30"; }
    if (!empty($search)) {
        $sql .= " AND (l.business_name LIKE ? OR u.full_name LIKE ? OR s.stall_number LIKE ?)";
        $like = "%{$search}%";
        $params[] = $like; $params[] = $like; $params[] = $like;
    }
    if ($isMarketManager) {
        $managedIds = getManagedMarketIds($db, $uid);
        if (!empty($managedIds)) {
            $ph = implode(',', array_fill(0, count($managedIds), '?'));
            $sql .= " AND m.market_id IN ($ph)";
            $params = array_merge($params, $managedIds);
        } else {
            $leases = [];
        }
    }
    // Balance filter using HAVING (computed column)
    if ($balance_filter === 'paid') {
        $sql .= " HAVING balance_amount <= 0";
    } elseif ($balance_filter === 'unpaid') {
        $sql .= " HAVING balance_amount > 0";
    }
    // Sort mapping
    $orderSql = " ORDER BY ";
    switch ($sort) {
        case 'start_asc':     $orderSql .= " l.lease_start_date ASC"; break;
        case 'start_desc':    $orderSql .= " l.lease_start_date DESC"; break;
        case 'end_asc':       $orderSql .= " l.lease_end_date ASC"; break;
        case 'end_desc':      $orderSql .= " l.lease_end_date DESC"; break;
        case 'rent_asc':      $orderSql .= " l.monthly_rent ASC"; break;
        case 'rent_desc':     $orderSql .= " l.monthly_rent DESC"; break;
        case 'balance_asc':   $orderSql .= " balance_amount ASC"; break;
        case 'balance_desc':  $orderSql .= " balance_amount DESC"; break;
        case 'vendor_asc':    $orderSql .= " u.full_name ASC"; break;
        case 'vendor_desc':   $orderSql .= " u.full_name DESC"; break;
        default:              $orderSql .= " l.lease_start_date DESC"; break;
    }
    $sql .= $orderSql;

    if ($leases === []) {
        $leases = $db->fetchAll($sql, $params) ?: [];
    }
} catch (Throwable $e) { error_log($e->getMessage()); $leases = []; }

include 'includes/header.php';
include 'includes/admin_sidebar.php';
?>

<section class="max-w-7xl mx-auto p-6">

<div class="mb-6 flex justify-between items-center">
    <div>
        <p class="text-gray-600">View and manage all lease agreements</p>
        <p class="text-xs text-gray-500">Auto-renew runs on page load: active leases without unpaid invoices and with prior payments are extended by one month and invoiced.</p>
    </div>
    <!-- Renew button removed -->
</div>

<?php if (!empty($_SESSION['flash_success'])): ?>
    <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-6" role="alert">
        <?php echo htmlspecialchars($_SESSION['flash_success']); unset($_SESSION['flash_success']); ?>
    </div>
<?php endif; ?>
<?php if ($error): ?>
    <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-6" role="alert">
        <?php echo htmlspecialchars($error); ?>
    </div>
<?php endif; ?>
<?php if ($success): ?>
    <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-6" role="alert">
        <?php echo htmlspecialchars($success); ?>
    </div>
<?php endif; ?>

<!-- Tabs -->
<div class="mb-6">
  <div role="tablist" aria-label="Manage leases tabs" class="flex gap-3 items-center">
    <?php
      $preserve = $_GET; unset($preserve['tab']);
      $preserveQs = !empty($preserve) ? '&' . http_build_query($preserve) : '';
      $activeClass = 'px-5 py-2 rounded-md font-medium bg-blue-600 text-white shadow';
      $inactiveClass = 'px-5 py-2 rounded-md font-medium bg-gray-100 text-gray-800 hover:bg-gray-200';
    ?>
    <a href="manage_leases.php?tab=leases<?php echo $preserveQs; ?>"
       role="tab"
       aria-selected="<?php echo $active_tab === 'leases' ? 'true' : 'false'; ?>"
       class="<?php echo ($active_tab === 'leases') ? $activeClass : $inactiveClass; ?>">
       Leases
    </a>

    <a href="manage_leases.php?tab=applications<?php echo $preserveQs; ?>"
       role="tab"
       aria-selected="<?php echo $active_tab === 'applications' ? 'true' : 'false'; ?>"
       class="<?php echo ($active_tab === 'applications') ? $activeClass : $inactiveClass; ?>">
       Vendor Proposals
    </a>
  </div>
</div>

<!-- Applications tab -->
<div id="tab-applications" class="mb-6 <?php echo $active_tab === 'applications' ? '' : 'hidden'; ?>">
    <div class="bg-white rounded-lg shadow-md p-6 mb-6">
        <div class="flex items-center justify-between mb-4">
            <h4 class="text-lg font-semibold text-gray-800">Vendor Proposals (Pending Applications)</h4>
            <form method="GET" class="flex items-center gap-2">
                <input type="hidden" name="status" value="<?php echo htmlspecialchars($status_filter); ?>">
                <input type="hidden" name="expiring" value="<?php echo htmlspecialchars($expiring_filter); ?>">
                <input type="hidden" name="search" value="<?php echo htmlspecialchars($search); ?>">
                <input type="hidden" name="tab" value="applications">
                <select name="proposal_market_id" class="px-3 py-2 border rounded-md" onchange="this.form.submit()">
                    <option value="0">All Markets</option>
                    <?php
                      $markets = $db->fetchAll("SELECT market_id, market_name FROM markets ORDER BY market_name") ?: [];
                      foreach ($markets as $mk):
                    ?>
                      <option value="<?php echo (int)$mk['market_id']; ?>" <?php echo ($proposal_market_id??0)===(int)$mk['market_id']?'selected':''; ?>>
                        <?php echo htmlspecialchars($mk['market_name']); ?>
                      </option>
                    <?php endforeach; ?>
                </select>
                <select name="proposal_stall_id" class="px-3 py-2 border rounded-md" <?php echo $proposal_market_id>0?'':'disabled'; ?> onchange="this.form.submit()">
                    <option value="0"><?php echo $proposal_market_id>0 ? 'All Stalls (with pending proposals)' : 'Select market first'; ?></option>
                </select>
                <input type="date" name="proposal_pref_start" value="<?php echo htmlspecialchars($proposal_pref_start); ?>" class="px-3 py-2 border rounded-md" />
                <input type="text" name="proposal_search" value="<?php echo htmlspecialchars($proposal_search); ?>" placeholder="Search proposals..." class="px-3 py-2 border rounded-md" />
                <button type="submit" class="px-3 py-2 bg-blue-600 text-white rounded-md">Filter</button>
            </form>
        </div>

        <?php if (!empty($approved_apps)): ?>
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="text-left py-3 px-4 text-sm font-semibold text-gray-700">Vendor</th>
                            <th class="text-left py-3 px-4 text-sm font-semibold text-gray-700">Business</th>
                            <th class="text-left py-3 px-4 text-sm font-semibold text-gray-700">Stall</th>
                            <th class="text-left py-3 px-4 text-sm font-semibold text-gray-700">Preferred Start</th>
                            <th class="text-left py-3 px-4 text-sm font-semibold text-gray-700">Application Status</th>
                            <th class="text-left py-3 px-4 text-sm font-semibold text-gray-700">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200">
                        <?php foreach ($approved_apps as $app): ?>
                            <?php $appJson = json_encode($app, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT); ?>
                            <tr class="hover:bg-gray-50">
                                <td class="py-3 px-4"><div class="font-semibold"><?php echo htmlspecialchars($app['vendor_name']); ?></div></td>
                                <td class="py-3 px-4">
                                    <div class="font-semibold"><?php echo htmlspecialchars($app['business_name']); ?></div>
                                    <div class="text-xs text-gray-500"><?php echo htmlspecialchars($app['business_type']); ?></div>
                                </td>
                                <td class="py-3 px-4">
                                    <div><?php echo htmlspecialchars($app['stall_number']); ?></div>
                                    <div class="text-xs text-gray-500"><?php echo htmlspecialchars($app['market_name']); ?></div>
                                </td>
                                <td class="py-3 px-4">
                                    <?php $pref = $app['preferred_start_date'] ?? null;
                                    echo !empty($pref) ? htmlspecialchars(formatDate($pref)) : '-'; ?>
                                </td>
                                <td class="py-3 px-4"><?php echo htmlspecialchars($app['app_status'] ?? ''); ?></td>
                                <td class="py-3 px-4">
                                    <div class="flex gap-2 flex-wrap">
                                        <button type="button" onclick='openCreateLeaseModal(<?php echo $appJson; ?>)' class="px-3 py-1 bg-green-600 text-white rounded text-sm">Create Lease</button>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php else: ?>
            <div class="text-center py-8 text-gray-600">No pending applications found for the selected filters.</div>
        <?php endif; ?>
    </div>
</div>

<!-- Leases tab -->
<div id="tab-leases" class="mb-6 <?php echo $active_tab === 'leases' ? '' : 'hidden'; ?>">
    <div class="bg-white rounded-lg shadow-md p-6 mb-6">
        <form method="GET" action="" class="grid grid-cols-1 md:grid-cols-6 gap-4">
            <input type="hidden" name="tab" value="leases">
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">Status</label>
                <select name="status" class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    <option value="all">All Status</option>
                    <option value="active" <?php echo $status_filter === 'active' ? 'selected' : ''; ?>>Active</option>
                    <option value="expired" <?php echo $status_filter === 'expired' ? 'selected' : ''; ?>>Expired</option>
                    <option value="terminated" <?php echo $status_filter === 'terminated' ? 'selected' : ''; ?>>Terminated</option>
                    <option value="pending" <?php echo $status_filter === 'pending' ? 'selected' : ''; ?>>Pending</option>
                </select>
            </div>

            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">Expiring Filter</label>
                <select name="expiring" class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    <option value="">All Leases</option>
                    <option value="yes" <?php echo $expiring_filter === 'yes' ? 'selected' : ''; ?>>Expiring Soon (30 days)</option>
                </select>
            </div>

            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">Balance</label>
                <select name="balance" class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    <option value="" <?php echo $balance_filter === '' ? 'selected' : ''; ?>>All</option>
                    <option value="paid" <?php echo $balance_filter === 'paid' ? 'selected' : ''; ?>>Paid (₱0.00)</option>
                    <option value="unpaid" <?php echo $balance_filter === 'unpaid' ? 'selected' : ''; ?>>Unpaid (>₱0.00)</option>
                </select>
            </div>

            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">Sort</label>
                <select name="sort" class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    <option value="start_desc"  <?php echo $sort==='start_desc'?'selected':''; ?>>Start Date (Newest)</option>
                    <option value="start_asc"   <?php echo $sort==='start_asc'?'selected':''; ?>>Start Date (Oldest)</option>
                    <option value="end_desc"    <?php echo $sort==='end_desc'?'selected':''; ?>>End Date (Latest)</option>
                    <option value="end_asc"     <?php echo $sort==='end_asc'?'selected':''; ?>>End Date (Earliest)</option>
                    <option value="rent_desc"   <?php echo $sort==='rent_desc'?'selected':''; ?>>Monthly Rent (High → Low)</option>
                    <option value="rent_asc"    <?php echo $sort==='rent_asc'?'selected':''; ?>>Monthly Rent (Low → High)</option>
                    <option value="balance_desc"<?php echo $sort==='balance_desc'?'selected':''; ?>>Balance (High → Low)</option>
                    <option value="balance_asc" <?php echo $sort==='balance_asc'?'selected':''; ?>>Balance (Low → High)</option>
                    <option value="vendor_asc"  <?php echo $sort==='vendor_asc'?'selected':''; ?>>Vendor (A → Z)</option>
                    <option value="vendor_desc" <?php echo $sort==='vendor_desc'?'selected':''; ?>>Vendor (Z → A)</option>
                </select>
            </div>

            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">Search</label>
                <input type="text" name="search" value="<?php echo htmlspecialchars($search); ?>" placeholder="Search..." class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
            </div>

            <div class="flex items-end gap-2">
                <button type="submit" class="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition">Filter</button>
                <a href="manage_leases.php?tab=leases" class="px-6 py-2 bg-gray-300 text-gray-700 rounded-lg hover:bg-gray-400 transition">Reset</a>
            </div>
        </form>
    </div>

    <div class="bg-white rounded-lg shadow-md overflow-hidden">
        <?php if ($leases && count($leases) > 0): ?>
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="text-left py-4 px-6 text-sm font-semibold text-gray-700">Vendor</th>
                            <th class="text-left py-4 px-6 text-sm font-semibold text-gray-700">Business</th>
                            <th class="text-left py-4 px-6 text-sm font-semibold text-gray-700">Stall</th>
                            <th class="text-left py-4 px-6 text-sm font-semibold text-gray-700">Lease Period</th>
                            <th class="text-left py-4 px-6 text-sm font-semibold text-gray-700">Monthly Rent</th>
                            <th class="text-left py-4 px-6 text-sm font-semibold text-gray-700">Balance</th>
                            <th class="text-left py-4 px-6 text-sm font-semibold text-gray-700">Status</th>
                            <th class="text-left py-4 px-6 text-sm font-semibold text-gray-700">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200">
                        <?php foreach ($leases as $lease): ?>
                            <tr class="hover:bg-gray-50">
                                <td class="py-4 px-6">
                                    <p class="font-semibold text-gray-800"><?php echo htmlspecialchars($lease['vendor_name']); ?></p>
                                    <p class="text-xs text-gray-600"><?php echo htmlspecialchars($lease['email']); ?></p>
                                    <p class="text-xs text-gray-600"><?php echo htmlspecialchars($lease['contact_number']); ?></p>
                                </td>
                                <td class="py-4 px-6">
                                    <p class="font-semibold text-gray-800"><?php echo htmlspecialchars($lease['business_name']); ?></p>
                                    <p class="text-sm text-gray-600"><?php echo htmlspecialchars($lease['business_type']); ?></p>
                                </td>
                                <td class="py-4 px-6">
                                    <p class="font-medium text_gray_800"><?php echo htmlspecialchars($lease['stall_number']); ?></p>
                                    <p class="text-sm text-gray-600"><?php echo htmlspecialchars($lease['market_name']); ?></p>
                                </td>
                                <td class="py-4 px-6">
                                    <p class="text-sm text-gray-800"><?php echo formatDate($lease['lease_start_date']); ?></p>
                                    <p class="text-sm text-gray-800">to <?php echo formatDate($lease['lease_end_date']); ?></p>
                                    <?php if (strtolower($lease['status']) === 'active'): ?>
                                        <?php if ((int)$lease['days_remaining'] < 0): ?>
                                            <span class="text-xs text-red-600 font-semibold">⚠️ Expired</span>
                                        <?php elseif ((int)$lease['days_remaining'] <= 30): ?>
                                            <span class="text-xs text-orange-600 font-semibold">⏰ <?php echo (int)$lease['days_remaining']; ?> day<?php echo (int)$lease['days_remaining']===1?'':'s'; ?> left</span>
                                        <?php endif; ?>
                                    <?php endif; ?>
                                </td>
                                <td class="py-4 px-6">
                                    <p class="font-semibold text-gray-800">
                                        <?php
                                          $rentShow = ($lease['monthly_rent'] !== null && $lease['monthly_rent'] !== '') ? (float)$lease['monthly_rent'] : 0.0;
                                          echo formatCurrency($rentShow);
                                        ?>
                                    </p>
                                </td>
                                <td class="py-4 px-6">
                                    <?php $bal = (float)($lease['balance_amount'] ?? 0); ?>
                                    <p class="font-semibold <?php echo $bal > 0 ? 'text-red-600' : 'text-green-600'; ?>">
                                        <?php echo formatCurrency($bal); ?>
                                    </p>
                                </td>
                                <td class="py-4 px-6">
                                    <?php echo getStatusBadge($lease['status']); ?>
                                </td>
                                <td class="py-4 px-6">
                                    <div class="flex flex-wrap gap-2">
                                        <?php if (strtolower($lease['status']) === 'active'): ?>
                                            <!-- Renew button removed to avoid manual renew -->
                                            <?php if ((int)$lease['pending_payments'] > 0): ?>
                                                <button class="bg-gray-300 text-gray-700 px-3 py-1 rounded text-sm cursor-not-allowed" title="Settle open invoices before termination">Terminate</button>
                                            <?php else: ?>
                                                <button onclick="confirmTerminate(<?php echo (int)$lease['lease_id']; ?>, '<?php echo htmlspecialchars($lease['business_name']); ?>', <?php echo (int)$lease['pending_payments']; ?>)" class="bg-red-600 text-white px-3 py-1 rounded hover:bg-red-700 text-sm">Terminate</button>
                                            <?php endif; ?>
                                        <?php else: ?>
                                            <span class="text-gray-500 text-sm">No action</span>
                                        <?php endif; ?>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php else: ?>
            <div class="text-center py-16">
                <h3 class="text-xl font-semibold text-gray-700 mb-2">No leases found</h3>
                <p class="text-gray-500">Leases will appear here when created from pending applications.</p>
            </div>
        <?php endif; ?>
    </div>
</div>

<!-- Create Lease Modal -->
<div id="createLeaseModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
    <div class="bg-white rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div class="p-6">
            <h3 class="text-2xl font-bold text-gray-800 mb-4">Create Lease Agreement</h3>
            <form method="POST" action="">
                <?php echo csrf_field(); ?>
                <input type="hidden" name="application_id" id="create_app_id">

                <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-4">
                    <p class="text-sm"><strong>Vendor:</strong> <span id="create_vendor_name"></span></p>
                    <p class="text-sm"><strong>Business:</strong> <span id="create_business_name"></span></p>
                    <p class="text-sm"><strong>Stall:</strong> <span id="create_stall_info"></span></p>
                </div>

                <div class="grid grid-cols-2 gap-4 mb-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Start Date *</label>
                        <input type="date" name="lease_start_date" id="create_lease_start_date" required class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500" value="<?php echo date('Y-m-d'); ?>">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">End Date</label>
                        <input type="date" name="lease_end_date" id="create_lease_end_date" class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                        <p class="text-xs text-gray-500 mt-1">Leave blank to default to 1 month from start</p>
                    </div>
                </div>

                <div class="grid grid-cols-2 gap-4 mb-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Monthly Rent *</label>
                        <input type="number" name="monthly_rent" id="create_monthly_rent" step="0.01" required class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    </div>
                </div>

                <div class="flex gap-4">
                    <button type="submit" name="create_lease" id="create_lease_submit" class="flex-1 bg-green-600 text-white py-3 rounded-lg hover:bg-green-700 transition font-medium">Create Lease</button>
                    <button type="button" onclick="closeCreateLeaseModal()" class="flex-1 bg-gray-300 text-gray-700 py-3 rounded-lg hover:bg-gray-400 transition font-medium">Cancel</button>
                </div>
            </form>
        </div>
    </div>
</div>

</section>

<script>
function openCreateLeaseModal(app) {
    try { if (typeof app === 'string') app = JSON.parse(app); } catch(e) { app = app || {}; }
    const appId = app.application_id ?? '';
    const vendorName = app.vendor_name ?? '';
    const businessName = app.business_name ?? '';
    const stallInfo = (app.stall_number || '') + (app.market_name ? (' (' + app.market_name + ')') : '');
    const createAppIdEl = document.getElementById('create_app_id'); if (createAppIdEl) createAppIdEl.value = appId;
    const vendorEl = document.getElementById('create_vendor_name'); if (vendorEl) vendorEl.textContent = vendorName;
    const businessEl = document.getElementById('create_business_name'); if (businessEl) businessEl.textContent = businessName;
    const stallEl = document.getElementById('create_stall_info'); if (stallEl) stallEl.textContent = stallInfo;
    const startEl = document.getElementById('create_lease_start_date');
    if (startEl) startEl.value = app.preferred_start_date || new Date().toISOString().split('T')[0];
    const rentEl = document.getElementById('create_monthly_rent');
    if (rentEl) rentEl.value = (app.default_rent ?? '');
    const endEl = document.getElementById('create_lease_end_date');
    if (endEl) {
        const baseDate = (startEl.value && startEl.value !== '') ? new Date(startEl.value) : new Date();
        const defaultEnd = new Date(baseDate); defaultEnd.setMonth(defaultEnd.getMonth() + 1);
        endEl.value = defaultEnd.toISOString().split('T')[0];
        const minDate = new Date(baseDate); minDate.setDate(minDate.getDate() + 1);
        endEl.min = minDate.toISOString().split('T')[0];
    }
    const modal = document.getElementById('createLeaseModal'); if (modal) modal.classList.remove('hidden');
}
function closeCreateLeaseModal() {
    const modal = document.getElementById('createLeaseModal'); if (modal) modal.classList.add('hidden');
}

function confirmTerminate(leaseId, businessName, pendingPayments) {
    if (pendingPayments > 0) { alert('Cannot terminate lease: ' + pendingPayments + ' pending/overdue payment(s) must be settled first.'); return; }
    if (confirm('Terminate lease for "' + businessName + '"?\n\nThis will:\n- Mark the lease as terminated\n- Make the stall available again\n- Notify the vendor\n\nThis action cannot be undone.')) {
        window.location.href = '?terminate=' + leaseId + '&tab=leases';
    }
}

/* Escape to close modals */
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeCreateLeaseModal();
    }
});
['createLeaseModal'].forEach(modalId => {
    const el = document.getElementById(modalId); if (!el) return;
    el.addEventListener('click', function(e) {
        if (e.target === this) {
            if (modalId==='createLeaseModal') closeCreateLeaseModal();
        }
    });
});
</script>

<?php include 'includes/footer.php'; ?>