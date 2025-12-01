<?php
require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/csrf.php';
require_once 'includes/notifications.php';
require_once 'includes/inspector_utils.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

$page_title = 'Manage Leases';
$error = '';
$success = '';

$active_tab = isset($_GET['tab']) ? strtolower(trim($_GET['tab'])) : 'leases';
if (!in_array($active_tab, ['leases','applications'], true)) $active_tab = 'leases';

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
        if (!$date) return '-';
        $fmt = $withTime ? 'M j, Y g:i A' : 'M j, Y';
        $ts = strtotime($date);
        return $ts ? date($fmt, $ts) : '-';
    }
}
if (!function_exists('getStatusBadge')) {
    function getStatusBadge($status){
        $status=strtolower($status);
        $map=['active'=>'bg-green-100 text-green-700','expired'=>'bg-yellow-100 text-yellow-700','terminated'=>'bg-red-100 text-red-700','pending'=>'bg-amber-100 text-amber-700'];
        $cls=$map[$status]??'bg-gray-100 text-gray-700';
        return "<span class='px-2 py-1 rounded text-xs font-semibold {$cls}'>".htmlspecialchars(ucwords(str_replace('_',' ',$status)))."</span>";
    }
}

$uid = $_SESSION['user_id'] ?? null;
$isMarketManager = false;
try { if ($uid && function_exists('userIsInRole') && userIsInRole($db, $uid, 'market_manager')) $isMarketManager = true; } catch (Throwable $e) { error_log($e->getMessage()); }

// ---------------- Actions: Terminate, Create Lease, Bulk Renew ----------------

// Terminate lease
if (isset($_GET['terminate']) && !empty($_GET['terminate'])) {
    $lease_id = (int)$_GET['terminate'];
    if ($lease_id <= 0) {
        $error = 'Invalid lease selected.';
    } else {
        ensure_can_manage_lease($db, $lease_id, null, null);
        $lease = $db->fetch("SELECT l.*, s.stall_id, s.market_id, s.stall_number, l.vendor_id, (SELECT COUNT(*) FROM payments p WHERE p.lease_id = l.lease_id AND p.status IN ('pending','overdue','partial')) AS pending_payments FROM leases l JOIN stalls s ON l.stall_id = s.stall_id WHERE l.lease_id = ? LIMIT 1", [$lease_id]);
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

// Create lease (converted from application)
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
            $app = $db->fetch("SELECT a.*, s.stall_id, s.stall_number, s.market_id, s.monthly_rent AS stall_default_rent, u.user_id as vendor_id FROM applications a JOIN stalls s ON a.stall_id = s.stall_id JOIN users u ON a.vendor_id = u.user_id WHERE a.application_id = ? LIMIT 1", [$application_id]);
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

// Bulk renew all eligible (manual button)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['renew_all_eligible'])) {
    if (!csrf_validate_request()) {
        $error = 'Invalid CSRF token.';
    } else {
        try {
            $managedIds = getManagedMarketIds($db, $uid);
            $renewed = 0; $skipped = 0;

            $selSql = "SELECT l.lease_id, l.vendor_id
                       FROM leases l
                       JOIN stalls s ON l.stall_id = s.stall_id
                       WHERE l.status='active'
                         AND (l.lease_end_date IS NULL OR l.lease_end_date <= DATE_ADD(CURDATE(), INTERVAL 7 DAY))
                         AND (SELECT COUNT(*) FROM payments p WHERE p.lease_id = l.lease_id AND p.status IN ('pending','overdue','partial')) = 0";
            $params = [];
            if ($isMarketManager && !empty($managedIds)) {
                $ph = implode(',', array_fill(0, count($managedIds), '?'));
                $selSql .= " AND s.market_id IN ($ph)";
                $params = array_merge($params, $managedIds);
            }

            $candidates = $db->fetchAll($selSql." LIMIT 200", $params) ?: [];
            foreach ($candidates as $cand) {
                $lid = (int)$cand['lease_id'];
                try {
                    $ok = $db->query("UPDATE leases SET lease_end_date = DATE_ADD(lease_end_date, INTERVAL 1 MONTH), updated_at = NOW() WHERE lease_id = ? AND status='active'", [$lid]);
                    if ($ok) {
                        $renewed++;
                        if (function_exists('createNotification')) {
                            try {
                                $row = $db->fetch("SELECT vendor_id, lease_end_date FROM leases WHERE lease_id=? LIMIT 1", [$lid]);
                                $newEnd = $row['lease_end_date'] ?? '';
                                createNotification($db, (int)$row['vendor_id'], 'Lease Renewed', "Your lease has been renewed by the market manager. New end date: {$newEnd}.", 'success', 'lease', $lid, 'leases');
                            } catch (Throwable $e) {}
                        }
                        logAudit($db, $uid, 'Lease Bulk Renewed', 'leases', $lid, null, null);
                    } else { $skipped++; }
                } catch (Throwable $e) { $skipped++; }
            }
            $success = "Bulk renew complete: {$renewed} renewed, {$skipped} skipped.";
        } catch (Throwable $e) {
            error_log("bulk renew failed: ".$e->getMessage());
            $error = 'Bulk renew failed.';
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
    'start_desc',    // lease_start_date DESC
    'start_asc',     // lease_start_date ASC
    'end_desc',      // lease_end_date DESC
    'end_asc',       // lease_end_date ASC
    'rent_desc',     // monthly_rent DESC
    'rent_asc',      // monthly_rent ASC
    'balance_desc',  // balance_amount DESC
    'balance_asc',   // balance_amount ASC
    'vendor_asc',    // vendor_name ASC
    'vendor_desc'    // vendor_name DESC
];
if (!in_array($sort, $allowedSorts, true)) {
    // Map dir+default to start date if provided
    if ($dir === 'asc') $sort = 'start_asc';
    elseif ($dir === 'desc') $sort = 'start_desc';
    else $sort = 'start_desc';
}

/* Applications list (unchanged) */
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
                   (SELECT COUNT(*) FROM payments WHERE lease_id = l.lease_id AND status IN ('pending','overdue','partial')) as pending_payments,
                   COALESCE((SELECT SUM(amount - amount_paid) FROM payments WHERE lease_id = l.lease_id AND status IN ('pending','partial','overdue')), 0) AS balance_amount
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
    </div>
    <div class="flex items-center gap-2">
        <form method="POST" onsubmit="return confirm('Renew all eligible active leases (no pending/overdue payments) by +1 month?');">
            <?php echo csrf_field(); ?>
            <button type="submit" name="renew_all_eligible" class="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700">
                Renew all eligible
            </button>
        </form>
    </div>
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

<!-- Applications tab (unchanged UI) -->
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
                    <?php foreach ($markets as $mk): ?>
                        <option value="<?php echo (int)$mk['market_id']; ?>" <?php echo $proposal_market_id===(int)$mk['market_id']?'selected':''; ?>>
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
                                    <?php if ($lease['status'] === 'active'): ?>
                                        <?php if ((int)$lease['days_remaining'] < 0): ?>
                                            <span class="text-xs text-red-600 font-semibold">⚠️ Expired</span>
                                        <?php elseif ((int)$lease['days_remaining'] <= 30): ?>
                                            <span class="text-xs text-orange-600 font-semibold">⏰ <?php echo (int)$lease['days_remaining']; ?> days left</span>
                                        <?php endif; ?>
                                    <?php endif; ?>
                                </td>
                                <td class="py-4 px-6">
                                    <p class="font-semibold text-gray-800"><?php echo formatCurrency($lease['monthly_rent']); ?></p>
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
                                        <?php if ($lease['status'] === 'active'): ?>
                                            <button onclick='openRenewModal(<?php echo json_encode($lease, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT); ?>)' class="bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700 text-sm">Renew</button>
                                            <button onclick='openModifyModal(<?php echo json_encode($lease, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT); ?>)' class="bg-purple-600 text-white px-3 py-1 rounded hover:bg-purple-700 text-sm">Modify</button>
                                            <?php if (!($isMarketManager && (int)$lease['pending_payments'] === 0)): ?>
                                                <button onclick="confirmTerminate(<?php echo (int)$lease['lease_id']; ?>, '<?php echo htmlspecialchars($lease['business_name']); ?>', <?php echo (int)$lease['pending_payments']; ?>)" class="bg-red-600 text-white px-3 py-1 rounded hover:bg-red-700 text-sm">Terminate</button>
                                            <?php else: ?>
                                                <span class="text-xs text-gray-500 px-2 py-1 rounded border border-gray-300">Termination disabled (paid)</span>
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
                <p class="text-gray-500">Leases will appear here when created from pending applications</p>
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

<!-- Renew Lease Modal (fixed to monthly; read-only date) -->
<div id="renewModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
  <div class="bg-white rounded-lg max-w-lg w-full overflow-y-auto">
    <div class="p-6">
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-2xl font-bold text-gray-800">Renew Lease</h3>
        <button type="button" onclick="closeRenewModal()" class="text-gray-500 hover:text-gray-700">✕</button>
      </div>

      <form method="POST" action="">
        <?php echo csrf_field(); ?>
        <input type="hidden" name="renew_lease_id" id="renew_lease_id">

        <div class="mb-4"><p class="text-sm text-gray-600">Business</p><div id="renew_business_name" class="font-medium text-gray-800"></div></div>
        <div class="mb-4"><p class="text-sm text-gray-600">Current End Date</p><div id="renew_current_end" class="font-medium text-gray-800"></div></div>
        <div class="mb-4"><p class="text-sm text-gray-600">Current Monthly Rent</p><div id="renew_monthly_rent" class="font-medium text-gray-800"></div></div>

        <div class="mb-2">
          <label class="block text-sm text-gray-700 mb-1">New End Date (fixed to +1 month)</label>
          <input type="date" name="renew_new_end_date" id="renew_new_end_date" readonly aria-readonly="true" class="w-full px-4 py-2 border rounded bg-gray-100 opacity-80 cursor-not-allowed" />
        </div>
        <p class="text-xs text-gray-500 mb-4">Renewals are monthly and the date above is pre-set to one month after the current end date. Review and confirm to proceed.</p>

        <div class="flex gap-3">
          <button type="submit" name="renew_lease" class="bg-blue-600 text-white px-4 py-2 rounded">Confirm Renewal</button>
          <button type="button" onclick="closeRenewModal()" class="bg-gray-300 text-gray-700 px-4 py-2 rounded">Cancel</button>
        </div>
      </form>
    </div>
  </div>
</div>

<!-- Modify Lease Modal (note about when rent takes effect) -->
<div id="modifyModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
  <div class="bg-white rounded-lg max-w-lg w-full overflow-y-auto">
    <div class="p-6">
      <div class="flex items-center justify_between mb-4">
        <h3 class="text-2xl font-bold text-gray-800">Modify Lease</h3>
        <button type="button" onclick="closeModifyModal()" class="text-gray-500 hover:text-gray-700">✕</button>
      </div>

      <form method="POST" action="">
        <?php echo csrf_field(); ?>
        <input type="hidden" name="modify_lease_id" id="modify_lease_id">

        <div class="mb-4"><p class="text-sm text-gray-600">Business</p><div id="modify_business_name" class="font-medium text-gray-800"></div></div>
        <div class="mb-4"><p class="text-sm text-gray-600">Vendor</p><div id="modify_vendor_name" class="font-medium text-gray-800"></div></div>
        <div class="mb-4"><p class="text-sm text-gray-600">Current Monthly Rent</p><div id="modify_current_rent" class="font-medium text-gray-800"></div></div>

        <div class="mb-1">
          <label class="block text-sm text-gray-700 mb-2">New Monthly Rent *</label>
          <input type="number" name="modify_new_rent" id="modify_new_rent" step="0.01" required class="w-full px-4 py-2 border rounded" />
        </div>
        <p class="text-xs text-gray-500 mb-4">The new monthly rent will take effect at the end of the current lease term and be applied upon renewal.</p>

        <div class="flex gap-3">
          <button type="submit" name="modify_lease" class="bg-purple-600 text-white px-4 py-2 rounded">Save Changes</button>
          <button type="button" onclick="closeModifyModal()" class="bg-gray-300 text-gray-700 px-4 py-2 rounded">Cancel</button>
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
    ['create_lease_start_date','create_lease_end_date','create_monthly_rent'].forEach(id=>{
        const el=document.getElementById(id); if(!el) return;
        el.removeAttribute('readonly'); el.removeAttribute('aria-readonly'); el.classList.remove('bg-gray-100','opacity-80');
    });
}

function openRenewModal(lease) {
    try { if (typeof lease === 'string') lease = JSON.parse(lease); } catch(e) { lease = lease || {}; }
    const idEl = document.getElementById('renew_lease_id');
    const businessEl = document.getElementById('renew_business_name');
    const currentEndEl = document.getElementById('renew_current_end');
    const monthlyRentEl = document.getElementById('renew_monthly_rent');
    const newEndEl = document.getElementById('renew_new_end_date');
    const modal = document.getElementById('renewModal');
    if (!modal) return;
    if (idEl && lease.lease_id !== undefined) idEl.value = lease.lease_id;
    if (businessEl) businessEl.textContent = lease.business_name ?? '';
    if (currentEndEl) currentEndEl.textContent = lease.lease_end_date ?? '';
    if (monthlyRentEl) {
        try { monthlyRentEl.textContent = '₱' + parseFloat(lease.monthly_rent).toLocaleString('en-PH', {minimumFractionDigits: 2}); }
        catch (e) { monthlyRentEl.textContent = lease.monthly_rent ?? ''; }
    }
    if (newEndEl) {
        let base = lease.lease_end_date ? new Date(lease.lease_end_date) : new Date();
        const defaultEnd = new Date(base); defaultEnd.setMonth(defaultEnd.getMonth()+1);
        newEndEl.value = defaultEnd.toISOString().split('T')[0];
        newEndEl.readOnly = true;
        newEndEl.setAttribute('aria-readonly','true');
        newEndEl.classList.add('bg-gray-100','opacity-80','cursor-not-allowed');
    }
    modal.classList.remove('hidden');
}
function closeRenewModal(){ const el=document.getElementById('renewModal'); if(el) el.classList.add('hidden'); const ne=document.getElementById('renew_new_end_date'); if(ne) ne.value=''; const id=document.getElementById('renew_lease_id'); if(id) id.value=''; }

function openModifyModal(lease) {
    try { if (typeof lease === 'string') lease = JSON.parse(lease); } catch(e) { lease = lease || {}; }
    const idEl = document.getElementById('modify_lease_id');
    const businessEl = document.getElementById('modify_business_name');
    const vendorEl = document.getElementById('modify_vendor_name');
    const currentRentEl = document.getElementById('modify_current_rent');
    const newRentEl = document.getElementById('modify_new_rent');
    const modal = document.getElementById('modifyModal');
    if (!modal) return;
    if (idEl && lease.lease_id !== undefined) idEl.value = lease.lease_id;
    if (businessEl) businessEl.textContent = lease.business_name ?? '';
    if (vendorEl) vendorEl.textContent = lease.vendor_name ?? '';
    if (currentRentEl) {
        try { currentRentEl.textContent = '₱' + parseFloat(lease.monthly_rent).toLocaleString('en-PH', {minimumFractionDigits: 2}); }
        catch (e) { currentRentEl.textContent = lease.monthly_rent ?? ''; }
    }
    if (newRentEl) newRentEl.value = lease.monthly_rent ?? '';
    modal.classList.remove('hidden');
}
function closeModifyModal(){ const el=document.getElementById('modifyModal'); if(el) el.classList.add('hidden'); const id=document.getElementById('modify_lease_id'); if(id) id.value=''; const nr=document.getElementById('modify_new_rent'); if(nr) nr.value=''; }

function confirmTerminate(leaseId, businessName, pendingPayments) {
    if (pendingPayments > 0) { alert('Cannot terminate lease: ' + pendingPayments + ' pending/overdue payment(s) must be settled first.'); return; }
    if (confirm('Terminate lease for "' + businessName + '"?\n\nThis will:\n- Mark the lease as terminated\n- Make the stall available again\n- Notify the vendor\n\nThis action cannot be undone.')) {
        window.location.href = '?terminate=' + leaseId + '&tab=leases';
    }
}

document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeCreateLeaseModal(); closeRenewModal(); closeModifyModal();
    }
});
['createLeaseModal','renewModal','modifyModal'].forEach(modalId => {
    const el = document.getElementById(modalId); if (!el) return;
    el.addEventListener('click', function(e) {
        if (e.target === this) {
            if (modalId==='createLeaseModal') closeCreateLeaseModal();
            if (modalId==='renewModal') closeRenewModal();
            if (modalId==='modifyModal') closeModifyModal();
        }
    });
});
</script>

<?php include 'includes/footer.php'; ?>