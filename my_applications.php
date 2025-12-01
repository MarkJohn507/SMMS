<?php
/**
 * my_applications.php (Vendor view – tabs by status)
 * - Vendors see only their applications.
 * - Status tabs: Pending | Cancelled/Rejected | Completed
 * - Filters: Market, Search (business/type/stall/market), Sort, Page size.
 * - Cancel allowed only for pending applications, with CSRF and full permission checks.
 * - Notifications to admins on cancel.
 *
 * Fix: Do NOT display flash messages that originated from other pages (e.g., submit_application).
 * Only show local messages when this page itself performs an action (cancel).
 */

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/csrf.php';
require_once 'includes/notifications.php';
require_once 'includes/helpers.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

if (!isLoggedIn()) redirect('login.php?timeout=1');
requireVendor();

$user_id    = (int)($_SESSION['user_id'] ?? 0);
$page_title = 'My Applications';

/* Local flash messages used only when posting cancel on this page */
$error_message   = '';
$success_message = '';

/* Only consume flashes if this request posted a cancel action; otherwise ignore global session flashes */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['cancel_application'])) {
    if (!empty($_SESSION['error_message'])) { $error_message = (string)$_SESSION['error_message']; unset($_SESSION['error_message']); }
    if (!empty($_SESSION['success_message'])) { $success_message = (string)$_SESSION['success_message']; unset($_SESSION['success_message']); }
}

/* Helpers */
function add_where(&$sql, &$params, $cond, $vals = []) {
    $sql .= " AND ($cond)";
    foreach ((array)$vals as $v) $params[] = $v;
}
function paginate($total, $perPage, $currentPage) {
    $totalPages = max(1, (int)ceil($total / max(1, (int)$perPage)));
    $currentPage = max(1, min($currentPage, $totalPages));
    $offset = ($currentPage - 1) * $perPage;
    return ['totalPages'=>$totalPages, 'currentPage'=>$currentPage, 'offset'=>$offset, 'limit'=>$perPage];
}

/* POST: Cancel application */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['cancel_application'])) {
    if (!csrf_validate_request()) {
        $_SESSION['error_message'] = 'Invalid CSRF token.';
        redirect('my_applications.php#applications');
    }

    $application_id = (int)($_POST['application_id'] ?? 0);
    if ($application_id <= 0) {
        $_SESSION['error_message'] = 'Invalid application selected.';
        redirect('my_applications.php#applications');
    }

    $appRow = $db->fetch("SELECT * FROM applications WHERE application_id=? LIMIT 1", [$application_id]);
    if (!$appRow) {
        $_SESSION['error_message'] = 'Application not found.';
        redirect('my_applications.php#applications');
    }
    if ((int)$appRow['vendor_id'] !== (int)$user_id) {
        $_SESSION['error_message'] = 'You are not allowed to cancel this application.';
        redirect('my_applications.php#applications');
    }
    if (strtolower((string)$appRow['status']) !== 'pending') {
        $_SESSION['error_message'] = 'Only pending applications can be cancelled.';
        redirect('my_applications.php#applications');
    }

    try {
        $db->query(
            "UPDATE applications SET status='cancelled',
             admin_notes=CONCAT(COALESCE(admin_notes,''), ?),
             reviewed_at=NOW(), reviewed_by=?
             WHERE application_id=?",
            ["\n[Cancelled by vendor at ".date('Y-m-d H:i:s')."]", $user_id, $application_id]
        );

        // Free stall
        try { $db->query("UPDATE stalls SET status='available' WHERE stall_id=?", [$appRow['stall_id']]); } catch (Throwable $e) {
            error_log("cancel: stall status reset failed: ".$e->getMessage());
        }

        logAudit($db, $user_id, 'Application Cancelled', 'applications', $application_id, null, 'Cancelled by vendor');

        // Notify admins and market managers (best-effort)
        try {
            $admins = $db->fetchAll("
                SELECT DISTINCT u.user_id
                FROM user_roles ur
                JOIN roles r ON ur.role_id=r.role_id
                JOIN users u ON u.user_id=ur.user_id
                WHERE r.name IN ('super_admin','admin','market_manager')
                  AND ur.status='active' AND u.status='active'
            ") ?: [];
            if (empty($admins)) {
                $admins = $db->fetchAll("SELECT user_id FROM users WHERE role='admin' AND status='active'") ?: [];
            }
            $stallLabel = $db->fetch("SELECT stall_number FROM stalls WHERE stall_id=? LIMIT 1", [$appRow['stall_id']])['stall_number'] ?? 'Unknown';
            $msg = "Application #{$application_id} cancelled by vendor (".htmlspecialchars($_SESSION['full_name'] ?? 'Vendor')."). Stall: {$stallLabel}.";
            foreach ($admins as $a) {
                if (!empty($a['user_id']) && function_exists('createNotification')) {
                    createNotification($db, (int)$a['user_id'], 'Application Cancelled', $msg, 'warning', 'application', $application_id, 'applications');
                }
            }
        } catch (Throwable $e) {
            error_log("cancel notify admins failed: ".$e->getMessage());
        }

        $_SESSION['success_message'] = 'Application cancelled successfully.';
        redirect('my_applications.php#applications');
    } catch (Throwable $e) {
        error_log("cancel failed: ".$e->getMessage());
        $_SESSION['error_message'] = 'Failed to cancel application.';
        redirect('my_applications.php#applications');
    }
}

/* Tabs, Filters, Sorting, Pagination */
$allowedTabs = ['pending','void','completed'];
$tab = isset($_GET['tab']) ? strtolower(sanitize($_GET['tab'])) : 'pending';
if (!in_array($tab, $allowedTabs, true)) $tab = 'pending';

$market_filter = isset($_GET['market_id']) ? (int)$_GET['market_id'] : 0;
$q = isset($_GET['q']) ? trim(sanitize($_GET['q'])) : '';

$allowedSort = [
    'applied_desc' => 'a.application_date DESC, a.application_id DESC',
    'applied_asc'  => 'a.application_date ASC, a.application_id ASC',
    'pref_desc'    => 'a.preferred_start_date DESC, a.application_id DESC',
    'pref_asc'     => 'a.preferred_start_date ASC, a.application_id ASC',
    'status_asc'   => 'a.status ASC, a.application_date DESC',
    'status_desc'  => 'a.status DESC, a.application_date DESC',
    'market_asc'   => 'm.market_name ASC, s.stall_number ASC, a.application_date DESC',
    'market_desc'  => 'm.market_name DESC, s.stall_number ASC, a.application_date DESC',
];
$sort = isset($_GET['sort']) ? strtolower(sanitize($_GET['sort'])) : 'applied_desc';
if (!isset($allowedSort[$sort])) $sort = 'applied_desc';

$perPageAllowed = [10,25,50,100];
$per_page = isset($_GET['per_page']) ? (int)$_GET['per_page'] : 10;
if (!in_array($per_page, $perPageAllowed, true)) $per_page = 10;

$page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;

/* Markets list for filter (vendor-scoped) */
try {
    $markets_for_vendor = $db->fetchAll("
        SELECT DISTINCT m.market_id, m.market_name
        FROM applications a
        JOIN stalls s ON a.stall_id = s.stall_id
        JOIN markets m ON s.market_id = m.market_id
        WHERE a.vendor_id = ?
        ORDER BY m.market_name
    ", [$user_id]) ?: [];
} catch (Throwable $e) {
    error_log("my_applications markets list failed: ".$e->getMessage());
    $markets_for_vendor = [];
}

/* Tab counts (badges) */
$counts = ['pending'=>0,'void'=>0,'completed'=>0];
try {
    $rows = $db->fetchAll("
        SELECT LOWER(a.status) AS s, COUNT(*) AS c
        FROM applications a
        WHERE a.vendor_id=?
        GROUP BY LOWER(a.status)
    ", [$user_id]) ?: [];
    foreach ($rows as $r) {
        $s = $r['s'] ?? '';
        $c = (int)($r['c'] ?? 0);
        if ($s === 'pending') $counts['pending'] += $c;
        elseif ($s === 'approved') $counts['completed'] += $c;
        elseif ($s === 'cancelled' || $s === 'rejected') $counts['void'] += $c;
    }
} catch (Throwable $e) {
    error_log("my_applications counts failed: ".$e->getMessage());
}

/* WHERE clause per tab */
function apply_tab_filter(&$sql, &$params, string $tab) {
    if ($tab === 'pending') {
        add_where($sql, $params, "LOWER(a.status) = 'pending'");
    } elseif ($tab === 'void') {
        add_where($sql, $params, "LOWER(a.status) IN ('cancelled','rejected')");
    } else { // completed
        add_where($sql, $params, "LOWER(a.status) = 'approved'");
    }
}

/* Count total */
$countSql = "SELECT COUNT(*) AS cnt
             FROM applications a
             JOIN stalls s ON a.stall_id = s.stall_id
             JOIN markets m ON s.market_id = m.market_id
             WHERE a.vendor_id = ?";
$countParams = [$user_id];
apply_tab_filter($countSql, $countParams, $tab);
if ($market_filter > 0) { add_where($countSql, $countParams, "m.market_id = ?", [$market_filter]); }
if ($q !== '') {
    $like = "%{$q}%";
    add_where($countSql, $countParams,
        "a.business_name LIKE ? OR a.business_type LIKE ? OR s.stall_number LIKE ? OR m.market_name LIKE ?",
        [$like,$like,$like,$like]
    );
}

try { $totalRow = $db->fetch($countSql, $countParams) ?: ['cnt'=>0]; }
catch (Throwable $e) { error_log("my_applications count failed: ".$e->getMessage()); $totalRow = ['cnt'=>0]; }
$total = (int)($totalRow['cnt'] ?? 0);
$pager = paginate($total, $per_page, $page);

/* Fetch paginated applications */
$listSql = "SELECT a.application_id, a.vendor_id, a.business_name, a.business_type,
                   a.status, a.application_date, a.preferred_start_date,
                   a.stall_id, s.stall_number, m.market_name, a.admin_notes
            FROM applications a
            JOIN stalls s ON a.stall_id = s.stall_id
            JOIN markets m ON s.market_id = m.market_id
            WHERE a.vendor_id = ?";
$listParams = [$user_id];
apply_tab_filter($listSql, $listParams, $tab);
if ($market_filter > 0) { add_where($listSql, $listParams, "m.market_id = ?", [$market_filter]); }
if ($q !== '') {
    $like = "%{$q}%";
    add_where($listSql, $listParams,
        "a.business_name LIKE ? OR a.business_type LIKE ? OR s.stall_number LIKE ? OR m.market_name LIKE ?",
        [$like,$like,$like,$like]
    );
}
$listSql .= " ORDER BY {$allowedSort[$sort]} LIMIT ? OFFSET ?";
$listParams[] = (int)$pager['limit'];
$listParams[] = (int)$pager['offset'];
try { $applications = $db->fetchAll($listSql, $listParams) ?: []; }
catch (Throwable $e) { error_log("my_applications list failed: ".$e->getMessage()); $applications = []; }

logAudit($db, $user_id, 'View Applications', 'applications', null, null, null);

/* Build tab URLs preserving filters */
$preserve = [
    'market_id' => $market_filter ?: null,
    'q'         => ($q !== '') ? $q : null,
    'sort'      => $sort,
    'per_page'  => $per_page
];
$preserve = array_filter($preserve, fn($v)=>$v!==null && $v!=='');
function tabUrl(array $preserve, string $tab): string {
    return 'my_applications.php?' . http_build_query(array_merge($preserve, ['tab'=>$tab])) . '#applications';
}

require_once 'includes/header.php';
require_once 'includes/vendor_sidebar.php';
?>
<section class="max-w-7xl mx-auto p-6" id="applications">

  <!-- Only show local flash messages when this page itself performed an action -->
  <?php if (!empty($error_message)): ?>
    <div class="bg-red-100 rounded p-3 mb-4 text-red-700"><?php echo htmlspecialchars($error_message); ?></div>
  <?php endif; ?>
  <?php if (!empty($success_message)): ?>
    <div class="bg-green-100 rounded p-3 mb-4 text-green-700"><?php echo htmlspecialchars($success_message); ?></div>
  <?php endif; ?>

  <!-- Tabs -->
  <div class="mb-4 flex flex-wrap gap-2">
    <a href="<?php echo htmlspecialchars(tabUrl($preserve,'pending')); ?>"
       class="px-4 py-2 rounded font-medium transition <?php echo $tab==='pending'?'bg-green-600 text-white':'bg-gray-100 text-gray-800 hover:bg-gray-200'; ?>">
      Pending <span class="ml-2 text-xs px-2 py-0.5 rounded-full <?php echo $tab==='pending'?'bg-white text-green-700':'bg-gray-200 text-gray-800'; ?>"><?php echo (int)$counts['pending']; ?></span>
    </a>
    <a href="<?php echo htmlspecialchars(tabUrl($preserve,'void')); ?>"
       class="px-4 py-2 rounded font-medium transition <?php echo $tab==='void'?'bg-green-600 text-white':'bg-gray-100 text-gray-800 hover:bg-gray-200'; ?>">
      Cancelled/Rejected <span class="ml-2 text-xs px-2 py-0.5 rounded-full <?php echo $tab==='void'?'bg-white text-green-700':'bg-gray-200 text-gray-800'; ?>"><?php echo (int)$counts['void']; ?></span>
    </a>
    <a href="<?php echo htmlspecialchars(tabUrl($preserve,'completed')); ?>"
       class="px-4 py-2 rounded font-medium transition <?php echo $tab==='completed'?'bg-green-600 text-white':'bg-gray-100 text-gray-800 hover:bg-gray-200'; ?>">
      Completed <span class="ml-2 text-xs px-2 py-0.5 rounded-full <?php echo $tab==='completed'?'bg-white text-green-700':'bg-gray-200 text-gray-800'; ?>"><?php echo (int)$counts['completed']; ?></span>
    </a>
  </div>

  <!-- Filters -->
  <div class="bg-white rounded shadow p-4 mb-6">
    <form method="GET" action="#applications" class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-3 items-end">
      <input type="hidden" name="tab" value="<?php echo htmlspecialchars($tab); ?>">

      <div>
        <label class="block text-sm mb-1">Market</label>
        <select name="market_id" class="w-full px-3 py-2 border rounded">
          <option value="0">All markets</option>
          <?php foreach ($markets_for_vendor as $mk): ?>
            <option value="<?php echo (int)$mk['market_id']; ?>" <?php echo $market_filter===(int)$mk['market_id'] ? 'selected':''; ?>>
              <?php echo htmlspecialchars($mk['market_name']); ?>
            </option>
          <?php endforeach; ?>
        </select>
      </div>

      <div class="md:col-span-2 lg:col-span-2">
        <label class="block text-sm mb-1">Search</label>
        <input type="text" name="q" value="<?php echo htmlspecialchars($q); ?>" placeholder="Business name, type, stall number, market"
               class="w-full px-3 py-2 border rounded">
      </div>

      <div>
        <label class="block text-sm mb-1">Sort</label>
        <select name="sort" class="w-full px-3 py-2 border rounded">
          <option value="applied_desc" <?php echo $sort==='applied_desc'?'selected':''; ?>>Applied (newest)</option>
          <option value="applied_asc"  <?php echo $sort==='applied_asc' ?'selected':''; ?>>Applied (oldest)</option>
          <option value="pref_desc"    <?php echo $sort==='pref_desc'  ?'selected':''; ?>>Preferred Start (newest)</option>
          <option value="pref_asc"     <?php echo $sort==='pref_asc'   ?'selected':''; ?>>Preferred Start (oldest)</option>
          <option value="status_asc"   <?php echo $sort==='status_asc' ?'selected':''; ?>>Status (A→Z)</option>
          <option value="status_desc"  <?php echo $sort==='status_desc'?'selected':''; ?>>Status (Z→A)</option>
          <option value="market_asc"   <?php echo $sort==='market_asc' ?'selected':''; ?>>Market (A→Z)</option>
          <option value="market_desc"  <?php echo $sort==='market_desc'?'selected':''; ?>>Market (Z→A)</option>
        </select>
      </div>

      <div>
        <label class="block text-sm mb-1">Per Page</label>
        <select name="per_page" class="w-full px-3 py-2 border rounded">
          <?php foreach ([10,25,50,100] as $pp): ?>
            <option value="<?php echo $pp; ?>" <?php echo $per_page===$pp?'selected':''; ?>><?php echo $pp; ?></option>
          <?php endforeach; ?>
        </select>
      </div>

      <div class="md:col-span-2 lg:col-span-2 flex gap-3 items-end">
        <button class="bg-green-600 text-white px-4 py-2 rounded">Apply Filters</button>
        <a href="<?php echo htmlspecialchars(tabUrl([], $tab)); ?>" class="px-4 py-2 bg-gray-200 rounded">Reset</a>
      </div>
    </form>
  </div>

  <?php if ($applications && count($applications) > 0): ?>
    <div class="bg-white rounded shadow overflow-hidden">
      <div class="overflow-x-auto">
        <table class="w-full">
          <thead class="bg-gray-50">
            <tr>
              <th class="py-3 px-4 text-left">Business</th>
              <th class="py-3 px-4 text-left">Stall</th>
              <th class="py-3 px-4 text-left">Applied</th>
              <th class="py-3 px-4 text-left">Preferred Start</th>
              <th class="py-3 px-4 text-left">Status</th>
              <th class="py-3 px-4 text-left">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-200">
            <?php foreach ($applications as $a): ?>
              <tr class="hover:bg-gray-50">
                <td class="py-3 px-4">
                  <div class="font-medium"><?php echo htmlspecialchars($a['business_name']); ?></div>
                  <div class="text-xs text-gray-500"><?php echo htmlspecialchars($a['business_type'] ?? ''); ?></div>
                </td>
                <td class="py-3 px-4">
                  <?php echo htmlspecialchars($a['stall_number']).' — '.htmlspecialchars($a['market_name']); ?>
                </td>
                <td class="py-3 px-4 text-sm text-gray-600"><?php echo formatDate($a['application_date']); ?></td>
                <td class="py-3 px-4 text-sm text-gray-600">
                  <?php
                    $pref = $a['preferred_start_date'];
                    echo (!empty($pref) && $pref !== '0000-00-00')
                      ? '<span title="'.htmlspecialchars($pref).'">'.htmlspecialchars(formatDate($pref)).'</span>'
                      : '-';
                  ?>
                </td>
                <td class="py-3 px-4">
                  <?php echo getStatusBadge($a['status']); ?>
                </td>
                <td class="py-3 px-4">
                  <a class="text-blue-600 mr-3" href="application_details.php?id=<?php echo (int)$a['application_id']; ?>">View</a>
                  <?php if (strtolower((string)$a['status']) === 'pending'): ?>
                    <form method="POST" action="#applications" style="display:inline" onsubmit="return confirm('Cancel this application?');">
                      <?php echo csrf_field(); ?>
                      <input type="hidden" name="application_id" value="<?php echo (int)$a['application_id']; ?>">
                      <button type="submit" name="cancel_application" class="text-red-600 bg-transparent border-0 p-0">
                        Cancel
                      </button>
                    </form>
                  <?php endif; ?>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>

      <!-- Pagination -->
      <div class="p-4 flex items-center justify-between">
        <div class="text-sm text-gray-600">
          Page <?php echo $pager['currentPage']; ?> of <?php echo $pager['totalPages']; ?> — <?php echo $total; ?> applications
        </div>
        <div class="space-x-2">
          <?php
            // Preserve current filters while paging
            $baseParams = [
              'tab'       => $tab,
              'market_id' => $market_filter ?: null,
              'q'         => $q !== '' ? $q : null,
              'sort'      => $sort,
              'per_page'  => $per_page
            ];
            $baseParams = array_filter($baseParams, fn($v) => $v !== null && $v !== '');
            $base = 'my_applications.php?' . http_build_query($baseParams) . '#applications';
          ?>
          <?php if ($pager['currentPage'] > 1): ?>
            <a class="px-3 py-1 bg-gray-200 rounded" href="<?php echo $base . '&page=1'; ?>">First</a>
            <a class="px-3 py-1 bg-gray-200 rounded" href="<?php echo $base . '&page=' . ($pager['currentPage'] - 1); ?>">Prev</a>
          <?php endif; ?>
          <?php
            $startPg = max(1, $pager['currentPage'] - 2);
            $endPg   = min($pager['totalPages'], $pager['currentPage'] + 2);
            for ($pg = $startPg; $pg <= $endPg; $pg++):
          ?>
            <a class="px-3 py-1 <?php echo ($pg == $pager['currentPage']) ? 'bg-green-600 text-white rounded' : 'bg-gray-100 rounded'; ?>"
               href="<?php echo $base . '&page=' . $pg; ?>"><?php echo $pg; ?></a>
          <?php endfor; ?>
          <?php if ($pager['currentPage'] < $pager['totalPages']): ?>
            <a class="px-3 py-1 bg-gray-200 rounded" href="<?php echo $base . '&page=' . ($pager['currentPage'] + 1); ?>">Next</a>
            <a class="px-3 py-1 bg-gray-200 rounded" href="<?php echo $base . '&page=' . $pager['totalPages']; ?>">Last</a>
          <?php endif; ?>
        </div>
      </div>
    </div>
  <?php else: ?>
    <div class="bg-white rounded shadow p-8 text-center text-gray-500">
      No applications match the current filters.
    </div>
  <?php endif; ?>
</section>

<?php include 'includes/footer.php'; ?>