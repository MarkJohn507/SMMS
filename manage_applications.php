<?php
/**
 * manage_applications.php
 *
 * Improved Manage Applications (view-only)
 * - Adds proper status filter (reads enum values from schema if available)
 * - Adds pagination & sorting
 * - Market scoping for market managers
 * - Defensive DB handling and error logging
 * - Verification badge (existing behavior kept)
 *
 * Note: this is a single-file replacement to fix the syntax error previously reported.
 */

require_once 'config.php';
require_once 'includes/notifications.php';
require_once 'API/send_sms.php';
require_once 'includes/audit.php';
require_once 'includes/csrf.php';
require_once 'includes/auth_roles.php';
require_once 'includes/helpers.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

$uid = $_SESSION['user_id'] ?? null;
if (!$uid) redirect('login.php');

/* Role helper */
function userHasAnyRoleNames($db, $userId, array $names): bool {
    $names = array_map('strtolower', $names);
    try {
        if (function_exists('userIsInRole')) {
            foreach ($names as $n) if (userIsInRole($db, $userId, $n)) return true;
            return false;
        }
    } catch (Throwable $e) { error_log($e->getMessage()); }
    try {
        $roles = function_exists('_fetchUserRoleNames') ? _fetchUserRoleNames($userId, $db) : ($_SESSION['roles'] ?? []);
        $roles = array_map('strtolower', (array)$roles);
        foreach ($names as $n) if (in_array($n, $roles, true)) return true;
    } catch (Throwable $e) { error_log($e->getMessage()); }
    return false;
}

$allowedRoles = ['super_admin','admin','market_manager','accountant','issuer_admin','municipal_admin','agency_admin'];
if (!userHasAnyRoleNames($db, $uid, $allowedRoles)) {
    http_response_code(403); echo "Forbidden."; exit;
}

$page_title = 'Manage Applications';
$error = '';
$success = '';

/* Market management scope */
function getManagedMarketIds($db, int $userId): array {
    $ids = [];
    try {
        $r = $db->fetchAll("SELECT market_id FROM market_managers WHERE user_id = ?", [$userId]) ?: [];
        foreach ($r as $x) if (!empty($x['market_id'])) $ids[] = (int)$x['market_id'];
    } catch (Throwable $e) { error_log($e->getMessage()); }
    if (empty($ids)) {
        try {
            $r = $db->fetchAll("SELECT market_id FROM markets WHERE created_by = ?", [$userId]) ?: [];
            foreach ($r as $x) if (!empty($x['market_id'])) $ids[] = (int)$x['market_id'];
        } catch (Throwable $e) { error_log($e->getMessage()); }
    }
    return array_values(array_unique($ids));
}

/* Live vendor verification (defensive fallback) */
function getVendorVerificationStatus($db, int $vendorId): array {
    $hasPermit = false; $hasId = false; $missing = [];
    try {
        $rows = $db->fetchAll("
            SELECT d.doc_type, d.status
            FROM user_role_documents d
            JOIN user_roles ur ON d.user_role_id = ur.user_role_id
            JOIN roles r ON ur.role_id = r.role_id
            WHERE ur.user_id = ? AND r.name = 'vendor'
        ", [$vendorId]) ?: [];
        foreach ($rows as $r) {
            $t = strtolower($r['doc_type'] ?? '');
            $s = strtolower($r['status'] ?? '');
            if (in_array($t, ['permit','business_permit'], true) && $s === 'approved') $hasPermit = true;
            if (in_array($t, ['id','government_id','gov_id'], true) && $s === 'approved') $hasId = true;
        }
    } catch (Throwable $e) {
        error_log("getVendorVerificationStatus: " . $e->getMessage());
    }
    if (!$hasPermit) $missing[] = 'permit';
    if (!$hasId) $missing[] = 'id';
    return ['verified' => ($hasPermit && $hasId), 'missing' => $missing];
}

/* Utility: try to read enum values for a given table.column */
function enumValuesFromColumn($db, string $table, string $column): array {
    try {
        $row = $db->fetch("SELECT COLUMN_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1", [$table, $column]);
        if (!empty($row['COLUMN_TYPE'])) {
            $type = $row['COLUMN_TYPE']; // e.g. enum('pending','approved',...)
            if (preg_match("/^enum\\((.*)\\)$/i", $type, $m)) {
                // parse comma-separated quoted values
                $raw = $m[1];
                $parts = str_getcsv($raw, ',', "'");
                $vals = array_map('strtolower', array_map('trim', $parts));
                return $vals;
            }
        }
    } catch (Throwable $e) {
        error_log("enumValuesFromColumn error: " . $e->getMessage());
    }
    // fallback common statuses
    return ['pending','approved','rejected','cancelled','withdrawn'];
}

/* Pagination helper */
function paginate($total, $perPage, $currentPage) {
    $totalPages = max(1, (int)ceil($total / max(1, intval($perPage))));
    $currentPage = max(1, min($currentPage, $totalPages));
    $offset = ($currentPage - 1) * $perPage;
    return ['totalPages' => $totalPages, 'currentPage' => $currentPage, 'offset' => $offset, 'limit' => $perPage];
}

/* Filters */
$search = isset($_GET['search']) ? sanitize($_GET['search']) : '';
$status_filter = isset($_GET['status']) ? strtolower(sanitize($_GET['status'])) : 'pending';
$perPage = isset($_GET['per_page']) ? max(5, min(100, (int)$_GET['per_page'])) : 25;
$page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
$sort_by = isset($_GET['sort_by']) ? sanitize($_GET['sort_by']) : 'application_date';
$sort_dir = (isset($_GET['sort_dir']) && strtolower($_GET['sort_dir']) === 'asc') ? 'ASC' : 'DESC';

/* Allowed sort columns & map to real columns */
$allowedSort = [
    'application_date' => 'a.application_date',
    'preferred_start'  => 'preferred_start_date',
    'business_name'    => 'a.business_name'
];
$sort_sql = $allowedSort[$sort_by] ?? $allowedSort['application_date'];

/* Get enum statuses from DB if possible */
$enumStatuses = enumValuesFromColumn($db, 'applications', 'status');
$valid_statuses = $enumStatuses;
array_push($valid_statuses, 'all');

/* normalize status filter */
if ($status_filter !== 'all' && !in_array($status_filter, $enumStatuses, true)) {
    $status_filter = 'all';
}

/* Market scoping for market managers */
$isMarketManager = userHasAnyRoleNames($db, $uid, ['market_manager']);
$applications = [];
$total = 0;
$pager = paginate(0, $perPage, 1);

try {
    // Build where clause and params
    $where = " WHERE 1=1 ";
    $params = [];

    if (!empty($search)) {
        $where .= " AND (a.business_name LIKE ? OR u.full_name LIKE ? OR s.stall_number LIKE ?)";
        $sp = "%{$search}%";
        $params[] = $sp; $params[] = $sp; $params[] = $sp;
    }

    if ($status_filter !== 'all') {
        $where .= " AND LOWER(TRIM(a.status)) = ?";
        $params[] = $status_filter;
    }

    if ($isMarketManager) {
        $managed = getManagedMarketIds($db, $uid);
        if (empty($managed)) {
            // no access to any markets => no results
            $applications = [];
            $total = 0;
            $pager = paginate(0, $perPage, 1);
            // skip fetching rows
            throw new Exception('No managed markets');
        } else {
            $ph = implode(',', array_fill(0, count($managed), '?'));
            $where .= " AND m.market_id IN ($ph)";
            foreach ($managed as $id) $params[] = $id;
        }
    }

    // Count total
    $countSql = "SELECT COUNT(*) AS cnt
                 FROM applications a
                 JOIN stalls s ON a.stall_id = s.stall_id
                 JOIN markets m ON s.market_id = m.market_id
                 JOIN users u ON a.vendor_id = u.user_id
                 {$where}";
    $countRow = $db->fetch($countSql, $params);
    $total = (int)($countRow['cnt'] ?? 0);

    // Pagination
    $pager = paginate($total, $perPage, $page);
    $limit = (int)$pager['limit'];
    $offset = (int)$pager['offset'];

    // Fetch rows with sorting and limit
    $selectSql = "SELECT
        a.application_id, a.vendor_id, a.business_name, a.business_type, a.business_permit,
        a.application_date, a.admin_notes, a.status,
        NULLIF(a.preferred_start_date,'0000-00-00') AS preferred_start_date,
        s.stall_number, s.monthly_rent, m.market_name,
        u.full_name AS vendor_name, u.email, u.contact_number,
        a.reviewed_by, a.reviewed_at
    FROM applications a
    JOIN stalls s ON a.stall_id = s.stall_id
    JOIN markets m ON s.market_id = m.market_id
    JOIN users u ON a.vendor_id = u.user_id
    {$where}
    ORDER BY {$sort_sql} {$sort_dir}
    LIMIT ? OFFSET ?";

    $paramsWithLimit = array_merge($params, [$limit, $offset]);
    $applications = $db->fetchAll($selectSql, $paramsWithLimit) ?: [];

} catch (Throwable $e) {
    // If exception thrown intentionally above (no managed markets) it's OK; otherwise log
    if ($e->getMessage() !== 'No managed markets') {
        error_log("manage_applications: fetch failed: " . $e->getMessage());
    }
    if (!isset($applications) || !is_array($applications)) $applications = [];
}

/* Annotate verification (defensive) */
foreach ($applications as &$row) {
    $row['_verification'] = getVendorVerificationStatus($db, (int)$row['vendor_id']);
    // fetch reviewer name if reviewed_by present (optional)
    $row['_reviewer_name'] = null;
    if (!empty($row['reviewed_by'])) {
        try {
            $rev = $db->fetch("SELECT full_name FROM users WHERE user_id = ? LIMIT 1", [(int)$row['reviewed_by']]);
            if ($rev) $row['_reviewer_name'] = $rev['full_name'];
        } catch (Throwable $e) {}
    }
}
unset($row);

logAudit($db, $uid, 'View Manage Applications (view-only with status filter)', 'applications', null, null, null);

require_once 'includes/header.php';
require_once 'includes/admin_sidebar.php';
?>
<section class="max-w-7xl mx-auto p-6">
  <div class="mb-6">
    <p class="text-gray-600">View stall rental applications (read-only). Use filters to locate applications by status or search terms.</p>
  </div>

  <div class="bg-white rounded-lg shadow-md p-6 mb-6">
    <form class="flex flex-col md:flex-row gap-4" method="GET" action="">
      <div class="flex-1">
        <label class="block text-sm font-medium mb-2">Search</label>
        <input type="text" name="search" value="<?= htmlspecialchars($search); ?>"
               class="w-full px-4 py-2 border rounded" placeholder="Business, applicant, stall #">
      </div>

      <div>
        <label class="block text-sm font-medium mb-2">Status</label>
        <select name="status" class="px-4 py-2 border rounded">
          <option value="all" <?= $status_filter === 'all' ? 'selected' : '' ?>>All</option>
          <?php foreach ($enumStatuses as $st): ?>
            <option value="<?= htmlspecialchars($st) ?>" <?= $status_filter === $st ? 'selected' : '' ?>>
              <?= htmlspecialchars(ucfirst($st)) ?>
            </option>
          <?php endforeach; ?>
        </select>
      </div>

      <div>
        <label class="block text-sm font-medium mb-2">Sort</label>
        <select name="sort_by" class="px-3 py-2 border rounded">
          <option value="application_date" <?= $sort_by==='application_date' ? 'selected' : '' ?>>Applied</option>
          <option value="preferred_start"  <?= $sort_by==='preferred_start' ? 'selected' : '' ?>>Preferred Start</option>
          <option value="business_name"    <?= $sort_by==='business_name' ? 'selected' : '' ?>>Business</option>
        </select>
      </div>

      <div>
        <label class="block text-sm font-medium mb-2">Direction</label>
        <select name="sort_dir" class="px-3 py-2 border rounded">
          <option value="desc" <?= $sort_dir === 'DESC' ? 'selected' : '' ?>>Desc</option>
          <option value="asc"  <?= $sort_dir === 'ASC' ? 'selected' : '' ?>>Asc</option>
        </select>
      </div>

      <div class="flex items-end gap-2">
        <button class="px-6 py-2 bg-blue-600 text-white rounded">Filter</button>
        <a href="manage_applications.php" class="px-6 py-2 bg-gray-300 text-gray-700 rounded">Reset</a>
      </div>
    </form>

    <p class="mt-3 text-xs text-gray-500">
      All new applications should be from verified vendors. Legacy unverified entries (if any) show as Unverified.
    </p>
  </div>

  <div class="bg-white rounded-lg shadow-md overflow-hidden">
    <?php if (!empty($applications)): ?>
      <div class="overflow-x-auto">
        <table class="w-full">
          <thead class="bg-gray-50">
            <tr>
              <th class="text-left py-4 px-6">Applicant</th>
              <th class="text-left py-4 px-6">Business</th>
              <th class="text-left py-4 px-6">Stall</th>
              <th class="text-left py-4 px-6">Applied</th>
              <th class="text-left py-4 px-6">Preferred Start</th>
              <th class="text-left py-4 px-6">Verification</th>
              <th class="text-left py-4 px-6">Status</th>
              <th class="text-left py-4 px-6">View</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-200">
            <?php foreach ($applications as $app): ?>
              <?php
                $ver = $app['_verification'] ?? ['verified'=>false,'missing'=>['?']];
                $verified = !empty($ver['verified']);
                $missingList = $verified ? [] : ($ver['missing'] ?? []);
                $badgeClass = $verified ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700';
                $badgeLabel = $verified ? 'Verified' : 'Unverified';
                $missingText = !$verified && $missingList ? 'Missing: '.implode(', ', $missingList) : '';
                $appStatus = isset($app['status']) && $app['status'] !== '' ? htmlspecialchars(ucfirst($app['status'])) : '-';
              ?>
              <tr class="hover:bg-gray-50">
                <td class="py-4 px-6">
                  <p class="font-semibold"><?php echo htmlspecialchars($app['vendor_name']); ?></p>
                  <p class="text-xs text-gray-600"><?php echo htmlspecialchars($app['email']); ?></p>
                  <p class="text-xs text-gray-600"><?php echo htmlspecialchars($app['contact_number']); ?></p>
                </td>
                <td class="py-4 px-6">
                  <p class="font-semibold truncate max-w-[220px]" title="<?php echo htmlspecialchars($app['business_name']); ?>">
                    <?php echo htmlspecialchars($app['business_name']); ?>
                  </p>
                  <p class="text-sm text-gray-600 truncate max-w-[220px]"><?php echo htmlspecialchars($app['business_type']); ?></p>
                  <?php if (!empty($app['admin_notes'])): ?>
                    <p class="text-[11px] text-gray-500 mt-1 truncate max-w-[220px]" title="<?php echo htmlspecialchars($app['admin_notes']); ?>">
                      Notes: <?php echo htmlspecialchars(substr($app['admin_notes'],0,80)); ?><?php echo strlen($app['admin_notes'])>80?'…':''; ?>
                    </p>
                  <?php endif; ?>
                </td>
                <td class="py-4 px-6">
                  <p class="font-medium"><?php echo htmlspecialchars($app['stall_number']); ?></p>
                  <p class="text-sm text-gray-600"><?php echo htmlspecialchars($app['market_name']); ?></p>
                  <p class="text-sm font-semibold"><?php echo formatCurrency($app['monthly_rent'] ?? 0); ?>/mo</p>
                </td>
                <td class="py-4 px-6 text-sm text-gray-600 whitespace-nowrap"><?php echo formatDate($app['application_date']); ?></td>
                <td class="py-4 px-6 text-sm text-gray-600 whitespace-nowrap">
                  <?php echo !empty($app['preferred_start_date']) ? htmlspecialchars(formatDate($app['preferred_start_date'])) : '-'; ?>
                </td>
                <td class="py-4 px-6">
                  <span class="inline-block px-2 py-1 rounded text-xs font-semibold <?php echo $badgeClass; ?>"
                        title="<?php echo htmlspecialchars($missingText); ?>">
                    <?php echo $badgeLabel; ?>
                  </span>
                  <?php if (!$verified && $missingText): ?>
                    <p class="text-[11px] text-red-600 mt-1"><?php echo htmlspecialchars($missingText); ?></p>
                  <?php endif; ?>
                </td>
                <td class="py-4 px-6">
                  <span class="inline-block px-2 py-1 rounded text-xs font-semibold bg-gray-100 text-gray-700">
                    <?php echo $appStatus; ?>
                  </span>
                  <?php if (!empty($app['_reviewer_name'])): ?>
                    <div class="text-xs text-gray-500 mt-1">Reviewed by: <?php echo htmlspecialchars($app['_reviewer_name']); ?></div>
                    <?php if (!empty($app['reviewed_at'])): ?>
                      <div class="text-[11px] text-gray-400">on <?php echo formatDate($app['reviewed_at'], true); ?></div>
                    <?php endif; ?>
                  <?php endif; ?>
                </td>
                <td class="py-4 px-6">
                  <button type="button"
                          onclick='viewApplicationDetails(<?php echo json_encode(["application_id"=>$app["application_id"]], JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP); ?>)'
                          class="px-2 py-1 rounded text-sm hover:bg-gray-100"
                          title="View application">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-gray-700" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                      <path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                      <path stroke-linecap="round" stroke-linejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.477 0 8.268 2.943 9.542 7-1.274 4.057-5.065 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                    </svg>
                  </button>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>

      <div class="p-4 flex items-center justify-between">
        <div class="text-sm text-gray-600">Page <?php echo $pager['currentPage']; ?> of <?php echo $pager['totalPages']; ?> — <?php echo $total; ?> applications</div>
        <div class="space-x-2">
          <?php
            $baseParams = [];
            if ($search) $baseParams['search'] = $search;
            if ($status_filter !== 'all') $baseParams['status'] = $status_filter;
            if ($sort_by) $baseParams['sort_by'] = $sort_by;
            if ($sort_dir) $baseParams['sort_dir'] = strtolower($sort_dir);
            if ($perPage) $baseParams['per_page'] = $perPage;
            $base = 'manage_applications.php?' . http_build_query($baseParams);
          ?>
          <?php if ($pager['currentPage'] > 1): ?>
            <a class="px-3 py-1 bg-gray-200 rounded" href="<?php echo $base . '&page=1'; ?>">First</a>
            <a class="px-3 py-1 bg-gray-200 rounded" href="<?php echo $base . '&page=' . ($pager['currentPage'] - 1); ?>">Prev</a>
          <?php endif; ?>
          <?php for ($pg = 1; $pg <= $pager['totalPages']; $pg++): ?>
            <a class="px-3 py-1 <?php echo ($pg == $pager['currentPage']) ? 'bg-blue-600 text-white rounded' : 'bg-gray-100 rounded'; ?>" href="<?php echo $base . '&page=' . $pg; ?>"><?php echo $pg; ?></a>
          <?php endfor; ?>
          <?php if ($pager['currentPage'] < $pager['totalPages']): ?>
            <a class="px-3 py-1 bg-gray-200 rounded" href="<?php echo $base . '&page=' . ($pager['currentPage'] + 1); ?>">Next</a>
            <a class="px-3 py-1 bg-gray-200 rounded" href="<?php echo $base . '&page=' . $pager['totalPages']; ?>">Last</a>
          <?php endif; ?>
        </div>
      </div>

    <?php else: ?>
      <div class="text-center py-16">
        <h3 class="text-xl font-semibold text-gray-700 mb-2">No applications found</h3>
        <p class="text-gray-500">Adjust your filters or wait for new submissions.</p>
      </div>
    <?php endif; ?>
  </div>
</section>

<!-- Details Modal (view only) -->
<div id="detailsModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
  <div class="bg-white rounded-lg max-w-4xl w-full max-h-[90vh] overflow-y-auto">
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h3 class="text-2xl font-bold text-gray-800">Application Details</h3>
        <button onclick="closeDetailsModal()" class="text-gray-500 hover:text-gray-700">✕</button>
      </div>
      <div id="detailsModalContent"></div>
    </div>
  </div>
</div>

<script>
function viewApplicationDetails(appOrId){
  let appObj = (typeof appOrId==='object' && appOrId!==null) ? appOrId : {application_id:appOrId};
  const content = document.getElementById('detailsModalContent');
  content.innerHTML = '<div class="py-12 flex justify-center"><div class="animate-spin h-12 w-12 border-b-2 border-blue-600 rounded-full"></div></div>';
  document.getElementById('detailsModal').classList.remove('hidden');

  fetch('get_application_details.php?id='+encodeURIComponent(appObj.application_id))
    .then(r=>{ if(!r.ok) throw new Error('Load failed'); return r.text(); })
    .then(html=>{
      content.innerHTML=html;
      // Remove embedded action buttons defensively
      content.querySelectorAll('.approve-btn,.reject-btn,.application-action').forEach(el=>el.remove());
    })
    .catch(e=>{
      content.innerHTML='<div class="py-8 text-center text-red-600">Failed to load details.</div>';
      console.error(e);
    });
}

function closeDetailsModal(){
  document.getElementById('detailsModal').classList.add('hidden');
  document.getElementById('detailsModalContent').innerHTML='';
}

document.addEventListener('click',e=>{
  const dm=document.getElementById('detailsModal');
  if (dm && e.target===dm) closeDetailsModal();
});
document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){ closeDetailsModal(); }
});
</script>

<?php include 'includes/footer.php'; ?>