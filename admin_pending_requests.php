<?php
/**
 * admin_pending_requests.php
 *
 * FINAL (super_admin only)
 * - Safe queries that include ur.market_id and ur.assigned_by when present.
 * - Excludes super_admin and vendor roles.
 * - Batch-resolves assigned_by -> requester name and market_id -> market manager name.
 * - Defensive against schemas that may not have optional columns.
 *
 * Update: Removed "Revoke" action/button from processed requests.
 */

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/csrf.php';
require_once 'includes/helpers.php';
require_once 'includes/audit.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
requireAdmin();

$roles = $_SESSION['roles'] ?? [];
if (!in_array('super_admin', $roles, true) && !in_array('municipal_admin', $roles, true)) {
    redirect('admin_dashboard.php');
}

$page_title = 'Role Requests';
$errors = [];
$success = '';

if (!empty($_GET['msg'])) {
    if ($_GET['msg'] === 'approved') $success = 'Role request approved.';
    elseif ($_GET['msg'] === 'rejected') $success = 'Role request rejected.';
}
if (!empty($_GET['error'])) $errors[] = 'An error occurred processing the request.';

$last_reject_error = '';
if (!empty($_SESSION['last_reject_error'])) {
    $last_reject_error = $_SESSION['last_reject_error'];
    unset($_SESSION['last_reject_error']);
}

$q = trim((string)($_GET['q'] ?? ''));
$useSearch = ($q !== '');
$searchSql = " AND (u.username LIKE ? OR u.full_name LIKE ? OR u.email LIKE ? OR r.name LIKE ?)";
$searchParams = $useSearch ? array_fill(0, 4, "%$q%") : [];

/**
 * Exclude super_admin and vendor roles
 */
$excludeRoles = " AND r.name NOT IN ('super_admin','vendor') ";

try {
    // discover optional columns in user_roles
    $cols = $db->fetchAll("SHOW COLUMNS FROM user_roles") ?: [];
    $colNames = [];
    foreach ($cols as $c) {
        if (is_array($c)) $colNames[] = $c['Field'] ?? $c['field'] ?? '';
    }
    $has_admin_notes         = in_array('admin_notes', $colNames, true);
    $has_resubmission_reason = in_array('resubmission_reason', $colNames, true);
    $has_assigned_by         = in_array('assigned_by', $colNames, true);

    $admin_expr  = $has_admin_notes ? 'ur.admin_notes' : "''";
    $reason_expr = $has_resubmission_reason ? 'ur.resubmission_reason' : "''";
    $assigned_by_expr = $has_assigned_by ? 'ur.assigned_by' : 'NULL AS assigned_by';

    $requested_col = null;
    foreach (['created_at', 'requested_at', 'assigned_at', 'created_on'] as $cand) {
        if (in_array($cand, $colNames, true)) { $requested_col = $cand; break; }
    }
    $processed_col = null;
    foreach (['reviewed_at', 'approved_at', 'updated_at', 'assigned_at', 'created_at'] as $cand) {
        if (in_array($cand, $colNames, true)) { $processed_col = $cand; break; }
    }

    // Build Pending SQL
    $pendingSql = "
        SELECT ur.user_role_id, ur.user_id, ur.role_id, COALESCE(ur.market_id, NULL) AS market_id,
               ur.status AS user_role_status,
               " . ($requested_col ? "ur.$requested_col AS requested_at" : "NULL AS requested_at") . ",
               u.username, u.full_name, u.email, u.contact_number, u.status AS user_status,
               r.name AS role_name, r.description AS role_description,
               $admin_expr AS admin_notes, $reason_expr AS resubmission_reason,
               " . ($has_assigned_by ? 'ur.assigned_by' : 'NULL') . " AS assigned_by
        FROM user_roles ur
        JOIN users u ON ur.user_id = u.user_id
        JOIN roles r ON ur.role_id = r.role_id
        WHERE LOWER(TRIM(COALESCE(ur.status,''))) = 'pending'
        $excludeRoles"
        . ($useSearch ? $searchSql : '')
        . " ORDER BY " . ($requested_col ? "ur.$requested_col DESC" : "ur.user_role_id DESC") . " LIMIT 500";

    $pending_requests = $db->fetchAll($pendingSql, $searchParams) ?: [];

    // Build Processed SQL
    $processedSql = "
        SELECT ur.user_role_id, ur.user_id, ur.role_id, COALESCE(ur.market_id, NULL) AS market_id,
               ur.status AS user_role_status,
               " . ($processed_col ? "ur.$processed_col AS processed_at" : "NULL AS processed_at") . ",
               u.username, u.full_name, u.email, u.contact_number, u.status AS user_status,
               r.name AS role_name, r.description AS role_description,
               $admin_expr AS admin_notes, $reason_expr AS resubmission_reason,
               " . ($has_assigned_by ? 'ur.assigned_by' : 'NULL') . " AS assigned_by
        FROM user_roles ur
        JOIN users u ON ur.user_id = u.user_id
        JOIN roles r ON ur.role_id = r.role_id
        WHERE LOWER(TRIM(COALESCE(ur.status,''))) <> 'pending'
        $excludeRoles"
        . ($useSearch ? $searchSql : '')
        . " ORDER BY " . ($processed_col ? "ur.$processed_col DESC" : "ur.user_role_id DESC") . " LIMIT 500";

    $processed_requests = $db->fetchAll($processedSql, $searchParams) ?: [];

    //
    // Enrich rows: batch-resolve assigned_by -> user full_name and market_id -> market manager name
    //
    $allRows = array_merge($pending_requests, $processed_requests);
    $assignedIds = [];
    $marketIds = [];
    foreach ($allRows as $rr) {
        if (!empty($rr['assigned_by']) && is_numeric($rr['assigned_by'])) {
            $assignedIds[(int)$rr['assigned_by']] = true;
        }
        if (!empty($rr['market_id']) && is_numeric($rr['market_id'])) {
            $marketIds[(int)$rr['market_id']] = true;
        }
    }

    $assignedMap = [];
    if (!empty($assignedIds)) {
        $ph = implode(',', array_fill(0, count($assignedIds), '?'));
        $params = array_keys($assignedIds);
        $rowsUsers = $db->fetchAll("SELECT user_id, full_name FROM users WHERE user_id IN ($ph)", $params) ?: [];
        foreach ($rowsUsers as $u) {
            $assignedMap[(int)$u['user_id']] = $u['full_name'] ?? '';
        }
    }

    // Determine if market_managers has a 'status' column
    $marketManagerMap = [];
    if (!empty($marketIds)) {
        $mmCols = $db->fetchAll("SHOW COLUMNS FROM market_managers") ?: [];
        $mmColNames = [];
        foreach ($mmCols as $c) if (is_array($c)) $mmColNames[] = $c['Field'] ?? $c['field'] ?? '';
        $mm_has_status = in_array('status', $mmColNames, true);

        $ph = implode(',', array_fill(0, count($marketIds), '?'));
        $params = array_keys($marketIds);
        $mm_status_clause = $mm_has_status ? "AND mm.status = 'active'" : "";
        $sql = "SELECT mm.market_id, u.user_id AS manager_user_id, u.full_name
                FROM market_managers mm
                JOIN users u ON mm.user_id = u.user_id
                WHERE mm.market_id IN ($ph) $mm_status_clause AND u.status = 'active'
                GROUP BY mm.market_id";
        $rowsMM = $db->fetchAll($sql, $params) ?: [];
        foreach ($rowsMM as $m) {
            $marketManagerMap[(int)$m['market_id']] = $m['full_name'] ?? '';
        }
    }

    // Populate requested_by_name and market_manager_name
    $populateRow = function (&$row) use ($assignedMap, $marketManagerMap) {
        $row['requested_by_name'] = null;
        $row['market_manager_name'] = null;

        if (!empty($row['assigned_by']) && isset($assignedMap[(int)$row['assigned_by']])) {
            $row['requested_by_name'] = $assignedMap[(int)$row['assigned_by']];
        }
        if (!empty($row['market_id']) && isset($marketManagerMap[(int)$row['market_id']])) {
            $row['market_manager_name'] = $marketManagerMap[(int)$row['market_id']];
        }
        $roleLower = strtolower((string)($row['role_name'] ?? ''));
        if (empty($row['requested_by_name']) && in_array($roleLower, ['inspector', 'accountant'], true) && !empty($row['market_manager_name'])) {
            $row['requested_by_name'] = $row['market_manager_name'] . ' (market manager)';
        }
    };

    foreach ($pending_requests as &$r) $populateRow($r);
    unset($r);
    foreach ($processed_requests as &$r) $populateRow($r);
    unset($r);

} catch (Throwable $e) {
    error_log("admin_pending_requests fetch error: " . $e->getMessage());
    $pending_requests = [];
    $processed_requests = [];
    $errors[] = 'Unable to load role requests.';
}

require_once 'includes/header.php';
require_once 'includes/admin_sidebar.php';
?>
<div class="max-w-7xl mx-auto p-6">
  <h1 class="text-2lx font-bold mb-2"><?php echo htmlspecialchars($page_title); ?></h1>
  <p class="text-sm text-gray-600 mb-4">
    Review and manage role assignment requests (excluding super_admin and vendor roles).
  </p>

  <?php if ($last_reject_error): ?>
    <div class="mb-4 bg-red-100 border border-red-300 text-red-800 px-4 py-2 rounded">
      <?php echo htmlspecialchars($last_reject_error); ?>
    </div>
  <?php endif; ?>

  <?php if ($errors): ?>
    <div class="mb-4 space-y-2">
      <?php foreach ($errors as $e): ?>
        <div class="bg-red-100 border border-red-300 text-red-800 px-4 py-2 rounded"><?php echo htmlspecialchars($e); ?></div>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>

  <?php if ($success): ?>
    <div class="mb-4 bg-green-100 border border-green-300 text-green-800 px-4 py-2 rounded">
      <?php echo htmlspecialchars($success); ?>
    </div>
  <?php endif; ?>

  <form method="get" class="mb-4 flex flex-wrap gap-2 items-center">
    <input type="text" name="q" value="<?php echo htmlspecialchars($q); ?>"
           placeholder="Search username, name, email, role..."
           class="px-3 py-2 border rounded w-72">
    <button class="px-3 py-2 bg-blue-600 text-white rounded">Search</button>
    <a href="admin_pending_requests.php" class="px-3 py-2 bg-gray-100 rounded">Clear</a>
    <span class="text-xs text-gray-500 ml-2">
      Showing: <?php echo $q !== '' ? htmlspecialchars($q) : 'All'; ?>
    </span>
  </form>

  <div class="mb-4 flex gap-2">
    <button id="tab-pending-btn"   class="px-4 py-2 rounded bg-blue-600 text-white">
      Pending (<?php echo count($pending_requests); ?>)
    </button>
    <button id="tab-processed-btn" class="px-4 py-2 rounded bg-gray-100">
      Processed (<?php echo count($processed_requests); ?>)
    </button>
  </div>

  <!-- Pending Tab -->
  <div id="tab-pending" class="bg-white rounded shadow overflow-auto p-4">
    <?php if (!$pending_requests): ?>
      <div class="p-6 text-center text-sm text-gray-600">No pending requests.</div>
    <?php else: ?>
      <table class="w-full text-sm">
        <thead class="bg-gray-50">
          <tr>
            <th class="px-4 py-3 text-left">Requested</th>
            <th class="px-4 py-3 text-left">User</th>
            <th class="px-4 py-3 text-left">Role</th>
            <th class="px-4 py-3 text-left">Account</th>
            <th class="px-4 py-3 text-left">Contact</th>
            <th class="px-4 py-3 text-left">Requested By</th>
            <th class="px-4 py-3 text-left">Manage</th>
          </tr>
        </thead>
        <tbody>
        <?php foreach ($pending_requests as $r): ?>
          <?php
            $roleLower = strtolower($r['role_name'] ?? '');
            if (in_array($roleLower, ['super_admin', 'vendor'], true)) continue; // double defense
            $requestedBy = $r['requested_by_name'] ?? '';
          ?>
          <tr class="border-t hover:bg-gray-50">
            <td class="px-4 py-3 text-xs text-gray-500">
              <?php echo htmlspecialchars(!empty($r['requested_at']) ? date('M j, Y H:i', strtotime($r['requested_at'])) : ''); ?>
            </td>
            <td class="px-4 py-3">
              <div class="font-medium"><?php echo htmlspecialchars($r['full_name'] ?? $r['username']); ?></div>
              <div class="text-xs text-gray-500">@<?php echo htmlspecialchars($r['username']); ?></div>
            </td>
            <td class="px-4 py-3">
              <div class="font-medium"><?php echo htmlspecialchars($r['role_name']); ?></div>
              <div class="text-xs text-gray-500"><?php echo htmlspecialchars($r['role_description'] ?? ''); ?></div>
              <?php if (!empty($r['resubmission_reason'])): ?>
                <div class="inline-block mt-1 text-[10px] px-2 py-1 bg-amber-100 text-amber-800 rounded"
                     title="<?php echo htmlspecialchars($r['resubmission_reason']); ?>">
                  Resubmission requested
                </div>
              <?php endif; ?>
            </td>
            <td class="px-4 py-3 text-xs">
              <div><?php echo htmlspecialchars($r['user_role_status']); ?></div>
              <div class="text-gray-500">Acct: <?php echo htmlspecialchars($r['user_status']); ?></div>
              <?php if (!empty($r['market_id'])): ?>
                <div class="text-xs text-gray-500">Market ID: <?php echo (int)$r['market_id']; ?></div>
              <?php endif; ?>
            </td>
            <td class="px-4 py-3 text-xs">
              <div><?php echo htmlspecialchars($r['email']); ?></div>
              <div class="text-gray-500"><?php echo htmlspecialchars($r['contact_number'] ?? ''); ?></div>
            </td>
            <td class="px-4 py-3 text-xs">
              <?php if ($requestedBy !== ''): ?>
                <div class="font-medium"><?php echo htmlspecialchars($requestedBy); ?></div>
              <?php else: ?>
                <div class="text-gray-500">—</div>
              <?php endif; ?>
            </td>
            <td class="px-4 py-3">
              <a href="manage_users.php?user_id=<?php echo (int)$r['user_id']; ?>"
                 class="px-3 py-1 bg-gray-100 hover:bg-gray-200 rounded text-xs"
                 title="Open user details">Manage</a>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>
  </div>

  <!-- Processed Tab -->
  <div id="tab-processed" class="hidden bg-white rounded shadow overflow-auto p-4">
    <?php if (!$processed_requests): ?>
      <div class="p-6 text-center text-sm text-gray-600">No processed requests.</div>
    <?php else: ?>
      <table class="w-full text-sm">
        <thead class="bg-gray-50">
          <tr>
            <th class="px-4 py-3 text-left">Processed</th>
            <th class="px-4 py-3 text-left">User</th>
            <th class="px-4 py-3 text-left">Role</th>
            <th class="px-4 py-3 text-left">Status</th>
            <th class="px-4 py-3 text-left">Contact</th>
            <th class="px-4 py-3 text-left">Requested By</th>
            <th class="px-4 py-3 text-left">Notes / Actions</th>
          </tr>
        </thead>
        <tbody>
        <?php foreach ($processed_requests as $r): ?>
          <?php
            $cleanStatus = strtolower(trim((string)$r['user_role_status']));
            $roleNameLower = strtolower(trim((string)$r['role_name']));
            if (in_array($roleNameLower, ['super_admin', 'vendor'], true)) continue;

            $statusBadge = match($cleanStatus) {
                'under_review'       => "<span class='inline-block px-2 py-1 rounded bg-indigo-100 text-indigo-700 text-[10px] font-semibold'>Under Review</span>",
                'rejected'           => "<span class='inline-block px-2 py-1 rounded bg-red-100 text-red-700 text-[10px] font-semibold'>Rejected</span>",
                'active'             => "<span class='inline-block px-2 py-1 rounded bg-green-100 text-green-700 text-[10px] font-semibold'>Active</span>",
                'provisional_active' => "<span class='inline-block px-2 py-1 rounded bg-amber-100 text-amber-700 text-[10px] font-semibold'>Provisional</span>",
                ''                   => "<span class='inline-block px-2 py-1 rounded bg-gray-200 text-gray-700 text-[10px] font-semibold'>Unknown</span>",
                default              => "<span class='inline-block px-2 py-1 rounded bg-gray-100 text-gray-700 text-[10px] font-semibold'>".htmlspecialchars($r['user_role_status'])."</span>"
            };
            $canReviewApprove = in_array($cleanStatus, ['under_review','pending','provisional_active','rejected'], true);
            $canReject        = in_array($cleanStatus, ['under_review','rejected','provisional_active'], true);

            $requestedBy = $r['requested_by_name'] ?? '';
          ?>
          <tr class="border-t hover:bg-gray-50">
            <td class="px-4 py-3 text-xs text-gray-500">
              <?php echo htmlspecialchars(!empty($r['processed_at']) ? date('M j, Y H:i', strtotime($r['processed_at'])) : ''); ?>
            </td>
            <td class="px-4 py-3">
              <div class="font-medium"><?php echo htmlspecialchars($r['full_name'] ?? $r['username']); ?></div>
              <div class="text-xs text-gray-500">@<?php echo htmlspecialchars($r['username']); ?></div>
            </td>
            <td class="px-4 py-3">
              <div class="font-medium"><?php echo htmlspecialchars($r['role_name']); ?></div>
              <div class="text-xs text-gray-500"><?php echo htmlspecialchars($r['role_description'] ?? ''); ?></div>
            </td>
            <td class="px-4 py-3 text-xs"><?php echo $statusBadge; ?></td>
            <td class="px-4 py-3 text-xs">
              <div><?php echo htmlspecialchars($r['email']); ?></div>
              <div class="text-gray-500"><?php echo htmlspecialchars($r['contact_number'] ?? ''); ?></div>
            </td>
            <td class="px-4 py-3 text-xs">
              <?php if ($requestedBy !== ''): ?>
                <div class="font-medium"><?php echo htmlspecialchars($requestedBy); ?></div>
              <?php else: ?>
                <div class="text-gray-500">—</div>
              <?php endif; ?>
            </td>
            <td class="px-4 py-3">
              <div class="space-y-2 text-xs">
                <?php if (!empty($r['resubmission_reason'])): ?>
                  <div class="text-amber-700"><strong>Resubmission reason:</strong> <?php echo htmlspecialchars($r['resubmission_reason']); ?></div>
                <?php endif; ?>
                <?php if (!empty($r['admin_notes'])): ?>
                  <div class="text-gray-600 whitespace-pre-wrap"><strong>Admin notes:</strong> <?php echo htmlspecialchars($r['admin_notes']); ?></div>
                <?php endif; ?>
                <div class="flex flex-wrap gap-2 mt-1">
                  <a href="manage_users.php?user_id=<?php echo (int)$r['user_id']; ?>"
                     class="px-3 py-1 bg-gray-100 hover:bg-gray-200 rounded"
                     title="Open detailed view">Manage</a>

                  <?php if ($canReviewApprove): ?>
                    <form method="POST" action="approve_role.php"
                          onsubmit="return confirm('Run approval review for this role?');"
                          class="m-0">
                      <?php echo csrf_field(); ?>
                      <input type="hidden" name="user_role_id" value="<?php echo (int)$r['user_role_id']; ?>">
                      <button class="px-3 py-1 bg-green-600 hover:bg-green-700 text-white rounded">Review / Approve</button>
                    </form>
                  <?php endif; ?>

                  <?php if ($canReject): ?>
                    <button type="button"
                            class="px-3 py-1 bg-red-600 hover:bg-red-700 text-white rounded"
                            data-user-role-id="<?php echo (int)$r['user_role_id']; ?>"
                            data-user-name="<?php echo htmlspecialchars($r['full_name'] ?? $r['username'], ENT_QUOTES); ?>"
                            data-role-name="<?php echo htmlspecialchars($r['role_name'], ENT_QUOTES); ?>"
                            onclick="openRejectModal(this)">Reject</button>
                  <?php endif; ?>
                </div>
              </div>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>
  </div>
</div>

<!-- Reject Modal -->
<div id="rejectModal" class="hidden fixed inset-0 z-50 flex items-center justify-center p-4 bg-black bg-opacity-50">
  <div class="bg-white rounded-lg w-full max-w-xl p-6 shadow-lg">
    <h3 class="text-xl font-semibold mb-3">Reject Role Request</h3>
    <p id="rejectModalLabel" class="text-sm text-gray-600 mb-4"></p>
    <form method="POST" action="reject_role.php">
      <?php echo csrf_field(); ?>
      <input type="hidden" name="user_role_id" id="reject_user_role_id">
      <div class="mb-4">
        <label class="block text-sm font-medium mb-1">Rejection reason (required)</label>
        <textarea name="reason" rows="5" required class="w-full border p-3 rounded" placeholder="Explain why and what user must fix"></textarea>
      </div>
      <div class="flex justify-end gap-2">
        <button type="button" onclick="closeRejectModal()" class="px-4 py-2 bg-gray-200 rounded">Cancel</button>
        <button type="submit" class="px-4 py-2 bg-red-600 text-white rounded">Reject</button>
      </div>
    </form>
  </div>
</div>

<script>
(function(){
  const tabP=document.getElementById('tab-pending-btn');
  const tabR=document.getElementById('tab-processed-btn');
  const boxP=document.getElementById('tab-pending');
  const boxR=document.getElementById('tab-processed');

  function showPending(){
    boxP.classList.remove('hidden'); boxR.classList.add('hidden');
    tabP.classList.add('bg-blue-600','text-white'); tabP.classList.remove('bg-gray-100');
    tabR.classList.remove('bg-blue-600','text-white'); tabR.classList.add('bg-gray-100');
  }
  function showProcessed(){
    boxR.classList.remove('hidden'); boxP.classList.add('hidden');
    tabR.classList.add('bg-blue-600','text-white'); tabR.classList.remove('bg-gray-100');
    tabP.classList.remove('bg-blue-600','text-white'); tabP.classList.add('bg-gray-100');
  }
  tabP.addEventListener('click',showPending);
  tabR.addEventListener('click',showProcessed);
  showPending();

  window.openRejectModal=function(btn){
    document.getElementById('reject_user_role_id').value=btn.getAttribute('data-user-role-id');
    const userName=btn.getAttribute('data-user-name');
    const roleName=btn.getAttribute('data-role-name');
    document.getElementById('rejectModalLabel').textContent="Reject role '"+roleName+"' for user "+userName;
    document.getElementById('rejectModal').classList.remove('hidden');
  };
  window.closeRejectModal=function(){
    document.getElementById('rejectModal').classList.add('hidden');
    document.getElementById('reject_user_role_id').value='';
  };
  document.addEventListener('click',function(e){
    const modal=document.getElementById('rejectModal');
    if (modal && e.target===modal) closeRejectModal();
  });
  document.addEventListener('keydown',function(e){
    if (e.key==='Escape') closeRejectModal();
  });
})();
</script>
<?php include 'includes/footer.php'; ?>