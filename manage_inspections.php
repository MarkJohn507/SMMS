<?php
// manage_inspections.php
// Two tabs: Scheduled Inspections | Completed Inspections
// Fixes:
//  - Allow market managers/accountants (and admins) to complete inspections within their markets.
//  - Require that the user performing the "Complete" action (inspector/manager/accountant/admin)
//    has at least one approved 'id' OR an approved 'permit' before completing an inspection.
//  - Make the "View" modal robust: embed a JSON fallback of the row on the View button and use it
//    if the API doesn't provide full fields so details always display.

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/inspector_utils.php';
require_once 'includes/csrf.php';
require_once 'includes/notifications.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

if (!isLoggedIn()) {
    $_SESSION['intended_url'] = $_SERVER['REQUEST_URI'] ?? '/';
    redirect('login.php?timeout=1');
}

$page_title = 'Manage Inspections';
$uid = (int)($_SESSION['user_id'] ?? 0);
if (!$uid) redirect('login.php');

// Resolve roles (include pending roles where appropriate)
$roleNames = [];
try {
    if (function_exists('_fetchUserRoleNames')) {
        $roleNames = _fetchUserRoleNames($uid, $db) ?: [];
    } elseif (!empty($_SESSION['roles']) && is_array($_SESSION['roles'])) {
        $roleNames = $_SESSION['roles'];
    }
} catch (Throwable $e) {
    error_log("manage_inspections: role fetch failed for user {$uid}: ".$e->getMessage());
    $roleNames = $_SESSION['roles'] ?? [];
}
$roleNames = array_map('strtolower', $roleNames);

$is_super_admin    = in_array('super_admin', $roleNames, true);
$is_market_manager = in_array('market_manager', $roleNames, true);
$is_accountant     = in_array('accountant', $roleNames, true);
$is_inspector      = function_exists('isInspector') ? isInspector($db, $uid) : in_array('inspector', $roleNames, true);

// whether the currently-logged-in user (who might perform completion) has at least one approved ID OR Permit
$user_verified = false;
try {
    $user_verified = userHasApprovedIdOrPermit($db, $uid);
} catch (Throwable $e) {
    error_log("manage_inspections: user_verified check failed for user {$uid}: " . $e->getMessage());
    $user_verified = false;
}

// Access control: disallow super_admin; allow market_manager, accountant, inspector or core admin
if ($is_super_admin) { http_response_code(403); echo "Forbidden"; exit; }
if (!($is_market_manager || $is_accountant || $is_inspector || isAdmin())) { http_response_code(403); echo "Forbidden"; exit; }

// Build market scope
$marketIds = [];
if (isAdmin()) {
    $marketIds = [];
} elseif ($is_market_manager || $is_accountant) {
    try { $marketIds = getManagedMarketIds($db, $uid); } catch (Throwable $e) { $marketIds = []; }
} elseif ($is_inspector) {
    try { $marketIds = getInspectorMarketIds($db, $uid); } catch (Throwable $e) { $marketIds = []; }
}

// Active tab (scheduled|completed)
$active_tab = isset($_GET['tab']) ? strtolower(trim($_GET['tab'])) : 'scheduled';
if (!in_array($active_tab, ['scheduled','completed'], true)) $active_tab = 'scheduled';

// Filters (shared)
$filter_market  = isset($_GET['market_id']) ? (int)$_GET['market_id'] : 0;
$filter_outcome = isset($_GET['outcome']) ? sanitize($_GET['outcome']) : '';
$search         = isset($_GET['search']) ? sanitize($_GET['search']) : '';
$scheduled_only = isset($_GET['scheduled_only']) && $_GET['scheduled_only'] === '1'; // only for scheduled tab

/* ---------------------- Helper functions ---------------------- */

/**
 * Attempt to locate the vendor/owner user_id for a stall.
 */
function getStallOwnerUserId($db, int $stall_id): ?int {
    if (!$db || $stall_id <= 0) return null;
    try {
        $candidates = [
            'vendor_user_id','lessee_user_id','lessee_id','user_id','vendor_id',
            'owner_id','assigned_user_id','assigned_to','holder_id','account_id'
        ];

        static $tableColsCache = null;
        if ($tableColsCache === null) {
            $cols = $db->fetchAll("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'stalls'") ?: [];
            $tableColsCache = array_map(fn($r) => $r['COLUMN_NAME'], $cols);
        }

        $found = array_values(array_intersect($candidates, $tableColsCache));
        if (!empty($found)) {
            $selectParts = array_map(fn($c) => "s.`$c`", $found);
            $sql = "SELECT COALESCE(" . implode(',', $selectParts) . ") AS vendor_user_id FROM stalls s WHERE s.stall_id = ? LIMIT 1";
            $r = $db->fetch($sql, [$stall_id]);
            if ($r && !empty($r['vendor_user_id'])) return (int)$r['vendor_user_id'];
        }

        $leaseCols = $db->fetchAll("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'leases'") ?: [];
        $leaseColNames = array_map(fn($r) => $r['COLUMN_NAME'], $leaseCols);
        if (in_array('user_id', $leaseColNames, true) && in_array('stall_id', $leaseColNames, true)) {
            $lease = $db->fetch("SELECT user_id FROM leases WHERE stall_id = ? ORDER BY created_at DESC LIMIT 1", [$stall_id]);
            if ($lease && !empty($lease['user_id'])) return (int)$lease['user_id'];
        }

    } catch (Throwable $e) {
        error_log("getStallOwnerUserId error for stall {$stall_id}: " . $e->getMessage());
    }
    return null;
}

/**
 * Returns true if the given user has at least one approved 'id' OR an approved 'permit'
 */
function userHasApprovedIdOrPermit($db, int $user_id): bool {
    if (!$db || $user_id <= 0) return false;
    try {
        $r1 = $db->fetch(
            "SELECT COUNT(*) AS c FROM identity_documents WHERE user_id = ? AND status = 'approved' AND LOWER(doc_type) IN ('id','permit')",
            [$user_id]
        );
        if (!empty($r1['c'])) return true;

        $r2 = $db->fetch(
            "SELECT COUNT(*) AS c
             FROM user_role_documents urd
             JOIN user_roles ur ON urd.user_role_id = ur.user_role_id
             WHERE ur.user_id = ? AND urd.status = 'approved' AND LOWER(urd.doc_type) IN ('id','permit')",
            [$user_id]
        );
        if (!empty($r2['c'])) return true;
    } catch (Throwable $e) {
        error_log("userHasApprovedIdOrPermit error for user {$user_id}: ".$e->getMessage());
    }
    return false;
}

/* ---------------------- Completion action (server authoritative) ---------------------- */
/*
 Allow completion by:
  - The assigned inspector (if they are the logged user), or
  - A market manager/accountant/admin for inspections in their managed markets (marketIds)
 Require: performing user must be verified (userHasApprovedIdOrPermit) to complete.
*/
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['complete_inspection'])) {
    if (!csrf_validate_request()) {
        $_SESSION['error_message'] = 'Invalid CSRF token.';
        redirect('manage_inspections.php?tab=scheduled');
    }
    // Only users with appropriate roles may attempt completion
    if (!($is_inspector || $is_market_manager || $is_accountant || isAdmin())) {
        $_SESSION['error_message'] = 'Forbidden';
        redirect('manage_inspections.php?tab=scheduled');
    }

    $inspection_id = (int)($_POST['inspection_id'] ?? 0);
    $outcome       = strtolower(trim(sanitize($_POST['outcome'] ?? 'ok')));
    $notes_add     = trim($_POST['notes_add'] ?? '');
    $allowed_outcomes = ['ok','minor_issue','major_issue','follow_up_required','pending'];
    if (!in_array($outcome, $allowed_outcomes, true)) $outcome = 'ok';

    if ($inspection_id > 0) {
        try {
            $row = $db->fetch("SELECT inspection_id, inspector_id, status, stall_id, market_id FROM inspections WHERE inspection_id = ? LIMIT 1", [$inspection_id]);
            if (!$row) {
                $_SESSION['error_message'] = 'Inspection not found.';
                redirect('manage_inspections.php?tab=scheduled');
            }

            $statusLower = strtolower($row['status'] ?? '');
            // Determine whether current user may perform completion on this inspection
            $actorCanComplete = false;
            if ($is_inspector && (int)$row['inspector_id'] === $uid) {
                $actorCanComplete = true;
            } elseif ($is_market_manager || $is_accountant) {
                // market manager/accountant may complete only for inspections in their managed markets
                if (empty($marketIds) || in_array((int)$row['market_id'], $marketIds, true)) {
                    $actorCanComplete = true;
                }
            } elseif (isAdmin()) {
                $actorCanComplete = true;
            }

            if (!$actorCanComplete) {
                $_SESSION['error_message'] = 'You are not assigned to that inspection or do not have permission to complete it.';
                redirect('manage_inspections.php?tab=scheduled');
            }

            if (!in_array($statusLower, ['scheduled','pending'], true)) {
                $_SESSION['error_message'] = 'Inspection is not in a schedulable state.';
                redirect('manage_inspections.php?tab=scheduled');
            }

            // Enforce verification: the user performing the action must have at least one approved id OR permit
            $performer_verified = userHasApprovedIdOrPermit($db, $uid);
            if (!$performer_verified) {
                try {
                  if (function_exists('createNotification')) {
                    createNotification($db, $uid, 'Document verification required',
                      'You attempted to complete an inspection but you need at least one approved ID or Permit. Visit Account Settings → Document Verification to upload your documents.',
                      'info', 'verification_required', $inspection_id, 'inspections');
                  }
                } catch (Throwable $e) {
                  error_log("manage_inspections: createNotification failed for user {$uid}: ".$e->getMessage());
                }
                $_SESSION['error_message'] = 'Cannot complete inspection: you are not verified. You need at least one approved ID or Permit to perform this action.';
                redirect('manage_inspections.php?tab=scheduled');
            }

            // All checks passed — update inspection as completed
            $db->query("
                UPDATE inspections
                   SET inspected_at = NOW(),
                       outcome = ?,
                       status = 'completed',
                       notes = CONCAT(COALESCE(notes,''), ?),
                       updated_at = NOW()
                 WHERE inspection_id = ?
            ", [
                $outcome,
                ($notes_add !== '' ? ("\n[Inspector Notes] ".$notes_add) : ''),
                $inspection_id
            ]);

            // Notify market managers on significant outcomes
            if (in_array($outcome, ['major_issue','follow_up_required'], true)) {
                try {
                    $info = $db->fetch("
                        SELECT i.market_id, i.stall_id, s.stall_number
                          FROM inspections i
                          JOIN stalls s ON i.stall_id = s.stall_id
                         WHERE i.inspection_id = ?
                         LIMIT 1
                    ", [$inspection_id]) ?: [];
                    $mAdmins = $db->fetchAll("SELECT user_id FROM market_managers WHERE market_id = ?", [(int)($info['market_id'] ?? 0)]) ?: [];
                    $msg = "Inspection #{$inspection_id} for stall ".($info['stall_number'] ?? '#'.$info['stall_id'])." completed with outcome '{$outcome}'.";
                    foreach ($mAdmins as $a) {
                        if (!empty($a['user_id']) && function_exists('createNotification')) {
                            createNotification($db, (int)$a['user_id'], 'Inspection Completed: Attention', $msg, 'warning', 'inspection', $inspection_id, 'inspections');
                        }
                    }
                } catch (Throwable $e) { error_log("manage_inspections: notify failed: ".$e->getMessage()); }
            }

            logAudit($db, $uid, 'Complete Inspection', 'inspections', $inspection_id, null, $outcome);
            $_SESSION['success_message'] = 'Inspection marked as completed.';
        } catch (Throwable $e) {
            error_log("manage_inspections: complete failed: ".$e->getMessage());
            $_SESSION['error_message'] = 'Failed to complete inspection.';
        }
    }
    redirect('manage_inspections.php?tab=scheduled');
}

/* ---------------------- Scope check ---------------------- */
if ($filter_market > 0 && !empty($marketIds) && !in_array($filter_market, $marketIds, true) && !isAdmin()) {
    http_response_code(403);
    echo "Forbidden: you do not have access to that market.";
    exit;
}

/* ---------------------- Query builders ---------------------- */
function buildInspectionBaseWhere(&$sql, &$params, $marketIds, $filter_market, $filter_outcome, $search) {
    if (!empty($marketIds)) {
        $ph = implode(',', array_fill(0, count($marketIds), '?'));
        $sql .= " AND i.market_id IN ($ph)";
        foreach ($marketIds as $mid) $params[] = $mid;
    }
    if ($filter_market > 0) {
        $sql .= " AND i.market_id = ?";
        $params[] = $filter_market;
    }
    if ($filter_outcome !== '') {
        $sql .= " AND i.outcome = ?";
        $params[] = $filter_outcome;
    }
    if ($search !== '') {
        $like = "%{$search}%";
        $sql .= " AND (s.stall_number LIKE ? OR u.full_name LIKE ? OR m.market_name LIKE ? OR i.notes LIKE ?)";
        $params[] = $like; $params[] = $like; $params[] = $like; $params[] = $like;
    }
}

/* ---------------------- Fetch rows ---------------------- */
// Scheduled / pending query
$scheduled_rows = [];
try {
    $sqlScheduled = "
        SELECT i.inspection_id, i.stall_id, i.market_id, i.inspector_id,
               i.inspected_at, i.outcome, i.status AS inspection_status, i.notes,
               u.full_name AS inspector_name, s.stall_number, m.market_name
          FROM inspections i
          JOIN users u ON i.inspector_id = u.user_id
          JOIN stalls s ON i.stall_id = s.stall_id
          JOIN markets m ON i.market_id = m.market_id
         WHERE i.status IN ('scheduled','pending')
    ";
    $paramsScheduled = [];
    buildInspectionBaseWhere($sqlScheduled, $paramsScheduled, $marketIds, $filter_market, $filter_outcome, $search);

    if ($is_inspector && $scheduled_only && $active_tab === 'scheduled') {
        $sqlScheduled .= " AND i.inspector_id = ?";
        $paramsScheduled[] = $uid;
    }

    $sqlScheduled .= "
        ORDER BY
            CASE WHEN i.status='scheduled' THEN 0 ELSE 1 END,
            i.inspected_at DESC,
            i.updated_at DESC
        LIMIT 500
    ";
    $scheduled_rows = $db->fetchAll($sqlScheduled, $paramsScheduled) ?: [];
} catch (Throwable $e) {
    error_log("manage_inspections: scheduled query failed: ".$e->getMessage());
    $scheduled_rows = [];
}

// Completed query
$completed_rows = [];
try {
    $sqlCompleted = "
        SELECT i.inspection_id, i.stall_id, i.market_id, i.inspector_id,
               i.inspected_at, i.outcome, i.status AS inspection_status, i.notes,
               u.full_name AS inspector_name, s.stall_number, m.market_name
          FROM inspections i
          JOIN users u ON i.inspector_id = u.user_id
          JOIN stalls s ON i.stall_id = s.stall_id
          JOIN markets m ON i.market_id = m.market_id
         WHERE i.status = 'completed'
    ";
    $paramsCompleted = [];
    buildInspectionBaseWhere($sqlCompleted, $paramsCompleted, $marketIds, $filter_market, $filter_outcome, $search);

    $sqlCompleted .= "
        ORDER BY i.inspected_at DESC, i.updated_at DESC
        LIMIT 500
    ";
    $completed_rows = $db->fetchAll($sqlCompleted, $paramsCompleted) ?: [];
} catch (Throwable $e) {
    error_log("manage_inspections: completed query failed: ".$e->getMessage());
    $completed_rows = [];
}

/* ---------------------- Badge count for scheduled tab ---------------------- */
$scheduled_badge_count = 0;
try {
    $badge_sql = "SELECT COUNT(*) AS cnt FROM inspections i WHERE i.status IN ('scheduled','pending')";
    $badge_params = [];
    if (!empty($marketIds)) {
        $ph = implode(',', array_fill(0, count($marketIds), '?'));
        $badge_sql .= " AND i.market_id IN ($ph)";
        foreach ($marketIds as $mid) $badge_params[] = $mid;
    }
    if ($filter_market > 0) {
        $badge_sql .= " AND i.market_id = ?";
        $badge_params[] = $filter_market;
    }
    if ($is_inspector && $scheduled_only) {
        $badge_sql .= " AND i.inspector_id = ?";
        $badge_params[] = $uid;
    }
    $rowBadge = $db->fetch($badge_sql, $badge_params) ?: [];
    $scheduled_badge_count = (int)($rowBadge['cnt'] ?? 0);
} catch (Throwable $e) {
    error_log("manage_inspections: badge count failed: ".$e->getMessage());
    $scheduled_badge_count = 0;
}

/* ---------------------- Markets list ---------------------- */
try {
    if (isAdmin()) {
        $markets = $db->fetchAll("SELECT market_id, market_name FROM markets WHERE status='active' ORDER BY market_name") ?: [];
    } else {
        if (empty($marketIds)) {
            $markets = [];
        } else {
            $ph = implode(',', array_fill(0, count($marketIds), '?'));
            $markets = $db->fetchAll(
                "SELECT market_id, market_name FROM markets WHERE market_id IN ($ph) AND status='active' ORDER BY market_name",
                $marketIds
            ) ?: [];
        }
    }
} catch (Throwable $e) {
    error_log("manage_inspections: markets fetch failed: ".$e->getMessage());
    $markets = [];
}

/* ---------------------- Render ---------------------- */
logAudit($db, $uid, 'View Inspections (Two Tabs + Badge)', 'inspections', null, null, null);

require_once 'includes/header.php';
require_once 'includes/admin_sidebar.php';
?>
<section class="max-w-7xl mx-auto p-6">
  <div class="mb-6 flex items-center justify-between">
    <div>
      <p class="text-gray-600">Scheduled vs Completed inspections (use tabs). Filters apply to both.</p>
    </div>
  </div>

  <?php if (!empty($_SESSION['error_message'])): ?>
    <div class="bg-red-100 border border-red-300 text-red-700 px-4 py-2 rounded mb-4">
      <?php echo htmlspecialchars($_SESSION['error_message']); unset($_SESSION['error_message']); ?>
    </div>
  <?php endif; ?>
  <?php if (!empty($_SESSION['success_message'])): ?>
    <div class="bg-green-100 border border-green-300 text-green-700 px-4 py-2 rounded mb-4">
      <?php echo htmlspecialchars($_SESSION['success_message']); unset($_SESSION['success_message']); ?>
    </div>
  <?php endif; ?>

  <?php if (($is_inspector || $is_market_manager || $is_accountant) && !$user_verified): ?>
  <div class="mb-4 p-4 rounded border-l-4 border-amber-400 bg-amber-50 text-amber-800">
    <div class="flex items-start justify-between">
      <div>
        <strong class="block">Document verification required</strong>
        <div class="text-sm">
          You need at least one approved Government ID or an approved Permit to complete inspections.
          Please upload your documents and wait for admin approval.
        </div>
      </div>
      <div class="ml-4 flex-shrink-0">
        <a href="settings.php#documentsSection"
           class="inline-block bg-amber-600 text-white px-3 py-1 rounded text-sm">Verify Documents</a>
      </div>
    </div>
  </div>
  <?php endif; ?>

  <!-- Tabs -->
  <div class="flex flex-wrap gap-2 mb-4">
    <a href="manage_inspections.php?tab=scheduled<?php
       $qs = [];
       foreach (['market_id','outcome','search','scheduled_only'] as $k){
         if (isset($_GET[$k]) && $_GET[$k] !== '') $qs[$k] = $_GET[$k];
       }
       echo !empty($qs)?'&'.http_build_query($qs):''; ?>"
       class="relative px-4 py-2 rounded-md font-medium <?php echo $active_tab==='scheduled'?'bg-blue-600 text-white':'bg-gray-100 text-gray-700 hover:bg-gray-200'; ?>">
       Scheduled
       <?php if ($scheduled_badge_count > 0): ?>
         <span class="absolute -top-2 -right-2 bg-red-600 text-white text-xs font-bold rounded-full px-2 py-0.5 shadow">
           <?php echo (int)$scheduled_badge_count; ?>
         </span>
       <?php endif; ?>
    </a>
    <a href="manage_inspections.php?tab=completed<?php
       $qs = [];
       foreach (['market_id','outcome','search'] as $k){
         if (isset($_GET[$k]) && $_GET[$k] !== '') $qs[$k] = $_GET[$k];
       }
       echo !empty($qs)?'&'.http_build_query($qs):''; ?>"
       class="px-4 py-2 rounded-md font-medium <?php echo $active_tab==='completed'?'bg-blue-600 text-white':'bg-gray-100 text-gray-700 hover:bg-gray-200'; ?>">
       Completed
    </a>
  </div>

  <!-- Filters -->
  <div class="bg-white rounded-lg shadow-md p-6 mb-6">
    <form method="GET" class="flex flex-wrap gap-4 items-end">
      <input type="hidden" name="tab" value="<?php echo htmlspecialchars($active_tab); ?>">
      <div>
        <label class="block text-sm text-gray-600 mb-1">Market</label>
        <select name="market_id" class="px-3 py-2 border rounded">
          <option value="0">All</option>
          <?php foreach ($markets as $m): ?>
            <option value="<?php echo (int)$m['market_id']; ?>" <?php echo ($filter_market == $m['market_id']) ? 'selected' : ''; ?>>
              <?php echo htmlspecialchars($m['market_name']); ?>
            </option>
          <?php endforeach; ?>
        </select>
      </div>
      <div>
        <label class="block text-sm text-gray-600 mb-1">Outcome</label>
        <select name="outcome" class="px-3 py-2 border rounded">
          <option value="">All</option>
          <option value="ok" <?php echo $filter_outcome === 'ok' ? 'selected' : ''; ?>>OK</option>
          <option value="minor_issue" <?php echo $filter_outcome === 'minor_issue' ? 'selected' : ''; ?>>Minor Issue</option>
          <option value="major_issue" <?php echo $filter_outcome === 'major_issue' ? 'selected' : ''; ?>>Major Issue</option>
          <option value="pending" <?php echo $filter_outcome === 'pending' ? 'selected' : ''; ?>>Pending</option>
        </select>
      </div>
      <div class="flex-1 min-w-[200px]">
        <label class="block text-sm text-gray-600 mb-1">Search</label>
        <input type="text" name="search" value="<?php echo htmlspecialchars($search); ?>"
               placeholder="stall, inspector, market, notes..." class="px-3 py-2 border rounded w-full">
      </div>
      <?php if ($is_inspector && $active_tab === 'scheduled'): ?>
      <div class="flex items-center mt-1">
        <label class="flex items-center text-sm text-gray-600">
          <input type="checkbox" name="scheduled_only" value="1" <?php echo $scheduled_only?'checked':''; ?> class="mr-1">
          Only my scheduled
        </label>
      </div>
      <?php endif; ?>
      <div>
        <button type="submit" class="bg-blue-600 text-white px-4 py-2 rounded">Apply</button>
        <a href="manage_inspections.php?tab=<?php echo htmlspecialchars($active_tab); ?>" class="ml-2 px-3 py-2 border rounded text-sm">Reset</a>
      </div>
    </form>
  </div>

  <?php
    $rows = ($active_tab === 'scheduled') ? $scheduled_rows : $completed_rows;
    $emptyMsg = ($active_tab === 'scheduled') ? 'No scheduled inspections found.' : 'No completed inspections found.';
  ?>

  <div class="bg-white rounded shadow overflow-x-auto">
    <table class="w-full text-sm">
      <thead class="bg-gray-50 text-left">
        <tr>
          <th class="p-3">Status</th>
          <th class="p-3">Date</th>
          <th class="p-3">Market</th>
          <th class="p-3">Stall</th>
          <th class="p-3">Inspector</th>
          <th class="p-3">Outcome</th>
          <th class="p-3">Notes</th>
          <th class="p-3">Actions</th>
        </tr>
      </thead>
      <tbody>
        <?php if (empty($rows)): ?>
          <tr><td colspan="8" class="p-6 text-center text-gray-500"><?php echo htmlspecialchars($emptyMsg); ?></td></tr>
        <?php else: foreach ($rows as $i):
          $status = strtolower($i['inspection_status'] ?? '');
          $isAssignedInspector = $is_inspector && (int)$i['inspector_id'] === $uid;
          $badgeCls = match($status) {
            'scheduled','pending' => 'bg-yellow-100 text-yellow-800',
            'completed'           => 'bg-green-100 text-green-700',
            default               => 'bg-gray-100 text-gray-700'
          };
          $when = '-';
          if (!empty($i['inspected_at'])) {
              $ts = strtotime($i['inspected_at']);
              $when = in_array($status, ['scheduled','pending'], true)
                  ? ('Scheduled for '.date('M j, Y', $ts))
                  : date('M j, Y H:i', $ts);
          } else {
              $when = in_array($status, ['scheduled','pending'], true) ? 'Scheduled' : '-';
          }
          $outcomeDisplay = in_array($status, ['scheduled','pending'], true) ? '—' : ($i['outcome'] ?? '—');

          // Determine if the current user can Complete this specific inspection:
          // - assigned inspector may complete their own scheduled inspections
          // - market manager/accountant may complete inspections in their managed markets
          $canComplete = false;
          if ($active_tab === 'scheduled' && in_array($status, ['scheduled','pending'], true)) {
              if ($isAssignedInspector) $canComplete = true;
              if (($is_market_manager || $is_accountant) && (!empty($marketIds) ? in_array((int)$i['market_id'], $marketIds, true) : true)) $canComplete = true;
              if (isAdmin()) $canComplete = true;
          }
        ?>
        <tr class="border-t <?php echo in_array($status,['scheduled','pending'])?'bg-yellow-50':''; ?>">
          <td class="p-3">
            <span class="px-2 py-1 rounded text-xs font-semibold <?php echo $badgeCls; ?>">
              <?php echo ucfirst($status === 'pending' ? 'Scheduled' : $status); ?>
            </span>
          </td>
          <td class="p-3"><?php echo htmlspecialchars($when); ?></td>
          <td class="p-3"><?php echo htmlspecialchars($i['market_name'] ?? ''); ?></td>
          <td class="p-3"><?php echo htmlspecialchars($i['stall_number'] ?? ''); ?></td>
          <td class="p-3"><?php echo htmlspecialchars($i['inspector_name'] ?? ''); ?></td>
          <td class="p-3"><?php echo htmlspecialchars($outcomeDisplay); ?></td>
          <td class="p-3"><?php echo htmlspecialchars(mb_strimwidth($i['notes'] ?? '', 0, 120, '…')); ?></td>
          <td class="p-3">
            <div class="flex flex-wrap gap-2">
              <button type="button"
                      class="text-blue-600 hover:underline view-btn"
                      data-id="<?php echo (int)$i['inspection_id']; ?>"
                      data-row="<?php echo htmlspecialchars(json_encode($i), ENT_QUOTES); ?>"
                      onclick="viewInspection(<?php echo (int)$i['inspection_id']; ?>)">
                View
              </button>
              <?php if ($canComplete): ?>
                <?php if (!$user_verified): ?>
                  <span class="text-gray-400 text-xs italic" title="User not verified: approve at least one ID or permit first.">
                    Complete (blocked: not verified)
                  </span>
                <?php else: ?>
                  <button type="button"
                          onclick="openCompleteModal(<?php echo (int)$i['inspection_id']; ?>)"
                          class="text-green-600 hover:underline">
                    Complete
                  </button>
                <?php endif; ?>
              <?php endif; ?>
            </div>
          </td>
        </tr>
        <?php endforeach; endif; ?>
      </tbody>
    </table>
  </div>

  <?php
    // Determine whether to render the complete modal for this user (anyone who might perform a completion)
    $canPerformCompletesGlobally = ($is_inspector || $is_market_manager || $is_accountant || isAdmin());
  ?>
  <?php if ($canPerformCompletesGlobally): ?>
  <div id="completeModal" class="hidden fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
    <div class="bg-white rounded-lg max-w-md w-full">
      <div class="p-4 border-b flex items-center justify-between">
        <h3 class="text-lg font-semibold">Complete Inspection</h3>
        <button onclick="closeCompleteModal()" class="text-gray-600">✕</button>
      </div>
      <form method="POST" action="" class="p-4 space-y-4">
        <?php echo csrf_field(); ?>
        <input type="hidden" name="inspection_id" id="complete_inspection_id">
        <div>
          <label class="block text-sm mb-1">Outcome *</label>
          <select name="outcome" class="w-full border px-3 py-2 rounded" required>
            <option value="ok">OK</option>
            <option value="minor_issue">Minor Issue</option>
            <option value="major_issue">Major Issue</option>
          </select>
        </div>
        <div>
          <label class="block text-sm mb-1">Additional Notes (optional)</label>
            <textarea name="notes_add" class="w-full border px-3 py-2 rounded" rows="4"></textarea>
          </div>
          <div class="flex gap-3">
            <?php if (!$user_verified): ?>
            <div class="p-2 bg-yellow-50 border rounded text-sm text-amber-800">
              You cannot mark inspections as complete until you have at least one approved ID or Permit.
              <a href="settings.php#documentsSection" class="underline ml-1">Go to Document Verification</a>
            </div>
            <button type="button" disabled class="bg-gray-300 text-gray-600 px-4 py-2 rounded cursor-not-allowed mt-2">Mark Complete</button>
            <?php else: ?>
            <button type="submit" name="complete_inspection" class="bg-green-600 text-white px-4 py-2 rounded">Mark Complete</button>
            <?php endif; ?>
            <button type="button" onclick="closeCompleteModal()" class="bg-gray-300 px-4 py-2 rounded">Cancel</button>
          </div>
      </form>
    </div>
  </div>
  <?php endif; ?>

  <div id="inspectionModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
    <div class="bg-white rounded-lg max-w-3xl w-full max-h-[90vh] overflow-auto">
      <div class="p-4 border-b flex items-center justify-between">
        <h3 id="inspectionModalTitle" class="text-lg font-semibold">Inspection</h3>
        <button onclick="closeInspectionModal()" class="text-gray-600">✕</button>
      </div>
      <div id="inspectionModalBody" class="p-4">
        <p class="text-sm text-gray-600">Loading…</p>
      </div>
      <div class="p-4 border-t text-right">
        <button onclick="closeInspectionModal()" class="px-4 py-2 bg-gray-200 rounded">Close</button>
      </div>
    </div>
  </div>
</section>

<script>
function escapeHtml(s){
  return String(s||'').replace(/&/g,'&amp;')
                      .replace(/</g,'&lt;')
                      .replace(/>/g,'&gt;')
                      .replace(/"/g,'&quot;')
                      .replace(/'/g,'&#39;');
}
function viewInspection(id){
  const modal = document.getElementById('inspectionModal');
  const body  = document.getElementById('inspectionModalBody');
  document.getElementById('inspectionModalTitle').textContent = 'Inspection #' + id;
  body.innerHTML = '<div class="p-6 text-center text-gray-600">Loading…</div>';
  modal.classList.remove('hidden');

  fetch('API/inspections.php?inspection_id=' + encodeURIComponent(id) + '&compact=1', {credentials:'same-origin'})
    .then(async r => {
      const text = await r.text();
      try {
        const j = JSON.parse(text);
        let ins = (j.inspection || (j.inspections && j.inspections[0])) || j || null;

        // Fallback to data embedded in the table row if API didn't return details
        if (!ins || (!ins.market_name && !ins.stall_number && !ins.inspector_name)) {
          const btn = document.querySelector('button.view-btn[data-id="'+id+'"]');
          if (btn && btn.dataset && btn.dataset.row) {
            try {
              const fallback = JSON.parse(btn.dataset.row);
              ins = Object.assign({}, fallback, ins || {});
            } catch (e) {
              // ignore parsing errors
            }
          }
        }

        if (!ins){
          body.innerHTML = '<div class="text-red-600">Inspection details unavailable.</div>';
          return;
        }

        let status = (ins.status || ins.inspection_status || '').toLowerCase();
        let dateText = '-';
        if (ins.inspected_at) {
          const d = new Date(ins.inspected_at.replace(' ', 'T'));
          dateText = (status === 'scheduled' || status === 'pending')
            ? 'Scheduled for ' + d.toLocaleDateString()
            : d.toLocaleString();
        } else {
          dateText = (status === 'scheduled' || status === 'pending') ? 'Scheduled' : '-';
        }
        const outcomeDisplay = (status === 'scheduled' || status === 'pending') ? '—' : (ins.outcome || '—');
        let html = '<div class="space-y-2">';
        html += '<div><strong>Status:</strong> '+escapeHtml(ins.status || ins.inspection_status || '')+'</div>';
        html += '<div><strong>Date:</strong> '+escapeHtml(dateText)+'</div>';
        html += '<div><strong>Market:</strong> '+escapeHtml(ins.market_name || '')+'</div>';
        html += '<div><strong>Stall:</strong> '+escapeHtml(ins.stall_number || '')+'</div>';
        html += '<div><strong>Inspector:</strong> '+escapeHtml(ins.inspector_name || '')+'</div>';
        html += '<div><strong>Outcome:</strong> '+escapeHtml(outcomeDisplay)+'</div>';
        html += '<div><strong>Notes:</strong><div class="mt-1 p-2 bg-gray-50 rounded text-xs whitespace-pre-line">'+escapeHtml(ins.notes || '')+'</div></div>';
        html += '<div id="inspectionPhotos" class="mt-3"></div>';
        html += '</div>';
        body.innerHTML = html;

        // Fetch photos separately; ignore if fails
        fetch('API/inspections.php?inspection_id=' + encodeURIComponent(id) + '&include_photos=1', {credentials:'same-origin'})
          .then(r => r.ok ? r.json() : null)
          .then(j2 => {
            const photos = (j2 && j2.photos) || [];
            if (photos.length){
              const phDiv = document.getElementById('inspectionPhotos');
              phDiv.innerHTML = '<strong>Photos:</strong><div class="mt-2 flex flex-wrap gap-2">';
              photos.forEach(p => {
                phDiv.innerHTML += '<a href="'+escapeHtml(p.storage_url)+'" target="_blank" class="block border rounded overflow-hidden"><img src="'+escapeHtml(p.storage_url)+'" alt="" class="h-24 object-cover"></a>';
              });
              phDiv.innerHTML += '</div>';
            }
          })
          .catch(()=>{});
      } catch (e) {
        body.innerHTML = '<div class="text-red-600 p-4 text-xs whitespace-pre-wrap">Failed to load inspection.\nRaw response:\n\n' + escapeHtml(text.slice(0, 800)) + '</div>';
      }
    })
    .catch(err => {
      body.innerHTML = '<div class="text-red-600 p-4">Failed to load inspection: '+escapeHtml(err.message||'')+'</div>';
    });
}

function closeInspectionModal(){
  document.getElementById('inspectionModal').classList.add('hidden');
}
function openCompleteModal(id){
  const m = document.getElementById('completeModal');
  if(!m) return;
  document.getElementById('complete_inspection_id').value = id;
  m.classList.remove('hidden');
}
function closeCompleteModal(){
  const m = document.getElementById('completeModal');
  if(m) m.classList.add('hidden');
  const idEl = document.getElementById('complete_inspection_id');
  if(idEl) idEl.value='';
}

document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){ closeInspectionModal(); closeCompleteModal(); }
});
document.addEventListener('click',e=>{
  const modal=document.getElementById('inspectionModal');
  if(modal && !modal.classList.contains('hidden') && e.target===modal){
    closeInspectionModal();
  }
  const cModal=document.getElementById('completeModal');
  if(cModal && !cModal.classList.contains('hidden') && e.target===cModal){
    closeCompleteModal();
  }
});
</script>

<?php include 'includes/footer.php'; ?>