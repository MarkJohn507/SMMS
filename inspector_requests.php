<?php
// inspector_requests.php
// Inspector-only dashboard for viewing & acting on inspection requests (scheduled / pre-lease / renewal / complaint)

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/csrf.php';
require_once 'includes/inspector_utils.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

// require login
if (!isLoggedIn()) {
    $_SESSION['intended_url'] = $_SERVER['REQUEST_URI'] ?? '/';
    redirect('login.php?timeout=1');
}

$uid = $_SESSION['user_id'] ?? null;
if (!$uid) redirect('login.php');

// allow inspectors and admin-like roles (admins can see everything)
// IMPORTANT: super_admin should NOT imply full access unless your policy allows it. We'll detect admin/status via helpers.
$is_admin_like = isAdmin();
$is_super_admin = false;
try {
    if (function_exists('_fetchUserRoleNames')) {
        $roles = array_map('strtolower', _fetchUserRoleNames($uid, $db) ?: []);
        $is_super_admin = in_array('super_admin', $roles, true);
    } else {
        $roles = array_map('strtolower', (array)($_SESSION['roles'] ?? []));
        $is_super_admin = in_array('super_admin', $roles, true);
    }
} catch (Throwable $e) { $is_super_admin = false; }

// Inspectors
$is_inspector = isInspector($db, $uid);

// Access: inspector OR admin-like. If you want to block super_admin, set $is_admin_like = false when super_admin.
if (!($is_inspector || $is_admin_like)) {
    http_response_code(403);
    echo "Forbidden";
    exit;
}

$page_title = 'Inspection Requests';
$errors = [];
$success = '';

// Handle POST actions: assign to self, mark as in_progress/completed/decline
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_validate_request()) {
        $errors[] = 'Invalid CSRF token.';
    } else {
        $action = sanitize($_POST['action'] ?? '');
        $request_id = isset($_POST['request_id']) ? (int)$_POST['request_id'] : 0;

        if ($request_id <= 0) {
            $errors[] = 'Invalid request id.';
        } else {
            try {
                $req = $db->fetch("SELECT * FROM inspection_requests WHERE request_id = ? LIMIT 1", [$request_id]);
                if (!$req) {
                    $errors[] = 'Request not found.';
                } else {
                    // For non-admin inspectors, ensure request is in their market scope
                    if (!$is_admin_like) {
                        $allowedMarkets = getInspectorMarketIds($db, $uid);
                        if (!empty($req['market_id']) && !in_array((int)$req['market_id'], $allowedMarkets, true)) {
                            http_response_code(403);
                            $errors[] = 'Forbidden: you are not assigned to this market.';
                        }
                    }

                    if (empty($errors)) {
                        $status = strtolower($req['status'] ?? '');
                        if ($action === 'assign_to_self') {
                            // Only open or declined requests can be assigned
                            if (!in_array($status, ['open','declined'], true)) {
                                $errors[] = 'Only open/declined requests can be assigned.';
                            } else {
                                $ok = $db->query("UPDATE inspection_requests SET assigned_inspector_id = ?, status = 'assigned', updated_at = NOW() WHERE request_id = ?", [$uid, $request_id]);
                                if ($ok) {
                                    logAudit($db, $uid, 'Assigned Inspection Request', 'inspection_requests', $request_id, null, null);
                                    // Notify requestor (best-effort)
                                    if (function_exists('createNotification') && !empty($req['requestor_id'])) {
                                        $title = "Inspection request #{$request_id} assigned";
                                        $insName = $_SESSION['full_name'] ?? $_SESSION['username'] ?? ('Inspector '.$uid);
                                        $msg = "Inspector {$insName} has been assigned to your inspection request.";
                                        try { createNotification($db, (int)$req['requestor_id'], $title, $msg, 'info', 'inspection_request', $request_id, 'inspection_requests'); } catch (Throwable $e) {}
                                    }
                                    $success = 'Request assigned to you.';
                                } else {
                                    $errors[] = 'Failed to assign request.';
                                }
                            }
                        } elseif ($action === 'start') {
                            if ((int)$req['assigned_inspector_id'] !== (int)$uid && !$is_admin_like) {
                                $errors[] = 'Only the assigned inspector can start this request.';
                            } elseif (!in_array($status, ['assigned','open'], true)) {
                                $errors[] = 'Only assigned/open requests can be started.';
                            } else {
                                $ok = $db->query("UPDATE inspection_requests SET status = 'in_progress', updated_at = NOW() WHERE request_id = ?", [$request_id]);
                                if ($ok) {
                                    logAudit($db, $uid, 'Started Inspection', 'inspection_requests', $request_id, null, null);
                                    $success = 'Inspection started.';
                                } else {
                                    $errors[] = 'Failed to mark as in progress.';
                                }
                            }
                        } elseif ($action === 'complete') {
                            if ((int)$req['assigned_inspector_id'] !== (int)$uid && !$is_admin_like) {
                                $errors[] = 'Only the assigned inspector can complete this request.';
                            } elseif (!in_array($status, ['in_progress','assigned','open'], true)) {
                                $errors[] = 'Only active requests can be completed.';
                            } else {
                                $ok = $db->query("UPDATE inspection_requests SET status = 'completed', updated_at = NOW() WHERE request_id = ?", [$request_id]);
                                if ($ok) {
                                    logAudit($db, $uid, 'Completed Inspection Request', 'inspection_requests', $request_id, null, null);
                                    if (function_exists('createNotification') && !empty($req['requestor_id'])) {
                                        $title = "Inspection request #{$request_id} completed";
                                        $insName = $_SESSION['full_name'] ?? $_SESSION['username'] ?? ('Inspector '.$uid);
                                        $msg = "Your inspection request has been completed by {$insName}.";
                                        try { createNotification($db, (int)$req['requestor_id'], $title, $msg, 'success', 'inspection_request', $request_id, 'inspection_requests'); } catch (Throwable $e) {}
                                    }
                                    $success = 'Inspection marked completed.';
                                } else {
                                    $errors[] = 'Failed to mark completed.';
                                }
                            }
                        } elseif ($action === 'decline') {
                            $reason = sanitize($_POST['decline_reason'] ?? '');
                            if ((int)$req['assigned_inspector_id'] !== (int)$uid && !$is_admin_like) {
                                $errors[] = 'Only the assigned inspector can decline this request.';
                            } elseif (empty($reason)) {
                                $errors[] = 'Please provide a reason for decline.';
                            } else {
                                $ok = $db->query("UPDATE inspection_requests SET status = 'declined', notes = CONCAT(IFNULL(notes,''), '\n\nDecline reason: ', ?), updated_at = NOW() WHERE request_id = ?", [$reason, $request_id]);
                                if ($ok) {
                                    logAudit($db, $uid, 'Declined Inspection Request', 'inspection_requests', $request_id, null, null);
                                    if (function_exists('createNotification') && !empty($req['requestor_id'])) {
                                        $title = "Inspection request #{$request_id} declined";
                                        $insName = $_SESSION['full_name'] ?? $_SESSION['username'] ?? 'an inspector';
                                        $msg = "Your inspection request was declined by {$insName}. Reason: " . substr($reason, 0, 200);
                                        try { createNotification($db, (int)$req['requestor_id'], $title, $msg, 'warning', 'inspection_request', $request_id, 'inspection_requests'); } catch (Throwable $e) {}
                                    }
                                    $success = 'Request declined.';
                                } else {
                                    $errors[] = 'Failed to decline request.';
                                }
                            }
                        } else {
                            $errors[] = 'Unknown action.';
                        }
                    }
                }
            } catch (Throwable $e) {
                error_log("inspector_requests: action error: " . $e->getMessage());
                $errors[] = 'Server error performing action.';
            }
        }
    }
}

// Filters
$filter_trigger   = sanitize($_GET['trigger'] ?? ''); // scheduled|pre_lease|renewal|complaint
$filter_requestor = sanitize($_GET['requestor'] ?? ''); // vendor|market_manager
$filter_status    = sanitize($_GET['status'] ?? 'open'); // default open
$filter_market    = isset($_GET['market_id']) ? (int)$_GET['market_id'] : 0;

// Build query scoped to inspector markets unless admin-like
$params = [];
$sql = "SELECT ir.*, u.full_name AS requestor_name, s.stall_number, m.market_name, insp.full_name AS assigned_inspector_name
        FROM inspection_requests ir
        LEFT JOIN users u ON ir.requestor_id = u.user_id
        LEFT JOIN stalls s ON ir.stall_id = s.stall_id
        LEFT JOIN markets m ON ir.market_id = m.market_id
        LEFT JOIN users insp ON ir.assigned_inspector_id = insp.user_id
        WHERE 1=1";

if (!$is_admin_like) {
    $allowed = getInspectorMarketIds($db, $uid);
    if (empty($allowed)) {
        $requests = [];
    } else {
        $ph = implode(',', array_fill(0, count($allowed), '?'));
        $sql .= " AND (ir.market_id IN ($ph) OR ir.market_id IS NULL)";
        foreach ($allowed as $a) $params[] = $a;
    }
}

if (!empty($filter_trigger))   { $sql .= " AND ir.trigger_type = ?";    $params[] = $filter_trigger; }
if (!empty($filter_requestor)) { $sql .= " AND ir.requestor_type = ?";  $params[] = $filter_requestor; }
if (!empty($filter_status))    { $sql .= " AND ir.status = ?";          $params[] = $filter_status; }
if ($filter_market > 0)        { $sql .= " AND ir.market_id = ?";       $params[] = $filter_market; }

$sql .= " ORDER BY FIELD(ir.status, 'open','assigned','in_progress','completed','declined'), ir.created_at DESC LIMIT 500";

try {
    if (!isset($requests)) $requests = $db->fetchAll($sql, $params) ?: [];
} catch (Throwable $e) {
    error_log("inspector_requests: fetch error: " . $e->getMessage());
    $requests = [];
}

// Markets for filter
try {
    if ($is_admin_like) {
        $markets = $db->fetchAll("SELECT market_id, market_name FROM markets WHERE status = 'active' ORDER BY market_name") ?: [];
    } else {
        $mids = getInspectorMarketIds($db, $uid);
        if (empty($mids)) $markets = [];
        else {
            $ph = implode(',', array_fill(0, count($mids), '?'));
            $markets = $db->fetchAll("SELECT market_id, market_name FROM markets WHERE market_id IN ($ph) AND status = 'active' ORDER BY market_name", $mids) ?: [];
        }
    }
} catch (Throwable $e) {
    $markets = [];
    error_log("inspector_requests: markets fetch failed: " . $e->getMessage());
}

require_once 'includes/header.php';
require_once 'includes/admin_sidebar.php';
?>
<section class="max-w-7xl mx-auto p-6">
  <div class="mb-6">
    <h3 class="text-2xl font-bold text-gray-800 mb-2">Inspection Requests</h3>
    <p class="text-gray-600">Requests submitted by vendors or market managers. Filter by trigger type or status.</p>
  </div>

  <?php if (!empty($errors)): ?>
    <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
      <?php foreach ($errors as $err): ?><div><?php echo htmlspecialchars($err); ?></div><?php endforeach; ?>
    </div>
  <?php endif; ?>
  <?php if ($success): ?>
    <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-4"><?php echo htmlspecialchars($success); ?></div>
  <?php endif; ?>

  <div class="bg-white rounded shadow p-4 mb-6">
    <form method="GET" action="" class="flex flex-wrap gap-3 items-end">
      <div>
        <label class="text-xs text-gray-600">Trigger</label>
        <select name="trigger" class="px-3 py-2 border rounded">
          <option value="">All</option>
          <option value="scheduled" <?php echo $filter_trigger === 'scheduled' ? 'selected' : ''; ?>>Scheduled</option>
          <option value="pre_lease" <?php echo $filter_trigger === 'pre_lease' ? 'selected' : ''; ?>>Pre-lease</option>
          <option value="renewal" <?php echo $filter_trigger === 'renewal' ? 'selected' : ''; ?>>Renewal</option>
          <option value="complaint" <?php echo $filter_trigger === 'complaint' ? 'selected' : ''; ?>>Complaint</option>
        </select>
      </div>

      <div>
        <label class="text-xs text-gray-600">Requestor</label>
        <select name="requestor" class="px-3 py-2 border rounded">
          <option value="">All</option>
          <option value="vendor" <?php echo $filter_requestor === 'vendor' ? 'selected' : ''; ?>>Vendor</option>
          <option value="market_manager" <?php echo $filter_requestor === 'market_manager' ? 'selected' : ''; ?>>Market Manager</option>
        </select>
      </div>

      <div>
        <label class="text-xs text-gray-600">Status</label>
        <select name="status" class="px-3 py-2 border rounded">
          <option value="">Any</option>
          <option value="open" <?php echo $filter_status === 'open' ? 'selected' : ''; ?>>Open</option>
          <option value="assigned" <?php echo $filter_status === 'assigned' ? 'selected' : ''; ?>>Assigned</option>
          <option value="in_progress" <?php echo $filter_status === 'in_progress' ? 'selected' : ''; ?>>In Progress</option>
          <option value="completed" <?php echo $filter_status === 'completed' ? 'selected' : ''; ?>>Completed</option>
          <option value="declined" <?php echo $filter_status === 'declined' ? 'selected' : ''; ?>>Declined</option>
        </select>
      </div>

      <div>
        <label class="text-xs text-gray-600">Market</label>
        <select name="market_id" class="px-3 py-2 border rounded">
          <option value="0">All</option>
          <?php foreach ($markets as $m): ?>
            <option value="<?php echo (int)$m['market_id']; ?>" <?php echo $filter_market === (int)$m['market_id'] ? 'selected' : ''; ?>><?php echo htmlspecialchars($m['market_name']); ?></option>
          <?php endforeach; ?>
        </select>
      </div>

      <div>
        <button type="submit" class="bg-blue-600 text-white px-4 py-2 rounded">Filter</button>
        <a href="inspector_requests.php" class="ml-2 text-sm text-gray-600">Reset</a>
      </div>
    </form>
  </div>

  <div class="bg-white rounded shadow overflow-auto">
    <table class="w-full text-sm">
      <thead class="bg-gray-50 text-left">
        <tr>
          <th class="p-3">Requested</th>
          <th class="p-3">Trigger</th>
          <th class="p-3">Requestor</th>
          <th class="p-3">Market / Stall</th>
          <th class="p-3">Priority</th>
          <th class="p-3">Status</th>
          <th class="p-3">Assigned</th>
          <th class="p-3">Actions</th>
        </tr>
      </thead>
      <tbody>
        <?php if (empty($requests)): ?>
          <tr><td colspan="8" class="p-6 text-center text-gray-500">No inspection requests</td></tr>
        <?php else: foreach ($requests as $r): ?>
          <tr class="border-t">
            <td class="p-3"><?php echo !empty($r['created_at']) ? date('M j, Y', strtotime($r['created_at'])) : '-'; ?></td>
            <td class="p-3">
              <?php echo htmlspecialchars($r['trigger_type']); ?>
              <?php if (!empty($r['preferred_date'])): ?>
                <div class="text-xs text-gray-500">Pref: <?php echo htmlspecialchars($r['preferred_date']); ?></div>
              <?php endif; ?>
            </td>
            <td class="p-3"><?php echo htmlspecialchars(ucfirst($r['requestor_type']) . ' — ' . ($r['requestor_name'] ?? $r['requestor_id'])); ?></td>
            <td class="p-3"><?php echo htmlspecialchars(($r['market_name'] ?? '-') . (!empty($r['stall_number']) ? ' / ' . $r['stall_number'] : '')); ?></td>
            <td class="p-3"><?php echo htmlspecialchars(ucfirst($r['priority'] ?? 'normal')); ?></td>
            <td class="p-3"><?php echo htmlspecialchars(ucfirst(str_replace('_',' ',$r['status']))); ?></td>
            <td class="p-3"><?php echo htmlspecialchars($r['assigned_inspector_name'] ?? '-'); ?></td>
            <td class="p-3">
              <div class="flex gap-2 flex-wrap">
                <?php if (in_array($r['status'], ['open','declined'], true)): ?>
                  <form method="POST" action="" class="inline-block">
                    <?php echo csrf_field(); ?>
                    <input type="hidden" name="request_id" value="<?php echo (int)$r['request_id']; ?>">
                    <input type="hidden" name="action" value="assign_to_self">
                    <button type="submit" class="px-2 py-1 bg-green-600 text-white rounded text-xs">Assign to me</button>
                  </form>
                <?php endif; ?>

                <?php if (in_array($r['status'], ['assigned','open'], true) && ((int)$r['assigned_inspector_id'] === (int)$uid || $is_admin_like)): ?>
                  <form method="POST" action="" class="inline-block">
                    <?php echo csrf_field(); ?>
                    <input type="hidden" name="request_id" value="<?php echo (int)$r['request_id']; ?>">
                    <input type="hidden" name="action" value="start">
                    <button type="submit" class="px-2 py-1 bg-yellow-500 text-white rounded text-xs">Start</button>
                  </form>
                <?php endif; ?>

                <?php if (in_array($r['status'], ['assigned','in_progress'], true) && ((int)$r['assigned_inspector_id'] === (int)$uid || $is_admin_like)): ?>
                  <form method="POST" action="" class="inline-block">
                    <?php echo csrf_field(); ?>
                    <input type="hidden" name="request_id" value="<?php echo (int)$r['request_id']; ?>">
                    <input type="hidden" name="action" value="complete">
                    <button type="submit" class="px-2 py-1 bg-blue-600 text-white rounded text-xs">Complete</button>
                  </form>

                  <button type="button" onclick="showDecline(<?php echo (int)$r['request_id']; ?>)" class="px-2 py-1 bg-red-600 text-white rounded text-xs">Decline</button>
                <?php endif; ?>

                <button type="button" onclick="viewRequestDetails(<?php echo (int)$r['request_id']; ?>)" class="px-2 py-1 bg-gray-100 text-gray-800 rounded text-xs">Details</button>
              </div>

              <!-- Decline form (hidden) -->
              <div id="decline-form-<?php echo (int)$r['request_id']; ?>" class="mt-2 hidden">
                <form method="POST" action="">
                  <?php echo csrf_field(); ?>
                  <input type="hidden" name="request_id" value="<?php echo (int)$r['request_id']; ?>">
                  <input type="hidden" name="action" value="decline">
                  <textarea name="decline_reason" rows="2" placeholder="Reason for decline" class="w-full border p-2 rounded text-xs mt-1"></textarea>
                  <div class="flex gap-2 mt-2">
                    <button type="submit" class="px-2 py-1 bg-red-600 text-white rounded text-xs">Submit Decline</button>
                    <button type="button" onclick="hideDecline(<?php echo (int)$r['request_id']; ?>)" class="px-2 py-1 bg-gray-300 rounded text-xs">Cancel</button>
                  </div>
                </form>
              </div>
            </td>
          </tr>
        <?php endforeach; endif; ?>
      </tbody>
    </table>
  </div>

  <!-- Request Details Modal -->
  <div id="requestModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
    <div class="bg-white rounded-lg max-w-2xl w-full max-h-[90vh] overflow-auto">
      <div class="p-4 border-b flex items-center justify-between">
        <h3 id="requestModalTitle" class="text-lg font-semibold">Request</h3>
        <button onclick="closeRequestModal()" class="text-gray-600">✕</button>
      </div>
      <div id="requestModalBody" class="p-4">Loading…</div>
      <div class="p-4 border-t text-right"><button onclick="closeRequestModal()" class="px-4 py-2 bg-gray-200 rounded">Close</button></div>
    </div>
  </div>
</section>

<script>
function showDecline(id) {
  document.getElementById('decline-form-' + id).classList.remove('hidden');
}
function hideDecline(id) {
  document.getElementById('decline-form-' + id).classList.add('hidden');
}

function viewRequestDetails(id) {
  const body = document.getElementById('requestModalBody');
  document.getElementById('requestModalTitle').textContent = 'Request #' + id;
  body.innerHTML = '<div class="p-4 text-gray-600">Loading…</div>';
  document.getElementById('requestModal').classList.remove('hidden');

  fetch('API/inspection_requests.php?request_id=' + encodeURIComponent(id), { credentials: 'same-origin' })
    .then(async r => {
      const text = await r.text();
      try {
        const j = JSON.parse(text);
        const req = j.request || (j.requests && j.requests[0]) || j;
        if (!req) { body.innerHTML = '<div class="text-red-600">Unavailable</div>'; return; }
        let html = '<div class="space-y-2">';
        html += '<div><strong>Requested:</strong> ' + (req.created_at || '') + '</div>';
        html += '<div><strong>Trigger:</strong> ' + (req.trigger_type || '') + '</div>';
        html += '<div><strong>Requestor:</strong> ' + (req.requestor_type || '') + ' — ' + (req.requestor_name || req.requestor_id) + '</div>';
        html += '<div><strong>Market / Stall:</strong> ' + ((req.market_name || '-') + (req.stall_number ? ' / ' + req.stall_number : '')) + '</div>';
        html += '<div><strong>Notes:</strong><div class="mt-1 p-2 bg-gray-50 rounded">' + (req.notes ? escapeHtml(req.notes) : '-') + '</div></div>';
        html += '</div>';
        body.innerHTML = html;
      } catch (e) {
        body.innerHTML = '<div class="text-red-600 p-4">Failed to load: ' + escapeHtml(text.slice(0, 300)) + '</div>';
      }
    })
    .catch(err => { body.innerHTML = '<div class="text-red-600 p-4">Failed to load: ' + escapeHtml(err.message || '') + '</div>'; });
}

function closeRequestModal(){ document.getElementById('requestModal').classList.add('hidden'); }
function escapeHtml(s){ if(!s) return ''; return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
</script>

<?php include 'includes/footer.php'; ?>