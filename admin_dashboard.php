<?php
require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/helpers.php';

if (!isLoggedIn()) {
    $_SESSION['intended_url'] = $_SERVER['REQUEST_URI'] ?? '/';
    redirect('login.php?timeout=1');
}
if (function_exists('refreshSessionRoles')) {
    refreshSessionRoles($db);
}

$uid = $_SESSION['user_id'] ?? null;
$roleNames = [];
try {
    if ($uid && function_exists('_fetchUserRoleNames')) {
        $roleNames = _fetchUserRoleNames($uid, $db) ?: [];
    } elseif (!empty($_SESSION['roles']) && is_array($_SESSION['roles'])) {
        $roleNames = $_SESSION['roles'];
    }
} catch (Throwable $e) {
    error_log("admin_dashboard: failed to fetch role names for user {$uid}: ".$e->getMessage());
    $roleNames = $_SESSION['roles'] ?? [];
}

$is_super_admin    = in_array('super_admin', $roleNames, true);
$is_market_manager = in_array('market_manager', $roleNames, true);
$is_accountant     = in_array('accountant', $roleNames, true);
$is_inspector      = in_array('inspector', $roleNames, true);

// Manage button visibility: exclude inspector & accountant
$can_manage_stalls = ($is_super_admin || $is_market_manager || isAdmin());

// Access guard
if (!($is_super_admin || $is_market_manager || $is_accountant || $is_inspector || isAdmin())) {
    http_response_code(403);
    echo "Forbidden";
    exit;
}

$page_title = 'Admin Dashboard';

// Update overdue payments (demo convenience)
if (function_exists('autoUpdateOverduePayments')) {
    autoUpdateOverduePayments($db);
}

function getUserManagedMarketIds($db, int $userId): array {
    $ids = [];
    try {
        $rows = $db->fetchAll("SELECT market_id FROM market_managers WHERE user_id = ?", [$userId]) ?: [];
        foreach ($rows as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id'];
    } catch (Throwable $e) {}
    try {
        $rows = $db->fetchAll("SELECT market_id FROM markets WHERE created_by = ?", [$userId]) ?: [];
        foreach ($rows as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id'];
    } catch (Throwable $e) {}
    try {
        $rows = $db->fetchAll("SELECT DISTINCT market_id FROM user_roles WHERE user_id = ? AND market_id IS NOT NULL AND status='active'", [$userId]) ?: [];
        foreach ($rows as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id'];
    } catch (Throwable $e) {}
    return array_values(array_unique($ids));
}

$managed_market_ids = [];
if (($is_market_manager || $is_accountant || $is_inspector) && $uid) {
    $managed_market_ids = getUserManagedMarketIds($db, (int)$uid);
}

/* Stats */
if ($is_market_manager || $is_accountant || $is_inspector) {
    if (empty($managed_market_ids)) {
        $stats = ['available_stalls'=>0,'occupied_stalls'=>0,'active_leases'=>0,'monthly_revenue'=>0.0];
    } else {
        $ph = implode(',', array_fill(0, count($managed_market_ids), '?'));
        $stats = $db->fetch(
            "SELECT
              (SELECT COUNT(*) FROM stalls s JOIN markets m ON s.market_id=m.market_id WHERE s.status='available' AND m.market_id IN ($ph)) AS available_stalls,
              (SELECT COUNT(*) FROM stalls s JOIN markets m ON s.market_id=m.market_id WHERE s.status='occupied' AND m.market_id IN ($ph)) AS occupied_stalls,
              (SELECT COUNT(*) FROM leases l JOIN stalls s ON l.stall_id=s.stall_id WHERE l.status='active' AND s.market_id IN ($ph)) AS active_leases,
              (SELECT COALESCE(SUM(p.amount),0) FROM payments p
                 JOIN leases l2 ON p.lease_id=l2.lease_id
                 JOIN stalls s2 ON l2.stall_id=s2.stall_id
                 WHERE p.status='paid'
                   AND MONTH(p.payment_date)=MONTH(CURDATE())
                   AND YEAR(p.payment_date)=YEAR(CURDATE())
                   AND s2.market_id IN ($ph)) AS monthly_revenue",
            array_merge($managed_market_ids,$managed_market_ids,$managed_market_ids,$managed_market_ids)
        );
    }
} else {
    $stats = $db->fetch("SELECT
        (SELECT COUNT(*) FROM stalls WHERE status='available') AS available_stalls,
        (SELECT COUNT(*) FROM stalls WHERE status='occupied') AS occupied_stalls,
        (SELECT COUNT(*) FROM leases WHERE status='active') AS active_leases,
        (SELECT COALESCE(SUM(amount),0) FROM payments
           WHERE status='paid'
             AND MONTH(payment_date)=MONTH(CURDATE())
             AND YEAR(payment_date)=YEAR(CURDATE())) AS monthly_revenue
    ");
}

/* Panels:
   - Applications hidden for super_admin and inspectors.
   - For inspectors show scheduled/pending inspections list.
*/
$show_pending_applications = (!$is_super_admin && !$is_inspector);
$show_pending_inspections  = $is_inspector;

// Hide identity docs for inspector and accountant roles (requirement)
$show_identity_documents   = (!$is_inspector && !$is_accountant);

/* Pending applications */
$recent_applications = [];
if ($show_pending_applications) {
    if ($is_market_manager || $is_accountant) {
        if (!empty($managed_market_ids)) {
            $ph = implode(',', array_fill(0, count($managed_market_ids), '?'));
            $recent_applications = $db->fetchAll("
              SELECT a.*, u.full_name, s.stall_number, m.market_name
                FROM applications a
                JOIN users u ON a.vendor_id = u.user_id
                JOIN stalls s ON a.stall_id = s.stall_id
                JOIN markets m ON s.market_id = m.market_id
               WHERE a.status='pending' AND m.market_id IN ($ph)
               ORDER BY a.application_date DESC
               LIMIT 8
            ", $managed_market_ids) ?: [];
        }
    } else {
        $recent_applications = $db->fetchAll("
          SELECT a.*, u.full_name, s.stall_number, m.market_name
            FROM applications a
            JOIN users u ON a.vendor_id = u.user_id
            JOIN stalls s ON a.stall_id = s.stall_id
            JOIN markets m ON s.market_id = m.market_id
           WHERE a.status='pending'
           ORDER BY a.application_date DESC
           LIMIT 8
        ") ?: [];
    }
}

/* Inspector scheduled/pending inspections */
$pending_inspections = [];
if ($show_pending_inspections) {
    try {
        $pending_inspections = $db->fetchAll("
          SELECT i.inspection_id, i.stall_id, i.market_id, i.inspector_id,
                 i.inspected_at, i.status, i.outcome, s.stall_number, m.market_name
            FROM inspections i
            JOIN stalls s ON i.stall_id = s.stall_id
            JOIN markets m ON i.market_id = m.market_id
           WHERE i.inspector_id = ?
             AND i.status IN ('scheduled','pending')
           ORDER BY i.inspected_at ASC, i.created_at DESC
           LIMIT 8
        ", [$uid]) ?: [];
    } catch (Throwable $e) {
        error_log("admin_dashboard: pending inspections fetch failed: ".$e->getMessage());
    }
}

/* Stall map */
if ($is_market_manager || $is_accountant || $is_inspector) {
    if (!empty($managed_market_ids)) {
        $ph = implode(',', array_fill(0, count($managed_market_ids), '?'));
        $stalls_rows = $db->fetchAll("
          SELECT s.stall_id, s.stall_number, s.status, s.floor_number,
                 s.stall_size, m.market_id, m.market_name
            FROM stalls s
            JOIN markets m ON s.market_id = m.market_id
           WHERE m.market_id IN ($ph)
           ORDER BY m.market_name, s.floor_number, s.stall_number
        ", $managed_market_ids) ?: [];
    } else { $stalls_rows = []; }
} else {
    $stalls_rows = $db->fetchAll("
      SELECT s.stall_id, s.stall_number, s.status, s.floor_number,
             s.stall_size, m.market_id, m.market_name
        FROM stalls s
        JOIN markets m ON s.market_id = m.market_id
       ORDER BY m.market_name, s.floor_number, s.stall_number
    ") ?: [];
}

$grouped = [];
foreach ($stalls_rows as $r) {
    $market = $r['market_name'] ?? 'Unknown Market';
    $floor  = $r['floor_number'] ?? 1;
    $grouped[$market][$floor][] = $r;
}

$recent_identity_docs = $show_identity_documents
    ? ($db->fetchAll("SELECT * FROM identity_documents ORDER BY uploaded_at DESC LIMIT 8") ?: [])
    : []; // fetch only if shown to avoid extra query (optional optimization)

$my_notifications = $db->fetchAll("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 10", [$uid]) ?: [];

logAudit($db, $uid, 'View Admin Dashboard', 'dashboard', null, null, null);

require_once 'includes/header.php';
require_once 'includes/admin_sidebar.php';
?>
<section class="max-w-7xl mx-auto p-6">

  <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mt-4">
    <div class="bg-white p-4 rounded shadow">
      <div class="text-sm text-gray-500">Available Stalls</div>
      <div class="text-2xl font-bold"><?php echo (int)($stats['available_stalls'] ?? 0); ?></div>
    </div>
    <div class="bg-white p-4 rounded shadow">
      <div class="text-sm text-gray-500">Occupied Stalls</div>
      <div class="text-2xl font-bold"><?php echo (int)($stats['occupied_stalls'] ?? 0); ?></div>
    </div>
    <div class="bg-white p-4 rounded shadow">
      <div class="text-sm text-gray-500">Active Leases</div>
      <div class="text-2xl font-bold"><?php echo (int)($stats['active_leases'] ?? 0); ?></div>
    </div>
    <div class="bg-white p-4 rounded shadow">
      <div class="text-sm text-gray-500">Monthly Revenue</div>
      <div class="text-2xl font-bold">
        <?php
        if (function_exists('formatCurrency')) {
            echo formatCurrency($stats['monthly_revenue'] ?? 0);
        } else {
            echo '₱' . number_format((float)($stats['monthly_revenue'] ?? 0), 2);
        }
        ?>
      </div>
    </div>
  </div>

  <section class="bg-white rounded shadow p-4 my-6">
    <h2 class="text-lg font-semibold mb-3">Stall Map Overview</h2>
    <div class="flex flex-wrap gap-4 mb-4">
      <div class="flex items-center space-x-2"><div class="w-4 h-4 bg-green-500 rounded"></div><span class="text-sm text-gray-600">Available</span></div>
      <div class="flex items-center space-x-2"><div class="w-4 h-4 bg-blue-500 rounded"></div><span class="text-sm text-gray-600">Occupied</span></div>
      <div class="flex items-center space-x-2"><div class="w-4 h-4 bg-yellow-500 rounded"></div><span class="text-sm text-gray-600">Reserved</span></div>
      <div class="flex items-center space-x-2"><div class="w-4 h-4 bg-red-500 rounded"></div><span class="text-sm text-gray-600">Maintenance</span></div>
      <div class="flex items-center space-x-2"><div class="w-4 h-4 bg-gray-400 rounded"></div><span class="text-sm text-gray-600">Unknown</span></div>
    </div>

    <?php if (empty($grouped)): ?>
      <p class="text-sm text-gray-500">
        <?php if ($is_market_manager || $is_inspector): ?>
          You don't manage any markets yet, so there are no stalls to display.
        <?php else: ?>
          No stalls found.
        <?php endif; ?>
      </p>
    <?php else: ?>
      <?php foreach ($grouped as $marketName => $floors): ?>
        <div class="mb-6">
          <h3 class="text-md font-semibold mb-2"><?php echo htmlspecialchars($marketName); ?></h3>
          <?php ksort($floors); ?>
          <?php foreach ($floors as $floorNum => $stalls): ?>
            <div class="mb-4">
              <div class="flex items-center justify-between mb-2">
                <div class="text-sm text-gray-700 font-medium">Floor <?php echo (int)$floorNum; ?></div>
                <div class="text-xs text-gray-500">Stalls: <?php echo count($stalls); ?></div>
              </div>
              <div class="grid grid-cols-4 sm:grid-cols-6 md:grid-cols-8 lg:grid-cols-12 gap-2">
                <?php foreach ($stalls as $stall):
                  $color_class = 'bg-gray-400';
                  switch (strtolower($stall['status'] ?? '')) {
                      case 'available':   $color_class = 'bg-green-500'; break;
                      case 'occupied':    $color_class = 'bg-blue-500'; break;
                      case 'reserved':    $color_class = 'bg-yellow-500'; break;
                      case 'maintenance': $color_class = 'bg-red-500'; break;
                  }
                  $title = htmlspecialchars(($stall['stall_number'] ?? 'N/A').' - '.ucfirst($stall['status'] ?? 'Unknown'));
                  $stall_market_id = isset($stall['market_id']) ? (int)$stall['market_id'] : null;
                  $stall_managed   = (!($is_market_manager || $is_inspector || $is_accountant))
                                     || ($stall_market_id !== null && in_array($stall_market_id, $managed_market_ids, true));
                  $interactive = !$is_super_admin && ($is_market_manager || $is_inspector || $is_accountant ? $stall_managed : true);
                ?>
                  <?php if (!$interactive): ?>
                    <div class="aspect-square <?php echo $color_class; ?> rounded flex items-center justify-center text-white text-xs font-bold opacity-70 cursor-default"
                         title="<?php echo $title; ?>" aria-label="<?php echo $title; ?>">
                      <?php echo htmlspecialchars($stall['stall_number'] ?? ''); ?>
                    </div>
                  <?php else: ?>
                    <button type="button"
                      class="aspect-square <?php echo $color_class; ?> rounded flex items-center justify-center text-white text-xs font-bold hover:scale-105 transform transition"
                      title="<?php echo $title; ?>"
                      data-stall-id="<?php echo (int)$stall['stall_id']; ?>"
                      aria-label="<?php echo $title; ?>">
                      <?php echo htmlspecialchars($stall['stall_number'] ?? ''); ?>
                    </button>
                  <?php endif; ?>
                <?php endforeach; ?>
              </div>
            </div>
          <?php endforeach; ?>
        </div>
      <?php endforeach; ?>
    <?php endif; ?>
  </section>

  <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mt-6">

    <?php if ($show_pending_applications): ?>
      <div class="col-span-2 bg-white rounded shadow p-4">
        <h3 class="text-lg font-semibold mb-3">Pending Applications</h3>
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead class="text-left text-gray-600">
              <tr>
                <th class="py-2">Applicant</th>
                <th>Business</th>
                <th>Stall</th>
                <th>Date</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
            <?php if (!empty($recent_applications)): foreach ($recent_applications as $app): ?>
              <tr class="border-t hover:bg-gray-50">
                <td class="py-2"><?php echo htmlspecialchars($app['full_name']); ?></td>
                <td><?php echo htmlspecialchars($app['business_name']); ?></td>
                <td><?php echo htmlspecialchars($app['stall_number']); ?></td>
                <td><?php echo !empty($app['application_date']) ? date('M j, Y', strtotime($app['application_date'])) : '-'; ?></td>
                <td><?php echo function_exists('getStatusBadge') ? getStatusBadge($app['status']) : htmlspecialchars($app['status']); ?></td>
                <td><a href="manage_applications.php?id=<?php echo (int)$app['application_id']; ?>" class="text-blue-600">Review</a></td>
              </tr>
            <?php endforeach; else: ?>
              <tr><td colspan="6" class="py-4 text-center text-gray-500">No pending applications</td></tr>
            <?php endif; ?>
            </tbody>
          </table>
        </div>
      </div>
    <?php endif; ?>

    <?php if ($show_pending_inspections): ?>
      <div class="col-span-2 bg-white rounded shadow p-4">
        <h3 class="text-lg font-semibold mb-3">Scheduled / Pending Inspections</h3>
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead class="text-left text-gray-600">
              <tr>
                <th class="py-2">Market</th>
                <th>Stall</th>
                <th>Scheduled Date</th>
                <th>Status</th>
                <th>Outcome</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
            <?php if (!empty($pending_inspections)): foreach ($pending_inspections as $ins):
                $statusLower = strtolower($ins['status'] ?? '');
                $scheduleTs  = !empty($ins['inspected_at']) ? strtotime($ins['inspected_at']) : null;
                $dateDisplay = $scheduleTs ? date('M j, Y', $scheduleTs) : '—';
                $outcomeDisplay = in_array($statusLower,['scheduled','pending']) ? '—' : ($ins['outcome'] ?? '—');
            ?>
              <tr class="border-t hover:bg-gray-50">
                <td class="py-2"><?php echo htmlspecialchars($ins['market_name'] ?? ''); ?></td>
                <td><?php echo htmlspecialchars($ins['stall_number'] ?? ''); ?></td>
                <td><?php echo htmlspecialchars($dateDisplay); ?></td>
                <td>
                  <span class="px-2 py-1 rounded text-xs font-semibold
                    <?php echo in_array($statusLower,['scheduled','pending'])?'bg-yellow-100 text-yellow-700':'bg-gray-100 text-gray-700'; ?>">
                    <?php echo ucfirst($statusLower === 'pending' ? 'Scheduled' : $statusLower); ?>
                  </span>
                </td>
                <td><?php echo htmlspecialchars($outcomeDisplay); ?></td>
                <td>
                  <a class="text-blue-600 hover:underline"
                     href="manage_inspections.php?tab=scheduled&search=<?php echo urlencode($ins['stall_number']); ?>">
                    Open
                  </a>
                </td>
              </tr>
            <?php endforeach; else: ?>
              <tr><td colspan="6" class="py-4 text-center text-gray-500">No scheduled inspections</td></tr>
            <?php endif; ?>
            </tbody>
          </table>
        </div>
      </div>
    <?php endif; ?>

    <aside class="bg-white rounded shadow p-4 <?php echo ($show_pending_applications || $show_pending_inspections) ? '' : 'lg:col-span-3'; ?>">
      <h3 class="font-semibold mb-2">Notifications</h3>
      <?php if (empty($my_notifications)): ?>
        <p class="text-sm text-gray-500">No notifications</p>
      <?php else: ?>
        <ul class="space-y-2 text-sm">
          <?php foreach ($my_notifications as $n): ?>
            <li class="border-b pb-2">
              <div class="font-medium"><?php echo htmlspecialchars($n['title']); ?></div>
              <div class="text-xs text-gray-500"><?php echo htmlspecialchars($n['created_at']); ?></div>
            </li>
          <?php endforeach; ?>
        </ul>
      <?php endif; ?>

      <?php if ($show_identity_documents): ?>
      <div class="mt-6">
        <h4 class="font-semibold mb-2">Latest Identity Documents</h4>
        <ul class="text-sm space-y-2">
          <?php if (!empty($recent_identity_docs)): foreach ($recent_identity_docs as $doc): ?>
            <li>
              <div><?php echo htmlspecialchars($doc['doc_type'] ?? 'Document'); ?> — <?php echo htmlspecialchars($doc['status'] ?? ''); ?></div>
              <div class="text-xs text-gray-500">Uploaded: <?php echo htmlspecialchars($doc['uploaded_at'] ?? ''); ?></div>
              <?php if (!empty($doc['storage_url'])): ?>
                <div class="mt-1"><a class="text-blue-600 text-sm" href="<?php echo htmlspecialchars($doc['storage_url']); ?>" target="_blank" rel="noopener noreferrer">View</a></div>
              <?php endif; ?>
            </li>
          <?php endforeach; else: ?>
            <li class="text-sm text-gray-500">No identity documents</li>
          <?php endif; ?>
        </ul>
      </div>
      <?php endif; ?>
    </aside>
  </div>
</section>

<div id="stallModal" class="hidden fixed inset-0 z-50 flex items-center justify-center p-4 bg-black bg-opacity-50">
  <div class="bg-white rounded-lg w-full max-w-2xl overflow-auto max-h-[90vh]">
    <div class="p-4 border-b flex items-center justify-between">
      <h3 id="stallModalTitle" class="text-lg font-semibold">Stall Details</h3>
      <button onclick="closeStallModal()" class="text-gray-600 hover:text-gray-800">✕</button>
    </div>
    <div class="p-4" id="stallModalBody">
      <p class="text-sm text-gray-600">Loading...</p>
    </div>
    <div class="p-4 border-t text-right">
      <button onclick="closeStallModal()" class="px-4 py-2 bg-gray-200 rounded mr-2">Close</button>
      <?php if ($can_manage_stalls): ?>
        <a id="stallModalManageLink" class="inline-block px-4 py-2 bg-blue-600 text-white rounded" href="#">Manage</a>
      <?php endif; ?>
    </div>
  </div>
</div>

<script>
const CAN_MANAGE_STALLS = <?php echo $can_manage_stalls ? 'true' : 'false'; ?>;

function closeStallModal() {
  document.getElementById('stallModal').classList.add('hidden');
  document.getElementById('stallModalBody').innerHTML = '';
}
document.querySelectorAll('[data-stall-id]').forEach(btn=>{
  btn.addEventListener('click',()=>openStallModal(btn.getAttribute('data-stall-id')));
});
function openStallModal(stallId){
  const modal=document.getElementById('stallModal');
  const body=document.getElementById('stallModalBody');
  const title=document.getElementById('stallModalTitle');
  const manageLink=document.getElementById('stallModalManageLink');
  modal.classList.remove('hidden');
  body.innerHTML='<p class="text-sm text-gray-600">Loading stall information…</p>';
  title.textContent='Stall '+stallId;
  fetch('fetch_stall.php?stall_id='+encodeURIComponent(stallId),{credentials:'same-origin'})
    .then(res=>{ if(res.status===403) return res.text().then(t=>({error:t||'Forbidden'})); return res.json(); })
    .then(data=>{
      if(data.error){
        body.innerHTML='<div class="text-sm text-red-600">'+escapeHtml(data.error)+'</div>';
        if(manageLink){ manageLink.href='#'; manageLink.classList.add('hidden'); }
        return;
      }
      const s=data.stall;
      let html='<div class="grid grid-cols-1 gap-2">';
      html+='<div><strong>Market:</strong> '+escapeHtml(s.market_name||'')+'</div>';
      html+='<div><strong>Stall:</strong> '+escapeHtml(s.stall_number||'')+'</div>';
      html+='<div><strong>Status:</strong> '+escapeHtml(s.status||'')+'</div>';
      html+='<div><strong>Size:</strong> '+escapeHtml(s.stall_size||'-')+'</div>';
      if(data.lease){
        const L=data.lease;
        html+='<hr class="my-2"><div class="font-medium">Active Lease</div>';
        html+='<div><strong>Lease ID:</strong> '+escapeHtml(String(L.lease_id))+'</div>';
        html+='<div><strong>Vendor:</strong> '+escapeHtml(L.vendor_name||'-')+'</div>';
        html+='<div><strong>Business:</strong> '+escapeHtml(L.business_name||'-')+'</div>';
        html+='<div><strong>Period:</strong> '+escapeHtml(L.lease_start_date||'-')+' → '+escapeHtml(L.lease_end_date||'-')+'</div>';
        if(CAN_MANAGE_STALLS && manageLink){ manageLink.href='manage_leases.php?lease_id='+encodeURIComponent(L.lease_id); manageLink.classList.remove('hidden'); }
        else if(manageLink){ manageLink.href='#'; manageLink.classList.add('hidden'); }
      } else {
        html+='<hr class="my-2"><div class="text-sm text-gray-600">No active lease for this stall.</div>';
        if(CAN_MANAGE_STALLS && manageLink){ manageLink.href='manage_stalls.php?stall_id='+encodeURIComponent(s.stall_id); manageLink.classList.remove('hidden'); }
        else if(manageLink){ manageLink.href='#'; manageLink.classList.add('hidden'); }
      }
      html+='</div>';
      body.innerHTML=html;
      title.textContent='Stall '+(s.stall_number||stallId);
    })
    .catch(err=>{
      body.innerHTML='<div class="text-sm text-red-600">Failed to load stall data.</div>';
      if(manageLink){ manageLink.href='#'; manageLink.classList.add('hidden'); }
      console.error(err);
    });
}
function escapeHtml(str){
  if(!str) return '';
  return String(str)
    .replaceAll('&','&amp;')
    .replaceAll('<','&lt;')
    .replaceAll('>','&gt;')
    .replaceAll('"','&quot;')
    .replaceAll("'","&#39;");
}
</script>

<?php include 'includes/footer.php'; ?>