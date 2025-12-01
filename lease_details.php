<?php
/**
 * lease_details.php (Fixed)
 *
 * Fixes:
 *  - Allow vendor access if either l.vendor_id matches or the stall has a matching owner column
 *    (vendor_user_id, vendor_id, user_id, owner_id) to accommodate different DB schemas.
 *  - Ensure inspection outcome only displays when inspection status is 'completed'.
 *  - Preserve existing admin functionality and add the Inspections section.
 */

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/notifications.php';
require_once 'includes/helpers.php';

if (!isLoggedIn()) redirect('login.php?timeout=1');
$user_id  = (int)($_SESSION['user_id'] ?? 0);
$lease_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
if ($lease_id <= 0) redirect('my_leases.php');

$sql = "SELECT l.*, s.stall_id, s.stall_number, s.floor_number, s.stall_size,
               m.market_name, m.location, u.full_name AS vendor_name
        FROM leases l
        JOIN stalls s ON l.stall_id = s.stall_id
        JOIN markets m ON s.market_id = m.market_id
        JOIN users u ON l.vendor_id = u.user_id
        WHERE l.lease_id = ? LIMIT 1";
$lease = $db->fetch($sql, [$lease_id]);
if (!$lease) redirect('my_leases.php');

// Authorization: allow vendor (lease vendor_id) OR owner-like columns on the stalls table
$allowed = false;
$lease_vendor_id = isset($lease['vendor_id']) ? (int)$lease['vendor_id'] : 0;
if ($lease_vendor_id !== 0 && $lease_vendor_id === $user_id) {
    $allowed = true;
} elseif (isAdmin()) {
    $allowed = true;
} else {
    // Try to detect stall owner columns that some schemas use.
    try {
        $stall_id = (int)($lease['stall_id'] ?? 0);
        if ($stall_id > 0) {
            $ownerRow = $db->fetch(
                "SELECT
                    COALESCE(
                      NULLIF(vendor_user_id, ''),
                      NULLIF(vendor_id, ''),
                      NULLIF(user_id, ''),
                      NULLIF(owner_id, ''),
                      NULLIF(assigned_user_id, ''),
                      NULLIF(assigned_to, '')
                    ) AS possible_owner
                 FROM stalls
                 WHERE stall_id = ?
                 LIMIT 1",
                [$stall_id]
            );
            if ($ownerRow && !empty($ownerRow['possible_owner'])) {
                // coalesced value may be string; cast
                $ownerCandidate = (int)$ownerRow['possible_owner'];
                if ($ownerCandidate === $user_id) $allowed = true;
            }
        }
    } catch (Throwable $e) {
        error_log("lease_details: owner detection failed for lease {$lease_id}: " . $e->getMessage());
    }
}

if (!$allowed) { http_response_code(403); echo "Forbidden"; exit; }

// Fetch payments
$payments = $db->fetchAll("SELECT * FROM payments WHERE lease_id = ? ORDER BY due_date DESC", [$lease_id]);

// --- Fetch inspections for this stall ---
$inspections = [];
$inspections_count = ['scheduled'=>0,'pending'=>0,'completed'=>0,'other'=>0];
try {
    $stall_id = (int)($lease['stall_id'] ?? 0);
    if ($stall_id > 0) {
        $inspections = $db->fetchAll(
            "SELECT i.inspection_id, i.stall_id, i.market_id, i.inspector_id, i.inspected_at,
                    i.outcome, i.status AS inspection_status, i.notes,
                    u.full_name AS inspector_name, i.updated_at
             FROM inspections i
             LEFT JOIN users u ON i.inspector_id = u.user_id
             WHERE i.stall_id = ?
             ORDER BY
               CASE WHEN i.status='completed' THEN 0 WHEN i.status='scheduled' THEN 1 ELSE 2 END,
               i.inspected_at DESC, i.updated_at DESC
             LIMIT 200",
            [$stall_id]
        ) ?: [];
        foreach ($inspections as $r) {
            $s = strtolower((string)($r['inspection_status'] ?? 'other'));
            if ($s === 'scheduled') $inspections_count['scheduled']++;
            elseif ($s === 'pending') $inspections_count['pending']++;
            elseif ($s === 'completed') $inspections_count['completed']++;
            else $inspections_count['other']++;
        }
    }
} catch (Throwable $e) {
    error_log("lease_details: inspections fetch failed for lease {$lease_id}: " . $e->getMessage());
    $inspections = [];
}

// helper for inspection badge
function inspectionStatusBadge($status){
    $s = strtolower((string)$status);
    return match($s){
        'scheduled','pending' => "<span class='inline-block px-2 py-0.5 rounded bg-yellow-100 text-yellow-800 text-xs font-semibold'>".htmlspecialchars(ucfirst($s))."</span>",
        'completed' => "<span class='inline-block px-2 py-0.5 rounded bg-green-100 text-green-700 text-xs font-semibold'>Completed</span>",
        default => "<span class='inline-block px-2 py-0.5 rounded bg-gray-100 text-gray-700 text-xs'>".htmlspecialchars(ucfirst($s))."</span>"
    };
}

$status_msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isAdmin()) {
    $new_status = sanitize($_POST['new_status'] ?? '');
    $allowed_statuses = ['active','expired','terminated','pending'];
    if (in_array($new_status, $allowed_statuses, true)) {
        $db->query("UPDATE leases SET status = ? WHERE lease_id = ?", [$new_status, $lease_id]);
        logAudit($db, $_SESSION['user_id'], 'Update Lease Status', 'leases', $lease_id, null, $new_status);
        $status_msg = 'Lease status updated.';
        $lease = $db->fetch($sql, [$lease_id]);
    }
}

$page_title = 'Lease Details';
require_once 'includes/header.php';
require_once (isAdmin() ? 'includes/admin_sidebar.php' : 'includes/vendor_sidebar.php');
?>
<section class="max-w-4xl mx-auto p-6">
  <div class="flex items-center justify-between mb-4">
    <h1 class="text-2xl font-bold">Lease #<?php echo (int)$lease['lease_id']; ?></h1>
    <div class="text-sm text-gray-600"><?php echo htmlspecialchars($lease['status']); ?></div>
  </div>

  <!-- Payment rule banner -->
  <div class="bg-blue-50 border-l-4 border-blue-400 text-blue-800 px-4 py-3 rounded mb-4 text-sm">
    Vendors must pay their stall lease on or before the 5th day of each month.
  </div>

  <?php if ($status_msg): ?>
    <div class="bg-green-100 p-3 rounded mb-4"><?php echo htmlspecialchars($status_msg); ?></div>
  <?php endif; ?>

  <div class="bg-white rounded shadow p-6 mb-6">
    <h2 class="text-lg font-semibold">Business</h2>
    <p><strong><?php echo htmlspecialchars($lease['business_name']); ?></strong>
       — <?php echo htmlspecialchars($lease['business_type'] ?? ''); ?></p>
    <p class="text-sm text-gray-600">Vendor: <?php echo htmlspecialchars($lease['vendor_name']); ?></p>
  </div>

  <div class="bg-white rounded shadow p-6 mb-6">
    <h2 class="text-lg font-semibold">Stall & Market</h2>
    <p><strong><?php echo htmlspecialchars($lease['stall_number']); ?></strong>
       — <?php echo htmlspecialchars($lease['market_name']); ?>
       (<?php echo htmlspecialchars($lease['location']); ?>)</p>
    <p>Size: <?php echo htmlspecialchars($lease['stall_size']); ?> • Floor: <?php echo (int)$lease['floor_number']; ?></p>
    <?php if (!empty($lease['contract_document'])): ?>
      <p class="mt-2"><a class="text-blue-600" href="<?php echo htmlspecialchars($lease['contract_document']); ?>" target="_blank">Download Contract</a></p>
    <?php endif; ?>
  </div>

  <div class="bg-white rounded shadow p-6 mb-6">
    <h2 class="text-lg font-semibold">Lease Terms</h2>
    <p>Start: <?php echo formatDate($lease['lease_start_date']); ?></p>
    <p>End: <?php echo formatDate($lease['lease_end_date']); ?></p>
    <p>Monthly Rent: <?php echo formatCurrency($lease['monthly_rent']); ?></p>
  </div>

  <div class="bg-white rounded shadow p-6 mb-6">
    <h2 class="text-lg font-semibold">Payments</h2>
    <?php if (!empty($payments)): ?>
      <table class="w-full text-sm">
        <thead class="bg-gray-50">
          <tr>
            <th class="py-2 px-3 text-left">Due Date</th>
            <th class="py-2 px-3 text-left">Amount</th>
            <th class="py-2 px-3 text-left">Status</th>
            <th class="py-2 px-3 text-left">Payment Date</th>
            <th class="py-2 px-3 text-left">Receipt</th>
            <th class="py-2 px-3 text-left">Flag</th>
          </tr>
        </thead>
        <tbody>
          <?php
            $todayTs = time();
            foreach ($payments as $p):
              $dueTs    = strtotime($p['due_date']);
              $paid     = strtolower($p['status']) === 'paid';
              $daysDiff = ($dueTs - $todayTs)/86400;
              $flagHtml = '';

              if (!$paid) {
                  if ($daysDiff < 0) {
                      $flagHtml = '<span class="inline-block px-2 py-0.5 rounded bg-red-600 text-white text-xs">Past Due</span>';
                  } elseif ($daysDiff <= 3) {
                      $flagHtml = '<span class="inline-block px-2 py-0.5 rounded bg-amber-600 text-white text-xs">Due Soon</span>';
                  }
              }
              $dueDay = (int)date('j', $dueTs);
              if (!$paid && $dueDay <= 5 && $daysDiff < 0) {
                  $flagHtml .= ' <span class="inline-block px-2 py-0.5 rounded bg-purple-600 text-white text-xs">Lease Rule Breach</span>';
              }
          ?>
            <tr class="border-t <?php echo (!$paid && $daysDiff < 0) ? 'bg-red-50' : ''; ?>">
              <td class="py-2 px-3"><?php echo formatDate($p['due_date']); ?></td>
              <td class="py-2 px-3"><?php echo formatCurrency($p['amount']); ?></td>
              <td class="py-2 px-3"><?php echo htmlspecialchars($p['status']); ?></td>
              <td class="py-2 px-3"><?php echo !empty($p['payment_date']) ? formatDate($p['payment_date']) : '-'; ?></td>
              <td class="py-2 px-3"><?php echo !empty($p['receipt_number']) ? htmlspecialchars($p['receipt_number']) : '-'; ?></td>
              <td class="py-2 px-3"><?php echo $flagHtml ?: '<span class="text-xs text-gray-400">-</span>'; ?></td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    <?php else: ?>
      <p class="text-sm text-gray-500">No payment records found for this lease.</p>
    <?php endif; ?>
  </div>

  <!-- Inspections Summary & List -->
  <div class="bg-white rounded shadow p-6 mb-6">
    <h2 class="text-lg font-semibold">Inspections</h2>
    <p class="text-sm text-gray-600 mb-3">Inspections for this stall (latest first).</p>

    <div class="flex gap-3 mb-4 text-sm">
      <div class="px-3 py-2 bg-gray-50 rounded">
        Scheduled: <strong><?php echo (int)$inspections_count['scheduled']; ?></strong>
      </div>
      <div class="px-3 py-2 bg-gray-50 rounded">
        Pending: <strong><?php echo (int)$inspections_count['pending']; ?></strong>
      </div>
      <div class="px-3 py-2 bg-gray-50 rounded">
        Completed: <strong><?php echo (int)$inspections_count['completed']; ?></strong>
      </div>
      <div class="px-3 py-2 bg-gray-50 rounded">
        Other: <strong><?php echo (int)$inspections_count['other']; ?></strong>
      </div>
    </div>

    <?php if (empty($inspections)): ?>
      <p class="text-sm text-gray-500">No inspections have been recorded for this stall.</p>
    <?php else: ?>
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead class="bg-gray-50">
            <tr>
              <th class="py-2 px-3 text-left">Status</th>
              <th class="py-2 px-3 text-left">Date</th>
              <th class="py-2 px-3 text-left">Inspector</th>
              <th class="py-2 px-3 text-left">Outcome</th>
              <th class="py-2 px-3 text-left">Notes</th>
              <th class="py-2 px-3 text-left">Actions</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($inspections as $ins):
                $s = strtolower((string)($ins['inspection_status'] ?? 'other'));
                $when = '-';
                if (!empty($ins['inspected_at'])) {
                    $ts = strtotime($ins['inspected_at']);
                    $when = ($s === 'scheduled' || $s === 'pending') ? 'Scheduled for '.date('M j, Y', $ts) : date('M j, Y H:i', $ts);
                } else {
                    $when = ($s === 'scheduled' || $s === 'pending') ? 'Scheduled' : '-';
                }
                // Show outcome only when completed
                $outcomeDisplay = ($s === 'completed') ? ($ins['outcome'] ?? '-') : '-';
            ?>
              <tr class="border-t">
                <td class="py-2 px-3"><?php echo inspectionStatusBadge($s); ?></td>
                <td class="py-2 px-3"><?php echo htmlspecialchars($when); ?></td>
                <td class="py-2 px-3"><?php echo htmlspecialchars($ins['inspector_name'] ?? '-'); ?></td>
                <td class="py-2 px-3"><?php echo htmlspecialchars($outcomeDisplay); ?></td>
                <td class="py-2 px-3"><?php echo htmlspecialchars(mb_strimwidth($ins['notes'] ?? '', 0, 120, '…')); ?></td>
                <td class="py-2 px-3">
                  <button type="button" class="text-blue-600 hover:underline view-inspection-btn" data-id="<?php echo (int)$ins['inspection_id']; ?>">View</button>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    <?php endif; ?>
  </div>

  <?php if (isAdmin()): ?>
    <div class="bg-white rounded shadow p-6 mb-6">
      <h2 class="text-lg font-semibold">Admin Actions</h2>
      <form method="POST" action="">
        <label class="block mb-2">Change Status</label>
        <select name="new_status" class="px-3 py-2 border rounded mb-3">
          <option value="active" <?php echo $lease['status']==='active' ? 'selected' : ''; ?>>Active</option>
          <option value="expired" <?php echo $lease['status']==='expired' ? 'selected' : ''; ?>>Expired</option>
          <option value="terminated" <?php echo $lease['status']==='terminated' ? 'selected' : ''; ?>>Terminated</option>
          <option value="pending" <?php echo $lease['status']==='pending' ? 'selected' : ''; ?>>Pending</option>
        </select>
        <button class="bg-green-600 text-white px-4 py-2 rounded">Update Status</button>
      </form>
    </div>
  <?php endif; ?>
</section>

<!-- Modal used to view inspection details (re-uses API/inspections.php) -->
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

<script>
function escapeHtml(s){
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function viewInspectionModal(id){
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
        const ins = (j.inspection || (j.inspections && j.inspections[0])) || j || null;
        if (!ins){
          body.innerHTML = '<div class="text-red-600">Inspection details unavailable.</div>';
          return;
        }
        let status = (ins.status || ins.inspection_status || '').toLowerCase();
        let dateText = '-';
        if (ins.inspected_at) {
          const d = new Date(ins.inspected_at.replace(' ', 'T'));
          dateText = (status === 'scheduled' || status === 'pending') ? 'Scheduled for ' + d.toLocaleDateString() : d.toLocaleString();
        }
        const outcomeDisplay = (status === 'completed') ? (ins.outcome || '—') : '—';
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
function closeInspectionModal(){ document.getElementById('inspectionModal').classList.add('hidden'); }

document.addEventListener('click', function(e){
  const btn = e.target.closest('.view-inspection-btn');
  if (btn){
    const id = btn.dataset.id;
    if (id) viewInspectionModal(id);
  }
  if (e.target.matches('#inspectionModal')) closeInspectionModal();
});
document.addEventListener('keydown', function(e){ if (e.key === 'Escape') closeInspectionModal(); });
</script>

<?php include 'includes/footer.php'; ?>