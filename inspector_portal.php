<?php
// inspector_portal.php
// Inspector-facing portal to list assigned markets/stalls and create/edit inspections.
// Assumes includes/inspector_utils.php, API/inspections.php and API/upload_inspection_photo.php exist.

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/csrf.php';
require_once 'includes/inspector_utils.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

// Require login
if (!isLoggedIn()) {
    $_SESSION['intended_url'] = $_SERVER['REQUEST_URI'] ?? '/';
    redirect('login.php?timeout=1');
}

$uid = $_SESSION['user_id'] ?? null;
if (!$uid) redirect('login.php');

// Only inspectors and admin-like roles may access
$roleNames = [];
try {
    if (function_exists('_fetchUserRoleNames')) $roleNames = _fetchUserRoleNames($uid, $db) ?: [];
    else $roleNames = $_SESSION['roles'] ?? [];
} catch (Throwable $e) {
    $roleNames = $_SESSION['roles'] ?? [];
}
$is_super = in_array('super_admin', $roleNames, true) || isAdmin();
$is_inspector = isInspector($db, $uid);

if (!($is_super || $is_inspector)) {
    http_response_code(403);
    echo "Forbidden";
    exit;
}

$page_title = 'Inspector Portal';
$error = '';
$success = '';

// Get inspector market scope
$inspector_market_ids = [];
if ($is_super) {
    // super sees all markets
    try {
        $rows = $db->fetchAll("SELECT market_id FROM markets WHERE status = 'active'") ?: [];
        foreach ($rows as $r) if (!empty($r['market_id'])) $inspector_market_ids[] = (int)$r['market_id'];
    } catch (Throwable $e) { $inspector_market_ids = []; }
} else {
    $inspector_market_ids = getInspectorMarketIds($db, $uid);
}

// If none, show empty
if (empty($inspector_market_ids)) {
    $markets = [];
    $stalls = [];
} else {
    // fetch markets
    try {
        $ph = implode(',', array_fill(0, count($inspector_market_ids), '?'));
        $markets = $db->fetchAll("SELECT market_id, market_name, location FROM markets WHERE market_id IN ($ph) AND status = 'active' ORDER BY market_name", $inspector_market_ids) ?: [];
    } catch (Throwable $e) { $markets = []; }

    // fetch stalls for those markets
    try {
        $ph = implode(',', array_fill(0, count($inspector_market_ids), '?'));
        $stalls = $db->fetchAll("SELECT s.*, m.market_name, m.location FROM stalls s JOIN markets m ON s.market_id = m.market_id WHERE s.market_id IN ($ph) ORDER BY m.market_name, s.floor_number, s.stall_number", $inspector_market_ids) ?: [];
    } catch (Throwable $e) { $stalls = []; }
}

// Recent inspections (scoped)
try {
    if ($is_super) {
        $recent_inspections = $db->fetchAll("SELECT i.*, u.full_name AS inspector_name, s.stall_number, m.market_name FROM inspections i JOIN users u ON i.inspector_id = u.user_id JOIN stalls s ON i.stall_id = s.stall_id JOIN markets m ON i.market_id = m.market_id ORDER BY i.inspected_at DESC LIMIT 50") ?: [];
    } else {
        $ph = implode(',', array_fill(0, count($inspector_market_ids), '?'));
        $recent_inspections = $db->fetchAll("SELECT i.*, u.full_name AS inspector_name, s.stall_number, m.market_name FROM inspections i JOIN users u ON i.inspector_id = u.user_id JOIN stalls s ON i.stall_id = s.stall_id JOIN markets m ON i.market_id = m.market_id WHERE i.market_id IN ($ph) ORDER BY i.inspected_at DESC LIMIT 200", $inspector_market_ids) ?: [];
    }
} catch (Throwable $e) { $recent_inspections = []; }

logAudit($db, $uid, 'View Inspector Portal', 'inspections', null, null, null);

require_once 'includes/header.php';
require_once 'includes/admin_sidebar.php';
?>

<section class="max-w-7xl mx-auto p-6">
  <div class="mb-6">
    <p class="text-gray-600">Inspect stalls and record findings for your assigned markets</p>
  </div>

  <?php if (empty($inspector_market_ids)): ?>
    <div class="bg-yellow-50 border-l-4 border-yellow-400 p-4 mb-6">
      <p class="text-yellow-800">You are not assigned to any markets. Contact an administrator to be assigned.</p>
    </div>
  <?php endif; ?>

  <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- Left: Markets & Stalls -->
    <div class="lg:col-span-2">
      <div class="bg-white rounded shadow p-6 mb-6">
        <h4 class="text-lg font-semibold mb-4">Assigned Markets & Stalls</h4>
        <?php if (empty($markets)): ?>
          <p class="text-sm text-gray-500">No markets assigned.</p>
        <?php else: ?>
          <?php foreach ($markets as $m): ?>
            <div class="mb-4">
              <div class="flex items-center justify-between">
                <div>
                  <h5 class="font-semibold"><?php echo htmlspecialchars($m['market_name']); ?></h5>
                  <div class="text-xs text-gray-500"><?php echo htmlspecialchars($m['location']); ?></div>
                </div>
                <div>
                  <button onclick="openMarketStalls(<?php echo (int)$m['market_id']; ?>)" class="px-3 py-1 bg-gray-100 rounded text-sm">View stalls</button>
                </div>
              </div>
              <div id="market-stalls-<?php echo (int)$m['market_id']; ?>" class="mt-3 hidden">
                <div class="grid grid-cols-3 gap-2">
                  <?php foreach ($stalls as $s): if ((int)$s['market_id'] !== (int)$m['market_id']) continue; ?>
                    <div class="p-3 border rounded flex items-center justify-between">
                      <div>
                        <div class="font-medium text-sm"><?php echo htmlspecialchars($s['stall_number']); ?></div>
                        <div class="text-xs text-gray-500">Floor <?php echo (int)$s['floor_number']; ?> — <?php echo htmlspecialchars($s['stall_size']); ?></div>
                      </div>
                      <div class="text-right">
                        <div class="text-xs mb-1"><?php echo getStatusBadge($s['status']); ?></div>
                        <div class="flex flex-col gap-1">
                          <button onclick='openInspectModalFor(<?php echo json_encode($s); ?>)' class="text-sm bg-yellow-600 text-white px-2 py-1 rounded">Inspect</button>
                          <?php if ($is_super): ?>
                            <a href="manage_stalls.php?market_id=<?php echo (int)$s['market_id']; ?>" class="text-sm px-2 py-1 rounded border">Manage</a>
                          <?php endif; ?>
                        </div>
                      </div>
                    </div>
                  <?php endforeach; ?>
                </div>
              </div>
            </div>
          <?php endforeach; ?>
        <?php endif; ?>
      </div>

      <div class="bg-white rounded shadow p-6">
        <h4 class="text-lg font-semibold mb-4">Recent Inspections</h4>
        <?php if (empty($recent_inspections)): ?>
          <p class="text-sm text-gray-500">No recent inspections.</p>
        <?php else: ?>
          <table class="w-full text-sm">
            <thead class="text-left text-gray-600">
              <tr><th class="py-2">Date</th><th>Market / Stall</th><th>Inspector</th><th>Outcome</th><th></th></tr>
            </thead>
            <tbody>
              <?php foreach ($recent_inspections as $ins): ?>
                <tr class="border-t hover:bg-gray-50">
                  <td class="py-2"><?php echo !empty($ins['inspected_at']) ? date('M j, Y H:i', strtotime($ins['inspected_at'])) : '-'; ?></td>
                  <td><?php echo htmlspecialchars($ins['market_name'] . ' / ' . $ins['stall_number']); ?></td>
                  <td><?php echo htmlspecialchars($ins['inspector_name']); ?></td>
                  <td><?php echo htmlspecialchars($ins['outcome']); ?></td>
                  <td><button class="text-blue-600" onclick="viewInspection(<?php echo (int)$ins['inspection_id']; ?>)">View</button></td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        <?php endif; ?>
      </div>
    </div>

    <!-- Right: Inspect Modal placed here (hidden until invoked from Assigned Markets & Stalls) -->
    <aside class="bg-white rounded shadow p-6">
      <h4 class="font-semibold mb-3">Create Inspection</h4>

      <p class="text-sm text-gray-600 mb-4">Click "Inspect" on any stall to populate this form and submit an inspection for that stall.</p>

      <!-- Inspect form (initially hidden until a stall is selected) -->
      <div id="inspectAsideContainer" class="">
        <form id="inspectFormAside" onsubmit="return false;">
          <?php echo csrf_field(); ?>
          <input type="hidden" id="inspect_stall_id_aside" name="stall_id">
          <input type="hidden" id="inspect_market_id_aside" name="market_id">

          <div class="space-y-3">
            <div>
              <label class="block text-sm">Selected Stall</label>
              <div id="inspect_selected_stall" class="font-medium text-gray-800">None</div>
            </div>

            <div>
              <label class="block text-sm">Outcome</label>
              <select id="inspect_outcome_aside" class="w-full px-3 py-2 border rounded">
                <option value="ok">OK</option>
                <option value="minor_issue">Minor Issue</option>
                <option value="major_issue">Major Issue</option>
              </select>
            </div>

            <div>
              <label class="block text-sm">Notes</label>
              <textarea id="inspect_notes_aside" class="w-full px-3 py-2 border rounded" rows="4"></textarea>
            </div>

            <div>
              <label class="block text-sm">Photos (optional)</label>
              <input id="inspect_photos_aside" type="file" accept="image/*" multiple class="w-full">
              <p class="text-xs text-gray-500 mt-1">Files are uploaded and attached to the inspection.</p>
            </div>

            <div class="flex gap-2">
              <button type="button" id="inspect_submit_btn_aside" onclick="submitInspectionAside()" class="bg-yellow-600 text-white px-4 py-2 rounded">Submit Inspection</button>
              <button type="button" id="inspect_clear_btn_aside" onclick="clearInspectAside()" class="bg-gray-300 px-4 py-2 rounded">Clear</button>
            </div>

            <div id="inspectStatusAside" class="text-sm mt-2"></div>
          </div>
        </form>
      </div>

      <div class="mt-6 text-sm text-gray-600">
        <p>Inspections recorded here are scoped to markets you are assigned to. Major issues will mark stalls as Maintenance and notify market managers (if enabled).</p>
      </div>
    </aside>
  </div>

  <!-- Inspection Details Modal -->
  <div id="inspectionModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
    <div class="bg-white rounded-lg max-w-3xl w-full max-h-[90vh] overflow-auto">
      <div class="p-4 border-b flex items-center justify-between">
        <h3 id="inspectionModalTitle" class="text-lg font-semibold">Inspection</h3>
        <button onclick="closeInspectionModal()" class="text-gray-600">✕</button>
      </div>
      <div id="inspectionModalBody" class="p-4"></div>
      <div class="p-4 border-t text-right"><button onclick="closeInspectionModal()" class="px-4 py-2 bg-gray-200 rounded">Close</button></div>
    </div>
  </div>
</section>

<script>
// Helpers: open/close market stalls
function openMarketStalls(marketId) {
  const el = document.getElementById('market-stalls-' + marketId);
  if (!el) return;
  el.classList.toggle('hidden');
}

// The aside-form based inspection workflow
function openInspectModalFor(stall) {
  // populate aside form (instead of separate modal)
  document.getElementById('inspect_stall_id_aside').value = stall.stall_id;
  document.getElementById('inspect_market_id_aside').value = stall.market_id;
  document.getElementById('inspect_selected_stall').textContent = (stall.market_name ? stall.market_name + ' / ' : '') + (stall.stall_number || stall.stall_id);
  document.getElementById('inspect_notes_aside').value = '';
  document.getElementById('inspect_outcome_aside').value = 'ok';
  document.getElementById('inspect_photos_aside').value = '';
  document.getElementById('inspectStatusAside').textContent = '';
  // focus submit button for quick flow
  const btn = document.getElementById('inspect_submit_btn_aside');
  if (btn) btn.focus();
  // scroll to aside on small screens
  const aside = document.querySelector('aside');
  if (aside && typeof aside.scrollIntoView === 'function') aside.scrollIntoView({ behavior: 'smooth' });
}

function clearInspectAside() {
  document.getElementById('inspect_stall_id_aside').value = '';
  document.getElementById('inspect_market_id_aside').value = '';
  document.getElementById('inspect_selected_stall').textContent = 'None';
  document.getElementById('inspect_notes_aside').value = '';
  document.getElementById('inspect_outcome_aside').value = 'ok';
  document.getElementById('inspect_photos_aside').value = '';
  document.getElementById('inspectStatusAside').textContent = '';
}

async function submitInspectionAside() {
  const stallId = document.getElementById('inspect_stall_id_aside').value;
  const marketId = document.getElementById('inspect_market_id_aside').value;
  const notes = document.getElementById('inspect_notes_aside').value;
  const outcome = document.getElementById('inspect_outcome_aside').value;
  const files = document.getElementById('inspect_photos_aside').files;
  const statusDiv = document.getElementById('inspectStatusAside');

  if (!stallId || !marketId) {
    alert('Select a stall to inspect by clicking Inspect on the Assigned Markets & Stalls list.');
    return;
  }

  statusDiv.textContent = 'Uploading photos...';
  const photoUrls = [];
  for (let i = 0; i < files.length; i++) {
    const f = files[i];
    const fd = new FormData();
    fd.append('photo', f);
    try {
      const resp = await fetch('API/upload_inspection_photo.php', { method: 'POST', credentials: 'same-origin', body: fd });
      const j = await resp.json();
      if (!resp.ok || !j.ok) { statusDiv.textContent = 'Photo upload failed'; return; }
      photoUrls.push({ url: j.url, caption: '' });
    } catch (e) {
      console.error(e); statusDiv.textContent = 'Photo upload failed'; return;
    }
  }

  statusDiv.textContent = 'Creating inspection...';
  const payload = { stall_id: parseInt(stallId,10), market_id: parseInt(marketId,10), outcome, status: 'completed', notes, photos: photoUrls };
  try {
    const r = await fetch('API/inspections.php', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    const j = await r.json();
    if (r.status === 201 && j.ok) {
      statusDiv.textContent = 'Inspection created (ID: ' + j.inspection_id + ')';
      setTimeout(()=>{ clearInspectAside(); location.reload(); }, 800);
    } else {
      statusDiv.textContent = 'Failed to create inspection: ' + (j.error || r.statusText);
    }
  } catch (e) {
    console.error(e); statusDiv.textContent = 'Network error';
  }
}

// View inspection details in modal (calls API)
function viewInspection(id) {
  const body = document.getElementById('inspectionModalBody');
  document.getElementById('inspectionModalTitle').textContent = 'Inspection #' + id;
  body.innerHTML = '<div class="p-4 text-gray-600">Loading…</div>';
  document.getElementById('inspectionModal').classList.remove('hidden');

  fetch('API/inspections.php?inspection_id=' + encodeURIComponent(id) + '&include_photos=1', { credentials: 'same-origin' })
    .then(r => r.ok ? r.json() : r.text().then(t=>{throw new Error(t||r.statusText)}))
    .then(j => {
      const ins = j.inspection || (j.inspections && j.inspections[0]) || j;
      if (!ins) { body.innerHTML = '<div class="text-red-600 p-4">Unavailable</div>'; return; }
      let html = `<div class="space-y-2"><div><strong>Date:</strong> ${ins.inspected_at||''}</div>`;
      html += `<div><strong>Market:</strong> ${escapeHtml(ins.market_name||'')}</div>`;
      html += `<div><strong>Stall:</strong> ${escapeHtml(ins.stall_number||'')}</div>`;
      html += `<div><strong>Inspector:</strong> ${escapeHtml(ins.inspector_name||'')}</div>`;
      html += `<div><strong>Outcome:</strong> ${escapeHtml(ins.outcome||'')}</div>`;
      html += `<div><strong>Notes:</strong><div class="mt-1 p-2 bg-gray-50 rounded">${escapeHtml(ins.notes||'')}</div></div>`;
      html += `<div id="inspectionPhotos" class="mt-3"></div></div>`;
      body.innerHTML = html;
      const photos = j.photos || [];
      if (photos.length) {
        const ph = document.getElementById('inspectionPhotos');
        ph.innerHTML = '<strong>Photos:</strong><div class="mt-2 flex flex-wrap gap-2">';
        photos.forEach(p => ph.innerHTML += `<a href="${escapeHtml(p.storage_url)}" target="_blank" class="block border rounded overflow-hidden"><img src="${escapeHtml(p.storage_url)}" class="h-24 object-cover"></a>`);
        ph.innerHTML += '</div>';
      }
    })
    .catch(err => { body.innerHTML = '<div class="text-red-600 p-4">Failed to load: ' + escapeHtml(err.message||'') + '</div>'; });
}
function closeInspectionModal(){ document.getElementById('inspectionModal').classList.add('hidden'); }
function escapeHtml(s){ if(!s) return ''; return String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#39;'); }
</script>

<?php include 'includes/footer.php'; ?>