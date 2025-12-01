<?php
require_once 'config.php';
require_once 'includes/helpers.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/csrf.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

$stall_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$compact  = isset($_GET['compact']) ? (int)$_GET['compact'] : 0;

if ($stall_id <= 0) {
    http_response_code(400);
    echo $compact ? '<div class="text-red-600 text-sm p-3">Invalid stall id.</div>' : "Invalid stall id.";
    exit;
}
$stall = $db->fetch("
    SELECT s.stall_id, s.stall_number, s.floor_number, s.stall_size,
           s.monthly_rent, s.dimensions, s.description,
           s.status,
           m.market_id, m.market_name, m.location
    FROM stalls s
    JOIN markets m ON s.market_id = m.market_id
    WHERE s.stall_id = ? LIMIT 1
", [$stall_id]);

if (!$stall) {
    http_response_code(404);
    echo $compact ? '<div class="text-red-600 text-sm p-3">Stall not found.</div>' : "Stall not found.";
    exit;
}

logAudit($db, $_SESSION['user_id'] ?? null, 'View Stall Details', 'stalls', $stall_id, null, $compact ? 'compact' : 'full');

/* Helpers */
if (!function_exists('formatCurrency')) {
    function formatCurrency($amount){ return '₱'.number_format((float)$amount,2); }
}
if (!function_exists('formatDate')) {
    function formatDate($date, $withTime=false){
        if (!$date || $date==='0000-00-00' || $date==='0000-00-00 00:00:00') return '-';
        $fmt = $withTime ? 'M j, Y g:i A' : 'M j, Y';
        $ts = strtotime($date);
        return $ts ? date($fmt, $ts) : '-';
    }
}

$lease = null;
$lease_is_current = false;
try {
    $lease = $db->fetch("
        SELECT l.lease_id, l.lease_start_date, l.lease_end_date, l.monthly_rent, l.status,
               u.full_name AS vendor_name
        FROM leases l
        JOIN users u ON l.vendor_id = u.user_id
        WHERE l.stall_id = ?
        ORDER BY l.lease_start_date DESC
        LIMIT 1
    ", [$stall_id]);

    if ($lease) {
        $statusNorm = strtolower(trim((string)$lease['status']));
        $today = new DateTime('today');
        $endStr = $lease['lease_end_date'] ?? null;
        $endOk = ($endStr && $endStr!=='0000-00-00' && $endStr!=='0000-00-00 00:00:00');
        $endDate = $endOk ? DateTime::createFromFormat('Y-m-d', substr($endStr,0,10)) : null;

        $isActiveLabel = in_array($statusNorm, ['active','ongoing','current'], true);
        $notTerminatedLabel = !in_array($statusNorm, ['terminated','cancelled','ended','expired','closed'], true);
        $dateInFuture = $endDate ? ($endDate >= $today) : true;

        $lease_is_current = $isActiveLabel || ($notTerminatedLabel && $dateInFuture);
    } else {
        $lease = $db->fetch("
            SELECT l.lease_id, l.lease_start_date, l.lease_end_date, l.monthly_rent, l.status,
                   u.full_name AS vendor_name
            FROM leases l
            JOIN users u ON l.vendor_id = u.user_id
            WHERE l.stall_id = ?
              AND LOWER(TRIM(l.status)) NOT IN ('terminated','cancelled','ended','expired','closed')
            ORDER BY l.lease_start_date DESC
            LIMIT 1
        ", [$stall_id]);
        if ($lease) $lease_is_current = true;
    }
} catch (Throwable $e) {
    error_log("stall_details: lease lookup failed: ".$e->getMessage());
}

/* =========================================
   COMPACT MODE (Embedded)
   ========================================= */
if ($compact) {
    $apps = [];
    try {
        $apps = $db->fetchAll("
            SELECT a.application_id, a.business_name, a.business_type,
                   a.application_date, a.preferred_start_date
            FROM applications a
            WHERE a.stall_id = ?
              AND LOWER(TRIM(a.status)) = 'pending'
            ORDER BY a.application_date DESC
            LIMIT 50
        ", [$stall_id]) ?: [];
    } catch (Throwable $e) {
        error_log("stall_details compact apps: ".$e->getMessage());
        $apps = [];
    }

    $stallStatus = strtolower((string)$stall['status']);
    ?>
    <div id="compactStallDetails" class="p-4 space-y-4">
      <!-- Header -->
      <div class="rounded-lg border bg-white p-4">
        <div class="flex items-start justify-between">
          <div class="space-y-1">
            <h3 class="text-base font-semibold text-gray-900">
              Stall <?php echo htmlspecialchars($stall['stall_number']); ?>
            </h3>
            <p class="text-xs text-gray-600">
              <?php echo htmlspecialchars($stall['market_name']); ?> • <?php echo htmlspecialchars($stall['location']); ?>
            </p>
          </div>
          <div class="text-right">
            <p class="text-[11px] text-gray-500">Floor</p>
            <p class="text-sm font-medium text-gray-800"><?php echo (int)$stall['floor_number']; ?></p>
          </div>
        </div>

        <?php if ($stallStatus === 'occupied' && $lease): ?>
          <div class="mt-3 rounded-md bg-blue-50 border border-blue-200 p-3">
            <p class="text-xs font-medium text-blue-800">
              <?php echo $lease_is_current ? 'Current lease' : 'Lease period'; ?>
            </p>
            <p class="text-xs text-blue-700">
              <?php echo formatDate($lease['lease_start_date']); ?> — <?php echo formatDate($lease['lease_end_date']); ?>
            </p>
          </div>
        <?php endif; ?>
      </div>

      <!-- Key Info -->
      <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div class="rounded-lg border bg-white p-3">
          <p class="text-[11px] text-gray-500">Size</p>
          <p class="text-sm font-medium text-gray-800"><?php echo htmlspecialchars($stall['stall_size']); ?></p>
        </div>
        <div class="rounded-lg border bg-white p-3">
          <p class="text-[11px] text-gray-500">Monthly Rent</p>
          <p class="text-sm font-medium text-gray-800"><?php echo formatCurrency($stall['monthly_rent']); ?>/mo</p>
        </div>
        <div class="rounded-lg border bg-white p-3">
          <p class="text-[11px] text-gray-500">Dimensions</p>
          <p class="text-sm font-medium text-gray-800"><?php echo htmlspecialchars($stall['dimensions'] ?: '-'); ?></p>
        </div>
      </div>

      <?php if (!empty($stall['dimensions']) || !empty($stall['description'])): ?>
      <div class="rounded-lg border bg-white p-4 space-y-3">
        <?php if (!empty($stall['dimensions'])): ?>
          <div class="space-y-1">
            <p class="text-[11px] text-gray-500">Dimensions</p>
            <p class="text-sm text-gray-800"><?php echo htmlspecialchars($stall['dimensions']); ?></p>
          </div>
        <?php endif; ?>
        <?php if (!empty($stall['description'])): ?>
          <div class="space-y-1">
            <p class="text-[11px] text-gray-500">Description</p>
            <p class="text-sm text-gray-800 whitespace-pre-line leading-relaxed"><?php echo htmlspecialchars($stall['description']); ?></p>
          </div>
        <?php endif; ?>
      </div>
      <?php endif; ?>

      <!-- Current Applications -->
      <div class="rounded-lg border bg-white p-4">
        <div class="flex items-center justify-between mb-2">
          <h4 class="text-sm font-semibold text-gray-900">Current applications</h4>
        </div>
        <?php if (empty($apps)): ?>
          <p class="text-xs text-gray-600">No current applications.</p>
        <?php else: ?>
          <div class="space-y-2">
            <?php foreach ($apps as $a): ?>
              <div class="rounded border p-3">
                <div class="text-sm font-medium text-gray-900"><?php echo htmlspecialchars($a['business_name']); ?></div>
                <?php if (!empty($a['business_type'])): ?>
                  <div class="text-[11px] text-gray-600"><?php echo htmlspecialchars($a['business_type']); ?></div>
                <?php endif; ?>
                <div class="text-[11px] text-gray-600">Applied: <?php echo formatDate($a['application_date']); ?></div>
                <?php if (!empty($a['preferred_start_date'])): ?>
                  <div class="text-[11px] text-gray-600">Preferred start: <?php echo htmlspecialchars(formatDate($a['preferred_start_date'])); ?></div>
                <?php endif; ?>
              </div>
            <?php endforeach; ?>
          </div>
        <?php endif; ?>
      </div>
    </div>
    <?php
    exit;
}

/* =========================================
   FULL VIEW (Standalone page)
   ========================================= */
$applications = $db->fetchAll("
    SELECT a.*, u.full_name as vendor_name
    FROM applications a
    JOIN users u ON a.vendor_id = u.user_id
    WHERE a.stall_id = ?
    ORDER BY a.application_date DESC
    LIMIT 12
", [$stall_id]);

require_once 'includes/header.php';
require_once (isAdmin() ? 'includes/admin_sidebar.php' : ( userIsInRole($db, $_SESSION['user_id'] ?? 0, 'vendor') ? 'includes/vendor_sidebar.php' : 'includes/header.php' ));
$stallStatus = strtolower((string)$stall['status']);
?>
<section class="max-w-5xl mx-auto p-6 space-y-6">
  <!-- Header -->
  <div class="bg-white rounded-lg shadow p-5">
    <div class="flex items-start justify-between">
      <div class="space-y-1">
        <h1 class="text-2xl font-bold text-gray-900">Stall <?php echo htmlspecialchars($stall['stall_number']); ?></h1>
        <p class="text-sm text-gray-600"><?php echo htmlspecialchars($stall['market_name']); ?> • <?php echo htmlspecialchars($stall['location']); ?></p>
      </div>
      <div class="text-right">
        <p class="text-xs text-gray-500">Status</p>
        <p class="inline-block mt-1 px-2 py-1 rounded text-xs font-semibold bg-gray-100 text-gray-700">
          <?php echo htmlspecialchars(ucfirst(str_replace('_',' ',$stall['status']))); ?>
        </p>
      </div>
    </div>
    <?php if ($stallStatus === 'occupied' && $lease): ?>
      <div class="mt-3 rounded-md bg-blue-50 border border-blue-200 p-3">
        <p class="text-xs font-medium text-blue-800"><?php echo $lease_is_current ? 'Current lease' : 'Lease period'; ?></p>
        <p class="text-xs text-blue-700">
          <?php echo formatDate($lease['lease_start_date']); ?> — <?php echo formatDate($lease['lease_end_date']); ?>
        </p>
      </div>
    <?php endif; ?>
  </div>

  <!-- Key Info -->
  <div class="bg-white rounded-lg shadow p-5 space-y-4">
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
      <div>
        <p class="text-xs text-gray-500">Size</p>
        <p class="font-semibold text-gray-800"><?php echo htmlspecialchars($stall['stall_size']); ?></p>
      </div>
      <div>
        <p class="text-xs text-gray-500">Floor</p>
        <p class="font-semibold text-gray-800"><?php echo (int)$stall['floor_number']; ?></p>
      </div>
      <div>
        <p class="text-xs text-gray-500">Monthly Rent</p>
        <p class="font-semibold text-gray-800"><?php echo formatCurrency($stall['monthly_rent']); ?> / mo</p>
      </div>
      <div>
        <p class="text-xs text-gray-500">Dimensions</p>
        <p class="font-semibold text-gray-800"><?php echo htmlspecialchars($stall['dimensions'] ?: '-'); ?></p>
      </div>
    </div>

    <?php if (!empty($stall['dimensions'])): ?>
      <div class="space-y-1">
        <p class="text-xs text-gray-500">Dimensions</p>
        <p class="text-sm text-gray-800"><?php echo htmlspecialchars($stall['dimensions']); ?></p>
      </div>
    <?php endif; ?>

    <?php if (!empty($stall['description'])): ?>
      <div class="space-y-1">
        <p class="text-xs text-gray-500">Description</p>
        <p class="text-sm text-gray-800 whitespace-pre-line leading-relaxed"><?php echo htmlspecialchars($stall['description']); ?></p>
      </div>
    <?php endif; ?>

    <div class="pt-2 flex flex-wrap gap-3">
      <?php if (userIsInRole($db, $_SESSION['user_id'] ?? 0, 'vendor') && $stallStatus === 'available'): ?>
        <button onclick="openApplyModal(<?php echo (int)$stall['stall_id']; ?>, '<?php echo htmlspecialchars(addslashes($stall['stall_number'])); ?>')" class="bg-blue-600 text-white px-4 py-2 rounded">Apply for Stall</button>
      <?php elseif ($stallStatus === 'occupied' && $lease): ?>
        <a href="lease_details.php?id=<?php echo (int)$lease['lease_id']; ?>" class="bg-gray-200 px-4 py-2 rounded text-gray-800">View Lease</a>
      <?php endif; ?>
      <?php if (isAdmin() || userIsInRole($db, $_SESSION['user_id'] ?? null, 'market_manager')): ?>
        <a href="manage_stalls.php?edit=<?php echo (int)$stall['stall_id']; ?>" class="bg-gray-100 px-4 py-2 rounded">Edit Stall</a>
      <?php endif; ?>
    </div>
  </div>

  <!-- Lease / Occupancy (full panel) -->
  <div class="bg-white rounded-lg shadow p-5">
    <h3 class="text-lg font-semibold mb-3 text-gray-900">Lease / Occupancy</h3>
    <?php if ($lease): ?>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div class="space-y-1">
          <p class="text-xs text-gray-500">Vendor</p>
          <p class="font-semibold text-gray-800"><?php echo htmlspecialchars($lease['vendor_name'] ?? ''); ?></p>
          <p class="text-xs text-gray-600">Lease ID: <?php echo (int)$lease['lease_id']; ?></p>
        </div>
        <div class="space-y-1">
          <p class="text-xs text-gray-500">Term</p>
          <p class="font-semibold text-gray-800"><?php echo formatDate($lease['lease_start_date']); ?> — <?php echo formatDate($lease['lease_end_date']); ?></p>
          <p class="text-xs text-gray-600 mt-1">Monthly rent: <?php echo formatCurrency($lease['monthly_rent']); ?></p>
        </div>
      </div>
      <?php if (isAdmin()): ?>
        <div class="mt-4">
          <a href="lease_details.php?id=<?php echo (int)$lease['lease_id']; ?>" class="px-3 py-2 bg-blue-600 text-white rounded">View Lease Details</a>
        </div>
      <?php endif; ?>
    <?php else: ?>
      <p class="text-gray-600">This stall has no active lease.</p>
    <?php endif; ?>
  </div>

  <!-- Recent Applications -->
  <div class="bg-white rounded-lg shadow p-5">
    <h3 class="text-lg font-semibold mb-3 text-gray-900">Recent Applications</h3>
    <?php if ($applications && count($applications) > 0): ?>
      <div class="space-y-3">
        <?php foreach ($applications as $a): ?>
          <div class="rounded border p-3 flex items-start justify-between">
            <div class="space-y-1">
              <p class="font-semibold text-gray-900">
                <?php echo htmlspecialchars($a['vendor_name']); ?>
                <span class="text-xs text-gray-500"> • #<?php echo (int)$a['application_id']; ?></span>
              </p>
              <p class="text-sm text-gray-800">
                <?php echo htmlspecialchars($a['business_name']); ?>
                <?php if (!empty($a['business_type'])): ?> — <?php echo htmlspecialchars($a['business_type']); ?><?php endif; ?>
              </p>
              <p class="text-xs text-gray-600">Applied: <?php echo formatDate($a['application_date']); ?></p>
            </div>
            <div class="text-right">
              <span class="inline-block px-2 py-1 rounded text-xs font-semibold bg-gray-100 text-gray-700">
                <?php echo htmlspecialchars(ucfirst(str_replace('_',' ',$a['status']))); ?>
              </span>
              <div class="mt-2">
                <a href="application_details.php?id=<?php echo (int)$a['application_id']; ?>" class="text-xs text-blue-600 hover:underline">View</a>
              </div>
            </div>
          </div>
        <?php endforeach; ?>
      </div>
    <?php else: ?>
      <p class="text-gray-600">No applications yet for this stall.</p>
    <?php endif; ?>
  </div>
</section>

<!-- Apply Modal -->
<div id="applyModal" class="hidden fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
  <div class="bg-white rounded-lg w-full max-w-lg p-6">
    <div class="flex items-center justify-between mb-4">
      <h3 class="text-xl font-semibold text-gray-900">Apply for Stall</h3>
      <button onclick="closeApplyModal()" class="text-gray-500 hover:text-gray-700">✕</button>
    </div>
    <form method="POST" action="submit_application.php">
      <?php echo csrf_field(); ?>
      <input type="hidden" name="stall_id" id="apply_stall_id">
      <div class="mb-3">
        <label class="block text-sm text-gray-700">Business Name *</label>
        <input name="business_name" id="apply_business_name" required class="w-full border rounded px-3 py-2">
      </div>
      <div class="mb-4">
        <label class="block text-sm text-gray-700">Business Type *</label>
        <input name="business_type" id="apply_business_type" required class="w-full border rounded px-3 py-2">
      </div>
      <div class="flex gap-2">
        <button class="bg-blue-600 text-white px-4 py-2 rounded">Submit Application</button>
        <button type="button" onclick="closeApplyModal()" class="bg-gray-300 text-gray-800 px-4 py-2 rounded">Cancel</button>
      </div>
    </form>
  </div>
</div>

<script>
function openApplyModal(stallId, stallLabel) {
  document.getElementById('apply_stall_id').value = stallId;
  document.getElementById('apply_business_name').value = stallLabel + ' Business';
  document.getElementById('apply_business_type').value = '';
  document.getElementById('applyModal').classList.remove('hidden');
}
function closeApplyModal() {
  document.getElementById('applyModal').classList.add('hidden');
}
</script>

<?php include 'includes/footer.php'; ?>