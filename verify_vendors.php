<?php
/**
 * verify_vendors.php
 *
 * Purpose:
 *   - List vendors (pending vs processed) for oversight (no inline approve/reject buttons).
 *   - Simplified stats header: ONLY Total Vendors, Active Vendors, Inactive Vendors.
 *
 * Classification:
 *   Pending Tab: vendor account status = 'pending' OR either permit/id not yet approved.
 *   Processed Tab: vendor account status != 'pending' AND both permit & id approved.
 *
 * Removed:
 *   - Previous detailed stats (pending tab counts, processed tab counts, rejected, etc.)
 *   - Document approve/reject actions (handled elsewhere).
 *
 * Assumptions:
 *   Tables: users, roles, user_roles, user_role_documents
 *   Required vendor docs: permit (required), id (optional but considered for "completed" only if approved).
 */

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/csrf.php';
require_once 'includes/audit.php';
require_once 'includes/helpers.php';

requireAdmin();

$page_title = 'Verify Vendors';
$error   = '';
$success = '';

$current_admin_id = $_SESSION['user_id'] ?? 0;
$sessionRoles     = $_SESSION['roles'] ?? [];
$is_super_admin   = in_array('super_admin', $sessionRoles, true);

/* ---------- Helper Escaper (ensure availability even if helpers.php missing) ---------- */
if (!function_exists('h')) {
    function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE); }
}

/* ---------- Determine if users.role column exists ---------- */
$usersHasRoleColumn = false;
try {
    $col = $db->fetch("SHOW COLUMNS FROM users LIKE 'role'");
    $usersHasRoleColumn = (bool)$col;
} catch (Throwable $e) {
    error_log("verify_vendors: role column detection failed: ".$e->getMessage());
}

/* ---------- Search & Tab ---------- */
$search    = trim((string)($_GET['q'] ?? ''));
$activeTab = ($_GET['tab'] ?? 'pending') === 'processed' ? 'processed' : 'pending';
$searchSql = '';
$paramsSearch = [];
if ($search !== '') {
    $searchSql = " AND (u.full_name LIKE ? OR u.username LIKE ? OR u.email LIKE ? OR u.contact_number LIKE ?)";
    $like="%{$search}%";
    $paramsSearch=[$like,$like,$like,$like];
}

/* ---------- Vendor Retrieval ---------- */
try {
    if ($usersHasRoleColumn) {
        $rawVendors = $db->fetchAll("
            SELECT u.user_id, u.username, u.full_name, u.email, u.contact_number, u.status,
                   u.verification_data, u.created_at
            FROM users u
            WHERE u.role='vendor' {$searchSql}
            ORDER BY u.created_at DESC
            LIMIT 1000
        ", $paramsSearch) ?: [];
    } else {
        $rawVendors = $db->fetchAll("
            SELECT DISTINCT u.user_id, u.username, u.full_name, u.email, u.contact_number, u.status,
                            u.verification_data, u.created_at
            FROM users u
            JOIN user_roles ur ON u.user_id=ur.user_id
            JOIN roles r ON ur.role_id=r.role_id
            WHERE r.name='vendor' {$searchSql}
            ORDER BY u.created_at DESC
            LIMIT 1000
        ", $paramsSearch) ?: [];
    }
} catch (Throwable $e){
    error_log("verify_vendors: vendor fetch fail: ".$e->getMessage());
    $rawVendors=[];
}

/* ---------- Document Fetch Helper ---------- */
function fetchVendorDocuments($db, int $userId, int $limitPerType = 1): array {
    $grouped = ['permit'=>[], 'id'=>[]];
    try {
        $rows = $db->fetchAll("
            SELECT d.user_role_document_id, d.doc_type, d.file_path, d.original_filename,
                   LOWER(d.status) AS status, d.uploaded_at
            FROM user_role_documents d
            JOIN user_roles ur ON d.user_role_id=ur.user_role_id
            JOIN roles r ON ur.role_id=r.role_id
            WHERE ur.user_id=? AND r.name='vendor'
            ORDER BY d.uploaded_at DESC
        ", [$userId]) ?: [];
        foreach ($rows as $r) {
            $t = strtolower($r['doc_type']);
            if (!isset($grouped[$t])) continue;
            if (count($grouped[$t]) < $limitPerType) $grouped[$t][] = $r;
        }
    } catch(Throwable $e){
        error_log("fetchVendorDocuments error user {$userId}: ".$e->getMessage());
    }
    return $grouped;
}

/* ---------- Document Summary ---------- */
function summarizeDocs(array $grouped): array {
    $summary = ['permit'=>'missing','id'=>'missing'];
    foreach (['permit','id'] as $type) {
        foreach ($grouped[$type] as $row) {
            $st = strtolower($row['status']);
            if ($st === 'approved') { $summary[$type]='approved'; break; }
            if ($st === 'rejected' && $summary[$type]!=='approved') { $summary[$type]='rejected'; }
            if (in_array($st,['pending','under_review']) && !in_array($summary[$type],['approved','rejected'])) {
                $summary[$type]='pending';
            }
        }
    }
    return $summary;
}

/* ---------- Classification into Tabs ---------- */
$pendingVendors   = [];
$processedVendors = [];

foreach ($rawVendors as $v) {
    $docsGrouped      = fetchVendorDocuments($db, (int)$v['user_id'], 1);
    $summary          = summarizeDocs($docsGrouped);
    $hasBothApproved  = ($summary['permit']==='approved' && $summary['id']==='approved');
    $acctPending      = strtolower($v['status']) === 'pending';

    if ($acctPending || !$hasBothApproved) {
        $pendingVendors[] = $v + ['_summary'=>$summary,'_docs'=>$docsGrouped];
    } else {
        $processedVendors[] = $v + ['_summary'=>$summary,'_docs'=>$docsGrouped];
    }
}

/* ---------- Simplified Stats: Total / Active / Inactive ---------- */
$vendorStats = ['total'=>0,'active'=>0,'inactive'=>0];
try {
    if ($usersHasRoleColumn) {
        $row = $db->fetch("
            SELECT
              COUNT(*) AS total,
              SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) AS active,
              SUM(CASE WHEN status='inactive' THEN 1 ELSE 0 END) AS inactive
            FROM users
            WHERE role='vendor'
        ") ?: [];
    } else {
        $row = $db->fetch("
            SELECT
              COUNT(DISTINCT u.user_id) AS total,
              SUM(CASE WHEN u.status='active' THEN 1 ELSE 0 END) AS active,
              SUM(CASE WHEN u.status='inactive' THEN 1 ELSE 0 END) AS inactive
            FROM users u
            JOIN user_roles ur ON u.user_id=ur.user_id
            JOIN roles r ON ur.role_id=r.role_id
            WHERE r.name='vendor'
        ") ?: [];
    }
    $vendorStats['total']    = (int)($row['total'] ?? 0);
    $vendorStats['active']   = (int)($row['active'] ?? 0);
    $vendorStats['inactive'] = (int)($row['inactive'] ?? 0);
} catch (Throwable $e) {
    error_log("verify_vendors simplified stats error: ".$e->getMessage());
}

/* ---------- Messages via GET (preserve old compatibility) ---------- */
if (!empty($_GET['msg'])) {
    $mapMsg = [
        'approved'    => 'Vendor approved successfully.',
        'rejected'    => 'Vendor rejected successfully.',
        'docapproved' => 'Document approved successfully.',
        'docrejected' => 'Document rejected successfully.'
    ];
    if (isset($mapMsg[$_GET['msg']])) $success = $mapMsg[$_GET['msg']];
}
if (!empty($_GET['err']) && !$error) {
    $error='An action encountered an error.';
}

/* ---------- Audit View ---------- */
logAudit($db,$current_admin_id,'View Vendor Verification','users',null,null,null);

/* ---------- Include Layout ---------- */
include 'includes/header.php';
include 'includes/admin_sidebar.php';
?>
<section class="max-w-7xl mx-auto p-6">

  <div class="mb-6">
    <h3 class="text-2xl font-bold text-gray-800 mb-2">Verify Vendors</h3>
    <p class="text-gray-600">Overview of vendor accounts and document completion status.</p>
  </div>

  <?php if ($error): ?>
    <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
      <?php echo h($error); ?>
    </div>
  <?php endif; ?>

  <?php if ($success): ?>
    <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-4">
      <?php echo h($success); ?>
    </div>
  <?php endif; ?>

  <!-- Simplified Stats -->
  <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
    <div class="bg-white rounded-lg shadow p-4">
      <p class="text-gray-500 text-xs">Total Vendors</p>
      <h3 class="text-2xl font-bold text-gray-800 mt-1"><?php echo $vendorStats['total']; ?></h3>
    </div>
    <div class="bg-white rounded-lg shadow p-4">
      <p class="text-gray-500 text-xs">Active Vendors</p>
      <h3 class="text-2xl font-bold text-green-600 mt-1"><?php echo $vendorStats['active']; ?></h3>
    </div>
    <div class="bg-white rounded-lg shadow p-4">
      <p class="text-gray-500 text-xs">Inactive Vendors</p>
      <h3 class="text-2xl font-bold text-gray-600 mt-1"><?php echo $vendorStats['inactive']; ?></h3>
    </div>
  </div>

  <!-- Search -->
  <form method="GET" action="" class="bg-white rounded-lg shadow p-4 mb-6 flex flex-wrap gap-4 items-end">
    <div class="flex-1 min-w-[240px]">
      <label class="block text-sm font-medium text-gray-700 mb-2">Search</label>
      <input type="text" name="q" value="<?php echo h($search); ?>"
             placeholder="Name, username, email, contact..."
             class="w-full px-3 py-2 border rounded focus:ring-2 focus:ring-blue-500">
    </div>
    <div class="flex gap-2">
      <input type="hidden" name="tab" value="<?php echo h($activeTab); ?>">
      <button class="px-6 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">Search</button>
      <a href="verify_vendors.php" class="px-6 py-2 bg-gray-300 text-gray-700 rounded hover:bg-gray-400">Reset</a>
    </div>
  </form>

  <!-- Tabs -->
  <div class="flex gap-2 mb-4">
    <a href="?tab=pending<?php if($search!=='') echo '&q='.urlencode($search); ?>"
       class="px-4 py-2 rounded text-sm font-medium <?php echo $activeTab==='pending' ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-700'; ?>">
       Pending (<?php echo count($pendingVendors); ?>)
    </a>
    <a href="?tab=processed<?php if($search!=='') echo '&q='.urlencode($search); ?>"
       class="px-4 py-2 rounded text-sm font-medium <?php echo $activeTab==='processed' ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-700'; ?>">
       Processed (<?php echo count($processedVendors); ?>)
    </a>
  </div>

  <?php
    // Simple badge helper
    function badge($st){
        $map = [
            'approved' => 'bg-green-100 text-green-700',
            'pending'  => 'bg-amber-100 text-amber-700',
            'rejected' => 'bg-red-100 text-red-700',
            'missing'  => 'bg-gray-100 text-gray-700'
        ];
        $cls = $map[$st] ?? 'bg-gray-100 text-gray-700';
        return "<span class='inline-block px-2 py-1 rounded text-[11px] font-semibold {$cls}'>".h(ucfirst($st))."</span>";
    }
  ?>

  <!-- Pending Vendors Table -->
  <?php if ($activeTab==='pending'): ?>
    <div class="bg-white rounded-lg shadow overflow-hidden">
      <?php if (!$pendingVendors): ?>
        <div class="p-8 text-center text-gray-500">No vendors in pending classification.</div>
      <?php else: ?>
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead class="bg-gray-50">
              <tr>
                <th class="px-5 py-3 text-left">Vendor</th>
                <th class="px-5 py-3 text-left">Permit</th>
                <th class="px-5 py-3 text-left">ID</th>
                <th class="px-5 py-3 text-left">Registered</th>
                <th class="px-5 py-3 text-left">Account Status</th>
                <th class="px-5 py-3 text-left">Manage</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-200">
              <?php foreach ($pendingVendors as $v): ?>
                <?php
                  $summary  = $v['_summary'];
                  $docs     = $v['_docs'];
                  $permitDoc = $docs['permit'][0] ?? null;
                  $idDoc     = $docs['id'][0] ?? null;
                  $acctStatus= strtolower($v['status']);
                ?>
                <tr class="hover:bg-gray-50 align-top">
                  <td class="px-5 py-4">
                    <div class="font-medium text-gray-800"><?php echo h($v['full_name']); ?></div>
                    <div class="text-xs text-gray-500">@<?php echo h($v['username']); ?></div>
                    <div class="text-xs text-gray-600"><?php echo h($v['email']); ?></div>
                    <div class="text-xs text-gray-600"><?php echo h($v['contact_number']); ?></div>
                  </td>
                  <td class="px-5 py-4 text-xs">
                    <?php echo badge($summary['permit']); ?>
                    <?php if ($permitDoc && !empty($permitDoc['file_path'])): ?>
                    <?php else: ?>
                      <div class="mt-1 text-[11px] text-gray-500">No permit uploaded.</div>
                    <?php endif; ?>
                  </td>
                  <td class="px-5 py-4 text-xs">
                    <?php echo badge($summary['id']); ?>
                    <?php if ($idDoc && !empty($idDoc['file_path'])): ?>
                      
                    <?php else: ?>
                    <?php endif; ?>
                  </td>
                  <td class="px-5 py-4 text-xs">
                    <div><?php echo h(formatDate($v['created_at'])); ?></div>
                    <div class="text-gray-500"><?php echo date('H:i', strtotime($v['created_at'])); ?></div>
                  </td>
                  <td class="px-5 py-4"><?php echo badge($acctStatus); ?></td>
                  <td class="px-5 py-4">
                    <a href="manage_users.php?user_id=<?php echo (int)$v['user_id']; ?>"
                       class="text-xs px-2 py-1 bg-gray-100 hover:bg-gray-200 rounded inline-block">
                      Manage
                    </a>
                  </td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      <?php endif; ?>
    </div>
  <?php endif; ?>

  <!-- Processed Vendors Table -->
  <?php if ($activeTab==='processed'): ?>
    <div class="bg-white rounded-lg shadow overflow-hidden">
      <?php if (!$processedVendors): ?>
        <div class="p-8 text-center text-gray-500">No processed vendors yet.</div>
      <?php else: ?>
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead class="bg-gray-50">
              <tr>
                <th class="px-5 py-3 text-left">Vendor</th>
                <th class="px-5 py-3 text-left">Permit</th>
                <th class="px-5 py-3 text-left">ID</th>
                <th class="px-5 py-3 text-left">Registered</th>
                <th class="px-5 py-3 text-left">Account Status</th>
                <th class="px-5 py-3 text-left">Manage</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-200">
              <?php foreach ($processedVendors as $v): ?>
                <?php
                  $summary   = $v['_summary'];
                  $docs      = $v['_docs'];
                  $permitDoc = $docs['permit'][0] ?? null;
                  $idDoc     = $docs['id'][0] ?? null;
                  $acctStatus= strtolower($v['status']);
                ?>
                <tr class="hover:bg-gray-50">
                  <td class="px-5 py-4">
                    <div class="font-medium text-gray-800"><?php echo h($v['full_name']); ?></div>
                    <div class="text-xs text-gray-500">@<?php echo h($v['username']); ?></div>
                    <div class="text-xs text-gray-600"><?php echo h($v['email']); ?></div>
                    <div class="text-xs text-gray-600"><?php echo h($v['contact_number']); ?></div>
                  </td>
                  <td class="px-5 py-4 text-xs">
                    <?php echo badge($summary['permit']); ?>
                    <?php if ($permitDoc && !empty($permitDoc['file_path'])): ?>
                      <a href="<?php echo h($permitDoc['file_path']); ?>" target="_blank"
                         class="text-xs text-blue-600 underline ml-1">View</a>
                    <?php endif; ?>
                  </td>
                  <td class="px-5 py-4 text-xs">
                    <?php echo badge($summary['id']); ?>
                    <?php if ($idDoc && !empty($idDoc['file_path'])): ?>
                      <a href="<?php echo h($idDoc['file_path']); ?>" target="_blank"
                         class="text-xs text-blue-600 underline ml-1">View</a>
                    <?php endif; ?>
                  </td>
                  <td class="px-5 py-4 text-xs">
                    <div><?php echo h(formatDate($v['created_at'])); ?></div>
                    <div class="text-gray-500"><?php echo date('H:i', strtotime($v['created_at'])); ?></div>
                  </td>
                  <td class="px-5 py-4"><?php echo badge($acctStatus); ?></td>
                  <td class="px-5 py-4">
                    <a href="manage_users.php?user_id=<?php echo (int)$v['user_id']; ?>"
                       class="text-xs px-2 py-1 bg-gray-100 hover:bg-gray-200 rounded inline-block">Manage</a>
                    <span class="block text-[11px] text-gray-500 mt-1">Complete</span>
                  </td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      <?php endif; ?>
    </div>
  <?php endif; ?>

</section>
<?php include 'includes/footer.php'; ?>