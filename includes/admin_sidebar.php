<?php
/**
 * includes/admin_sidebar.php
 * - Sidebar is sticky and full height.
 * - Only the navigation section scrolls (independent scrollbar).
 * - Logout button is pinned to the bottom.
 */

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

require_once __DIR__.'/auth_roles.php';
require_once __DIR__.'/notifications.php';

if (!function_exists('h')) {
    function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES|ENT_SUBSTITUTE); }
}

if (empty($_SESSION['roles']) && !empty($_SESSION['user_id'])) {
    refreshSessionRoles($GLOBALS['db'] ?? null);
}

$roles = array_map('strtolower', (array)($_SESSION['roles'] ?? []));

$is_super          = in_array('super_admin', $roles, true);
$is_issuer         = in_array('issuer_admin', $roles, true);
$is_market_manager = in_array('market_manager', $roles, true);
$is_accountant     = in_array('accountant', $roles, true);
$is_inspector      = in_array('inspector', $roles, true);
$is_vendor         = in_array('vendor', $roles, true);

$is_admin_panel    = shouldUseAdminSidebar($roles);

$db = $GLOBALS['db'] ?? null;

$unread = 0;
try {
    if (!empty($_SESSION['user_id'])) {
        $unread = (int)getUnreadCount($db, (int)$_SESSION['user_id']);
    }
} catch (Throwable $e) {
    error_log("admin_sidebar getUnreadCount: ".$e->getMessage());
}

$PENDING_ROLE_STATUSES = ['pending','under_review','submitted','awaiting_approval'];
$PENDING_DOC_STATUSES  = ['pending','under_review','submitted','awaiting_verification'];
$VENDOR_DOC_TYPES      = ['permit','business_permit','id','government_id','gov_id'];

$pendingRoleRequests = 0;
$pendingVendorUsers  = 0;
$pendingVendorDocs   = 0;

$inRoleStatuses = "('" . implode("','", array_map('strtolower',$PENDING_ROLE_STATUSES)) . "')";
$inDocStatuses  = "('" . implode("','", array_map('strtolower',$PENDING_DOC_STATUSES)) . "')";
$inDocTypes     = "('" . implode("','", array_map('strtolower',$VENDOR_DOC_TYPES)) . "')";

if ($db) {
    try {
        $row = $db->fetch("
            SELECT COUNT(*) AS c
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.role_id
            WHERE LOWER(ur.status) IN {$inRoleStatuses}
              AND r.name NOT IN ('vendor','super_admin')
        ");
        $pendingRoleRequests = (int)($row['c'] ?? 0);
    } catch (Throwable $e) {}

    try {
        $row = $db->fetch("
            SELECT COUNT(DISTINCT ur.user_id) AS c
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.role_id
            WHERE r.name='vendor'
              AND LOWER(ur.status) IN {$inRoleStatuses}
        ");
        $pendingVendorUsers = (int)($row['c'] ?? 0);
    } catch (Throwable $e) {}

    try {
        $row = $db->fetch("
            SELECT COUNT(DISTINCT ur.user_id) AS c
            FROM user_role_documents d
            JOIN user_roles ur ON d.user_role_id = ur.user_role_id
            JOIN roles r       ON ur.role_id     = r.role_id
            WHERE r.name='vendor'
              AND LOWER(d.status)   IN {$inDocStatuses}
              AND LOWER(d.doc_type) IN {$inDocTypes}
        ");
        $pendingVendorDocs = (int)($row['c'] ?? 0);
    } catch (Throwable $e) {}
}

$verifyVendorsBadge = $pendingVendorDocs + $pendingVendorUsers;
$current = basename(parse_url($_SERVER['REQUEST_URI'] ?? $_SERVER['PHP_SELF'], PHP_URL_PATH) ?: '');
?>
<div class="flex min-h-screen">
  <!-- Sidebar: sticky full-height; only nav scrolls -->
  <aside class="hidden lg:flex w-64 bg-gradient-to-b from-blue-900 to-blue-950 text-white sticky top-0 h-screen">
    <div class="flex flex-col w-full">
      <!-- Header (brand + user) - non-scroll -->
      <div class="p-6">
        <!-- Brand -->
        <div class="flex items-center space-x-3 mb-6">
          <svg class="w-10 h-10" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M3 21h18M4 10h16M4 6h16M6 14h2m4 0h2m4 0h2M6 18h2m4 0h2m4 0h2" />
          </svg>
          <div>
            <h1 class="text-xl font-bold">SMMS</h1>
            <p class="text-xs text-blue-200">Admin Panel</p>
          </div>
        </div>

        <!-- User Card -->
        <div class="bg-blue-700/50 rounded-lg p-4">
          <div class="flex items-center space-x-3">
            <div class="w-12 h-12 bg-blue-500 rounded-full flex items-center justify-center text-xl font-bold">
              <?php echo h(strtoupper(substr($_SESSION['full_name'] ?? ($_SESSION['username'] ?? 'A'),0,1))); ?>
            </div>
            <div class="flex-1 min-w-0">
              <p class="font-semibold truncate">
                <?php echo h($_SESSION['full_name'] ?? ($_SESSION['username'] ?? 'Admin')); ?>
              </p>
              <p class="text-xs text-blue-200">
                <?php
                  if      ($is_super)          echo 'Super Admin';
                  elseif  ($is_issuer)         echo 'Issuer Admin';
                  elseif  ($is_market_manager) echo 'Market Manager';
                  elseif  ($is_accountant)     echo 'Accountant';
                  elseif  ($is_inspector)      echo 'Inspector';
                  elseif  ($is_vendor)         echo 'Vendor';
                  else                         echo 'Administrator';
                ?>
              </p>
            </div>
          </div>
        </div>
      </div>

      <!-- Scrollable NAV -->
      <nav class="flex-1 overflow-y-auto overscroll-contain px-6 pb-4 space-y-2">
        <a href="admin_dashboard.php"
           class="flex items-center space-x-3 px-4 py-3 rounded-lg <?php echo $current==='admin_dashboard.php'?'bg-blue-600/50':'hover:bg-blue-700'; ?>">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                d="M3 12l9-7 9 7M5 10v10h5V14h4v6h5V10"/></svg>
          <span>Dashboard</span>
        </a>

        <?php if ($is_market_manager): ?>
          <a href="manage_markets.php"
             class="flex items-center space-x-3 px-4 py-3 rounded-lg <?php echo $current==='manage_markets.php'?'bg-blue-700':'hover:bg-blue-700'; ?>">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M3 20h18M6 20V8a2 2 0 012-2h8a2 2 0 012 2v12M8 12h2m4 0h2M8 16h2m4 0h2"/></svg>
            <span>Markets</span>
          </a>
        <?php endif; ?>

        <?php if ($is_market_manager || $is_vendor): ?>
          <a href="manage_stalls.php"
             class="flex items-center space-x-3 px-4 py-3 rounded-lg <?php echo $current==='manage_stalls.php'?'bg-blue-700':'hover:bg-blue-700'; ?>">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M4 4h7v7H4V4zm9 0h7v7h-7V4zM4 13h7v7H4v-7zm9 0h7v7h-7v-7z"/></svg>
            <span>Stalls</span>
          </a>

          <a href="manage_staff.php"
             class="flex items-center space-x-3 px-4 py-3 rounded-lg <?php echo $current==='manage_staff.php'?'bg-blue-700':'hover:bg-blue-700'; ?>">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a8 8 0 00-8 8h16a8 8 0 00-8-8z" />
            </svg>
            <span>Staff</span>
          </a>
        <?php endif; ?>

        <?php if ($is_market_manager || $is_vendor): ?>
          <a href="manage_applications.php"
             class="flex items-center space-x-3 px-4 py-3 rounded-lg <?php echo $current==='manage_applications.php'?'bg-blue-700':'hover:bg-blue-700'; ?>">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M9 5h6a2 2 0 012 2v1H7V7a2 2 0 012-2zm-2 4h10v10a2 2 0 01-2 2H9a2 2 0 01-2-2V9zm3 5l2 2 4-4"/></svg>
            <span>Applications</span>
          </a>
        <?php endif; ?>

        <?php if ($is_market_manager || $is_vendor): ?>
          <a href="manage_leases.php"
             class="flex items-center space-x-3 px-4 py-3 rounded-lg <?php echo $current==='manage_leases.php'?'bg-blue-700':'hover:bg-blue-700'; ?>">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M7 7h7l3 3v7a2 2 0 01-2 2H7a2 2 0 01-2-2V9a2 2 0 012-2zm0 5h10M7 17h7"/></svg>
            <span>Leases</span>
          </a>
        <?php endif; ?>

        <?php if ($is_accountant || $is_market_manager): ?>
          <a href="manage_payments.php"
             class="flex items-center space-x-3 px-4 py-3 rounded-lg <?php echo $current==='manage_payments.php'?'bg-blue-700':'hover:bg-blue-700'; ?>">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M3 7h18a2 2 0 012 2v7a2 2 0 01-2 2H3a2 2 0 01-2-2V9a2 2 0 012-2zm0 4h22M7 17h6"/></svg>
            <span>Payments</span>
          </a>
        <?php endif; ?>

        <?php if ($is_inspector || $is_market_manager): ?>
          <a href="manage_inspections.php"
             class="flex items-center space-x-3 px-4 py-3 rounded-lg <?php echo $current==='manage_inspections.php'?'bg-blue-700':'hover:bg-blue-700'; ?>">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M9 5h6a2 2 0 012 2v1H7V7a2 2 0 012-2zM7 9h10v10a2 2 0 01-2 2H9a2 2 0 01-2-2V9zm2 3h6m-6 4h6"/></svg>
            <span>Inspections</span>
          </a>
        <?php endif; ?>

        <?php if ($is_market_manager || $is_accountant || $is_super): ?>
          <a href="reports.php"
             class="flex items-center space-x-3 px-4 py-3 rounded-lg <?php echo $current==='reports.php'?'bg-blue-700':'hover:bg-blue-700'; ?>">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M3 3v18h18M7 13l3-3 3 3 5-5" />
            </svg>
            <span>Reports</span>
          </a>
        <?php endif; ?>

        <?php if ($is_issuer || $is_super): ?>
          <a href="verify_vendors.php"
             class="flex items-center space-x-3 px-4 py-3 rounded-lg <?php echo $current==='verify_vendors.php'?'bg-blue-700':'hover:bg-blue-700'; ?>">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M12 3l7 4v5c0 5-3.5 8-7 9-3.5-1-7-4-7-9V7l7-4zm-2 9l2 2 4-4"/></svg>
            <span>Vendor Verification</span>
            <?php if ($verifyVendorsBadge > 0): ?>
              <span class="ml-auto inline-flex items-center justify-center h-5 w-5 rounded-full bg-red-500 text-white text-xs">
                <?php echo $verifyVendorsBadge > 9 ? '9+' : $verifyVendorsBadge; ?>
              </span>
            <?php endif; ?>
          </a>
        <?php endif; ?>

        <?php if ($is_super || $is_issuer || in_array('admin', $roles, true)): ?>
          <a href="admin_pending_requests.php"
             class="flex items-center space-x-3 px-4 py-3 rounded-lg <?php echo $current==='admin_pending_requests.php'?'bg-blue-700':'hover:bg-blue-700'; ?>">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M17 20h5v-2a4 4 0 00-3-3.87M9 20H4v-2a4 4 0 013-3.87M15 11a4 4 0 10-6 0M19 8a3 3 0 11-6 0"/></svg>
            <span>Pending Role Requests</span>
            <?php if ($pendingRoleRequests > 0): ?>
              <span class="ml-auto inline-flex items-center justify-center h-5 w-5 rounded-full bg-red-500 text-white text-xs">
                <?php echo $pendingRoleRequests > 9 ? '9+' : $pendingRoleRequests; ?>
              </span>
            <?php endif; ?>
          </a>
        <?php endif; ?>

        <?php if ($is_admin_panel): ?>
          <a href="settings.php"
             class="flex items-center space-x-3 px-4 py-3 rounded-lg <?php echo $current==='settings.php'?'bg-blue-700':'hover:bg-blue-700'; ?>">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M11.983 6a2 2 0 014 0l.27 1.35a7.96 7.96 0 012.07 1.2l1.3-.37a2 2 0 011.98 3.46l-1.03.77c.06.4.09.82.09 1.24s-.03.84-.09 1.24l1.03.77a2 2 0 01-1.98 3.46l-1.3-.37a7.96 7.96 0 01-2.07 1.2L16 18a2 2 0 01-4 0l-.27-1.35a7.96 7.96 0 01-2.07-1.2l-1.3.37a2 2 0 01-1.98-3.46l1.03-.77A7.9 7.9 0 017 12c0-.42.03-.84.09-1.24l-1.03-.77a2 2 0 011.98-3.46l1.3.37a7.96 7.96 0 012.07-1.2L12 6zM12 9a3 3 0 100 6 3 3 0 000-6z" />
            </svg>
            <span>Settings</span>
          </a>
        <?php endif; ?>
      </nav>

      <!-- Bottom: Logout pinned -->
      <div class="p-6 mt-auto">
        <a href="logout.php" class="block bg-red-500 hover:bg-red-600 px-3 py-2 rounded text-center">Logout</a>
      </div>
    </div>
  </aside>

  <!-- Main content column -->
  <main class="flex-1">
    <nav class="bg-white shadow sticky top-0 z-30">
      <div class="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        <div>
          <h2 class="text-lg font-semibold text-gray-800">
            <?php echo h($page_title ?? 'Admin'); ?>
          </h2>
        </div>
        <div class="flex items-center space-x-4">
          <a href="notifications.php" class="relative" title="Notifications" aria-label="Notifications">
            <svg class="w-6 h-6 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M15 17h5l-1.405-1.405A2 2 0 0118 14.172V11a6 6 0 10-12 0v3.172a2 2 0 01-.595 1.423L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
            </svg>
            <?php if ($unread > 0): ?>
              <span class="absolute -top-1 -right-1 inline-flex items-center justify-center h-5 w-5 rounded-full bg-red-500 text-white text-xs">
                <?php echo $unread > 9 ? '9+' : $unread; ?>
              </span>
            <?php endif; ?>
          </a>
        </div>
      </div>
    </nav>
    <!-- Page content starts here -->