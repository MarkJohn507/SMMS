<?php
// Sidebar for non-super admin accounts (vendors, market_manager, municipal_admin, accountant, inspector, issuer_admin)
// Include this in pages for regular users. It adapts links to the user's active roles.
if (session_status() !== PHP_SESSION_ACTIVE) session_start();

if (!function_exists('getUnreadCount')) require_once __DIR__ . '/notifications.php';

// Ensure $db is available in scope where this file is included (config.php should have been required)
$unread = 0;
if (!empty($_SESSION['user_id'])) {
    try {
        $unread = getUnreadCount($db, $_SESSION['user_id']);
    } catch (Throwable $e) {
        error_log("user_sidebar: getUnreadCount failed: " . $e->getMessage());
        $unread = 0;
    }
}

// Resolve active roles (prefer session, fallback to DB)
$roles = $_SESSION['roles'] ?? [];
if (empty($roles) && !empty($_SESSION['user_id'])) {
    try {
        $rows = $db->fetchAll(
            "SELECT r.name FROM user_roles ur JOIN roles r ON ur.role_id = r.role_id WHERE ur.user_id = ? AND ur.status = 'active'",
            [$_SESSION['user_id']]
        ) ?: [];
        foreach ($rows as $rr) {
            if (!empty($rr['name'])) $roles[] = $rr['name'];
        }
    } catch (Throwable $e) {
        error_log("user_sidebar: role lookup failed: " . $e->getMessage());
    }
}

// convenience helpers
function role_has(array $roles, string $role): bool { return in_array($role, $roles, true); }
function role_any(array $roles, array $wanted): bool {
    foreach ($wanted as $w) if (in_array($w, $roles, true)) return true;
    return false;
}

// derive flags
$is_vendor = role_has($roles, 'vendor');
$is_market_manager = role_has($roles, 'market_manager');
$is_municipal = role_has($roles, 'municipal_admin');
$is_accountant = role_has($roles, 'accountant');
$is_inspector = role_has($roles, 'inspector');
$is_issuer = role_has($roles, 'issuer_admin');

// simple counts (best-effort, don't break page if queries fail)
$myApplications = $myLeases = $myPaymentsDue = 0;
$pendingApplications = $pendingRoleRequests = 0;

try {
    if (!empty($_SESSION['user_id'])) {
        $t = $db->fetch("SELECT COUNT(*) AS c FROM applications WHERE user_id = ?", [$_SESSION['user_id']]);
        $myApplications = (int)($t['c'] ?? 0);

        $t = $db->fetch("SELECT COUNT(*) AS c FROM leases WHERE user_id = ?", [$_SESSION['user_id']]);
        $myLeases = (int)($t['c'] ?? 0);

        $t = $db->fetch("SELECT COUNT(*) AS c FROM payments WHERE user_id = ? AND status = 'due'", [$_SESSION['user_id']]);
        $myPaymentsDue = (int)($t['c'] ?? 0);
    }

    if ($is_market_manager || $is_municipal) {
        // pending applications system-wide (admins/managers will filter by market in their pages)
        $t = $db->fetch("SELECT COUNT(*) AS c FROM applications WHERE status = 'pending'");
        $pendingApplications = (int)($t['c'] ?? 0);
    }
    $t = $db->fetch("SELECT COUNT(*) AS c FROM user_roles WHERE status = 'pending'");
    $pendingRoleRequests = (int)($t['c'] ?? 0);
} catch (Throwable $e) {
    error_log("user_sidebar: summary counts failed: " . $e->getMessage());
}

// render sidebar
?>
<aside class="w-64 bg-gray-50 border-r min-h-screen p-6 hidden lg:block">
  <div class="mb-6">
    <div class="flex items-center gap-3">
      <div class="w-10 h-10 bg-blue-600 text-white rounded-full flex items-center justify-center font-bold"><?php echo htmlspecialchars(strtoupper(substr($_SESSION['full_name'] ?? ($_SESSION['username'] ?? 'U'), 0, 1))); ?></div>
      <div>
        <div class="font-semibold text-gray-800"><?php echo htmlspecialchars($_SESSION['full_name'] ?? ($_SESSION['username'] ?? 'User')); ?></div>
        <div class="text-xs text-gray-500">
          <?php
            if ($is_market_manager) echo 'Market Manager';
            elseif ($is_municipal) echo 'Municipal Admin';
            elseif ($is_accountant) echo 'Accountant';
            elseif ($is_inspector) echo 'Inspector';
            elseif ($is_issuer) echo 'Issuer Admin';
            elseif ($is_vendor) echo 'Vendor';
            else echo 'User';
          ?>
        </div>
      </div>
    </div>
  </div>

  <nav class="space-y-2 text-sm">
    <a href="user_dashboard.php" class="flex items-center justify-between gap-3 px-3 py-2 rounded hover:bg-gray-100 <?php echo basename($_SERVER['PHP_SELF']) == 'user_dashboard.php' ? 'bg-gray-100' : ''; ?>">
      <div class="flex items-center gap-3">
        <svg class="w-5 h-5 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2"/></svg>
        <span>Dashboard</span>
      </div>
    </a>

    <?php if ($is_vendor): ?>
      <a href="my_stalls.php" class="flex items-center justify-between gap-3 px-3 py-2 rounded hover:bg-gray-100 <?php echo basename($_SERVER['PHP_SELF']) == 'my_stalls.php' ? 'bg-gray-100' : ''; ?>">
        <div class="flex items-center gap-3">
          <svg class="w-5 h-5 text-gray-600" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7h18M6 7v10a2 2 0 002 2h8a2 2 0 002-2V7"/></svg>
          <span>My Applications</span>
        </div>
        <?php if ($myApplications > 0): ?><span class="text-xs bg-yellow-100 px-2 py-0.5 rounded text-yellow-800"><?php echo $myApplications; ?></span><?php endif; ?>
      </a>

      <a href="my_leases.php" class="flex items-center justify-between gap-3 px-3 py-2 rounded hover:bg-gray-100 <?php echo basename($_SERVER['PHP_SELF']) == 'my_leases.php' ? 'bg-gray-100' : ''; ?>">
        <div class="flex items-center gap-3">
          <svg class="w-5 h-5 text-gray-600" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6"/></svg>
          <span>My Leases</span>
        </div>
        <?php if ($myLeases > 0): ?><span class="text-xs bg-yellow-100 px-2 py-0.5 rounded text-yellow-800"><?php echo $myLeases; ?></span><?php endif; ?>
      </a>

      <a href="my_payments.php" class="flex items-center justify-between gap-3 px-3 py-2 rounded hover:bg-gray-100 <?php echo basename($_SERVER['PHP_SELF']) == 'my_payments.php' ? 'bg-gray-100' : ''; ?>">
        <div class="flex items-center gap-3">
          <svg class="w-5 h-5 text-gray-600" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v8M8 12h8"/></svg>
          <span>Payments</span>
        </div>
        <?php if ($myPaymentsDue > 0): ?><span class="text-xs bg-red-100 px-2 py-0.5 rounded text-red-800"><?php echo $myPaymentsDue; ?></span><?php endif; ?>
      </a>
    <?php endif; ?>

    <?php if ($is_market_manager): ?>
      <a href="manage_stalls.php" class="flex items-center gap-3 px-3 py-2 rounded hover:bg-gray-100 <?php echo basename($_SERVER['PHP_SELF']) == 'manage_stalls.php' ? 'bg-gray-100' : ''; ?>">
        <svg class="w-5 h-5 text-gray-600" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2"/></svg>
        <span>Stalls</span>
      </a>

      <a href="manage_applications.php" class="flex items-center justify-between gap-3 px-3 py-2 rounded hover:bg-gray-100 <?php echo basename($_SERVER['PHP_SELF']) == 'manage_applications.php' ? 'bg-gray-100' : ''; ?>">
        <div class="flex items-center gap-3">
          <svg class="w-5 h-5 text-gray-600" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6"/></svg>
          <span>Applications</span>
        </div>
        <?php if ($pendingApplications > 0): ?><span class="text-xs bg-yellow-100 px-2 py-0.5 rounded text-yellow-800"><?php echo $pendingApplications; ?></span><?php endif; ?>
      </a>

      <a href="manage_vendors.php" class="flex items-center gap-3 px-3 py-2 rounded hover:bg-gray-100 <?php echo basename($_SERVER['PHP_SELF']) == 'manage_vendors.php' ? 'bg-gray-100' : ''; ?>">
        <svg class="w-5 h-5 text-gray-600" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292"/></svg>
        <span>Vendors</span>
      </a>

      <a href="manage_leases.php" class="flex items-center gap-3 px-3 py-2 rounded hover:bg-gray-100 <?php echo basename($_SERVER['PHP_SELF']) == 'manage_leases.php' ? 'bg-gray-100' : ''; ?>">
        <svg class="w-5 h-5 text-gray-600" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6"/></svg>
        <span>Leases</span>
      </a>

      <a href="reports.php" class="flex items-center gap-3 px-3 py-2 rounded hover:bg-gray-100 <?php echo basename($_SERVER['PHP_SELF']) == 'reports.php' ? 'bg-gray-100' : ''; ?>">
        <svg class="w-5 h-5 text-gray-600" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-2m3 2v-4m3 4v-6"/></svg>
        <span>Reports</span>
      </a>
    <?php endif; ?>

    <?php if ($is_municipal): ?>
      <a href="municipal_markets.php" class="flex items-center gap-3 px-3 py-2 rounded hover:bg-gray-100 <?php echo basename($_SERVER['PHP_SELF']) == 'municipal_markets.php' ? 'bg-gray-100' : ''; ?>">
        <svg class="w-5 h-5 text-gray-600" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7"/></svg>
        <span>Municipal Markets</span>
      </a>

      <a href="admin_pending_requests.php" class="flex items-center justify-between gap-3 px-3 py-2 rounded hover:bg-gray-100 <?php echo basename($_SERVER['PHP_SELF']) == 'admin_pending_requests.php' ? 'bg-gray-100' : ''; ?>">
        <div class="flex items-center gap-3">
          <svg class="w-5 h-5 text-gray-600" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3M3 11h18"/></svg>
          <span>Pending Role Requests</span>
        </div>
        <?php if ($pendingRoleRequests > 0): ?><span class="text-xs bg-red-100 px-2 py-0.5 rounded text-red-800"><?php echo $pendingRoleRequests; ?></span><?php endif; ?>
      </a>
    <?php endif; ?>

    <?php if ($is_accountant): ?>
      <a href="manage_payments.php" class="flex items-center gap-3 px-3 py-2 rounded hover:bg-gray-100 <?php echo basename($_SERVER['PHP_SELF']) == 'manage_payments.php' ? 'bg-gray-100' : ''; ?>">
        <svg class="w-5 h-5 text-gray-600" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 9V7a2 2 0 00-2-2H5"/></svg>
        <span>Payments</span>
      </a>

      <a href="reports.php" class="flex items-center gap-3 px-3 py-2 rounded hover:bg-gray-100 <?php echo basename($_SERVER['PHP_SELF']) == 'reports.php' ? 'bg-gray-100' : ''; ?>">
        <svg class="w-5 h-5 text-gray-600" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-2m3 2v-4"/></svg>
        <span>Reports</span>
      </a>
    <?php endif; ?>

    <?php if ($is_inspector): ?>
      <a href="inspections.php" class="flex items-center gap-3 px-3 py-2 rounded hover:bg-gray-100 <?php echo basename($_SERVER['PHP_SELF']) == 'inspections.php' ? 'bg-gray-100' : ''; ?>">
        <svg class="w-5 h-5 text-gray-600" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4"/></svg>
        <span>Inspections</span>
      </a>
    <?php endif; ?>

    <?php if ($is_issuer): ?>
      <a href="verify_vendors.php" class="flex items-center gap-3 px-3 py-2 rounded hover:bg-gray-100 <?php echo basename($_SERVER['PHP_SELF']) == 'verify_vendors.php' ? 'bg-gray-100' : ''; ?>">
        <svg class="w-5 h-5 text-gray-600" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4"/></svg>
        <span>Verify Vendors</span>
      </a>
    <?php endif; ?>

    <a href="notifications.php" class="flex items-center justify-between gap-3 px-3 py-2 rounded hover:bg-gray-100 <?php echo basename($_SERVER['PHP_SELF']) == 'notifications.php' ? 'bg-gray-100' : ''; ?>">
      <div class="flex items-center gap-3">
        <svg class="w-5 h-5 text-gray-600" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405"/></svg>
        <span>Notifications</span>
      </div>
      <?php if ($unread > 0): ?><span class="text-xs bg-red-100 px-2 py-0.5 rounded text-red-800"><?php echo $unread > 9 ? '9+' : $unread; ?></span><?php endif; ?>
    </a>

  </nav>
</aside>