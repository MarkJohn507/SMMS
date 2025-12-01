<?php
// includes/vendor_sidebar.php
// - Sidebar is sticky and full height.
// - Only the navigation section scrolls (independent scrollbar).
// - Logout button is pinned to the bottom.
// - Top-right name/role removed; sidebar user card preserved.

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
if (!function_exists('getUnreadCount')) require_once __DIR__ . '/notifications.php';

if (!function_exists('h')) {
    function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES|ENT_SUBSTITUTE); }
}

$unread = 0;
$dbInst = $db ?? ($GLOBALS['db'] ?? null);
if (!empty($_SESSION['user_id']) && $dbInst) {
    try { $unread = (int)getUnreadCount($dbInst, (int)$_SESSION['user_id']); }
    catch (Throwable $e) { $unread = 0; }
}

// Active link helper
$current = basename(parse_url($_SERVER['REQUEST_URI'] ?? $_SERVER['PHP_SELF'], PHP_URL_PATH) ?: '');
?>
<div class="flex min-h-screen">
  <!-- Sidebar: sticky full-height; only nav scrolls -->
  <aside class="hidden lg:flex w-64 bg-gradient-to-b from-green-600 to-green-800 text-white sticky top-0 h-screen">
    <div class="flex flex-col w-full">
      <!-- Header (brand + user) - non-scroll -->
      <div class="p-6">
        <!-- Logo and System Name -->
        <div class="flex items-center space-x-3 mb-6">
          <svg class="w-10 h-10" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M3 21h18M4 10h16M4 6h16M6 14h2m4 0h2m4 0h2M6 18h2m4 0h2m4 0h2" />
          </svg>
          <div>
            <h1 class="text-xl font-bold">SMMS</h1>
            <p class="text-xs text-green-200">Vendor Portal</p>
          </div>
        </div>

        <!-- User Info (unchanged; still shows avatar, name, role) -->
        <div class="bg-green-700/50 rounded-lg p-4">
          <div class="flex items-center space-x-3">
            <div class="w-12 h-12 bg-green-500 rounded-full flex items-center justify-center text-xl font-bold">
              <?php echo h(strtoupper(substr($_SESSION['full_name'] ?? ($_SESSION['username'] ?? 'U'), 0, 1))); ?>
            </div>
            <div class="flex-1 min-w-0">
              <p class="font-semibold truncate"><?php echo h($_SESSION['full_name'] ?? ($_SESSION['username'] ?? 'User')); ?></p>
              <p class="text-xs text-green-200">Vendor</p>
            </div>
          </div>
        </div>
      </div>

      <!-- Scrollable Navigation -->
      <nav class="flex-1 overflow-y-auto overscroll-contain px-6 pb-4 space-y-2">
        <a href="vendor_dashboard.php"
           class="flex items-center space-x-3 px-4 py-3 rounded-lg transition <?php echo $current==='vendor_dashboard.php'?'bg-green-700':'hover:bg-green-700'; ?>">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M3 12l9-7 9 7M5 10v10h5V14h4v6h5V10" />
          </svg>
          <span>Dashboard</span>
        </a>

        <a href="browse_stalls.php"
           class="flex items-center space-x-3 px-4 py-3 rounded-lg transition <?php echo $current==='browse_stalls.php'?'bg-green-700':'hover:bg-green-700'; ?>">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M21 21l-4.35-4.35M10 18a8 8 0 110-16 8 8 0 010 16z" />
          </svg>
          <span>Browse Stalls</span>
        </a>

        <a href="my_applications.php"
           class="flex items-center space-x-3 px-4 py-3 rounded-lg transition <?php echo $current==='my_applications.php'?'bg-green-700':'hover:bg-green-700'; ?>">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M9 5h6a2 2 0 012 2v1H7V7a2 2 0 012-2zm-2 4h10v10a2 2 0 01-2 2H9a2 2 0 01-2-2V9zm3 6l2 2 4-4" />
          </svg>
          <span>My Applications</span>
        </a>

        <a href="my_leases.php"
           class="flex items-center space-x-3 px-4 py-3 rounded-lg transition <?php echo $current==='my_leases.php'?'bg-green-700':'hover:bg-green-700'; ?>">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M7 7h7l3 3v7a2 2 0 01-2 2H7a2 2 0 01-2-2V9a2 2 0 012-2zm0 5h10M7 17h7" />
          </svg>
          <span>My Leases</span>
        </a>

        <div class="space-y-1">
          <a href="my_payments.php"
             class="flex items-center space-x-3 px-4 py-3 rounded-lg transition <?php echo $current==='my_payments.php'?'bg-green-700':'hover:bg-green-700'; ?>">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M3 7h18a2 2 0 012 2v7a2 2 0 01-2 2H3a2 2 0 01-2-2V9a2 2 0 012-2zm0 4h22M7 17h6" />
            </svg>
            <span>Payment History</span>
          </a>

          <a href="submit_payment.php"
             class="flex items-center space-x-3 px-4 py-3 rounded-lg transition <?php echo $current==='submit_payment.php'?'bg-green-700':'hover:bg-green-700'; ?>">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M3 7h18a2 2 0 012 2v6a2 2 0 01-2 2H3a2 2 0 01-2-2V9a2 2 0 012-2z" />
              <circle cx="12" cy="12" r="2" stroke-width="2"></circle>
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M19 6v4m2-2h-4" />
            </svg>
            <span>Submit Payment</span>
          </a>
        </div>

        <a href="settings.php"
           class="flex items-center space-x-3 px-4 py-3 rounded-lg transition <?php echo $current==='settings.php'?'bg-green-700':'hover:bg-green-700'; ?>">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M11.983 6a2 2 0 014 0l.27 1.35a7.96 7.96 0 012.07 1.2l1.3-.37a2 2 0 011.98 3.46l-1.03.77c.06.4.09.82.09 1.24s-.03.84-.09 1.24l1.03.77a2 2 0 01-1.98 3.46l-1.3-.37a7.96 7.96 0 01-2.07 1.2L16 18a2 2 0 01-4 0l-.27-1.35a7.96 7.96 0 01-2.07-1.2l-1.3.37a2 2 0 01-1.98-3.46l1.03-.77A7.9 7.9 0 017 12c0-.42.03-.84.09-1.24l-1.03-.77a2 2 0 011.98-3.46l1.3.37a7.96 7.96 0 012.07-1.2L12 6zM12 9a3 3 0 100 6 3 3 0 000-6z" />
          </svg>
          <span>Settings</span>
        </a>
      </nav>

      <!-- Bottom: Logout pinned -->
      <div class="p-6 mt-auto">
        <a href="logout.php"
           class="flex items-center gap-2 bg-red-500 hover:bg-red-600 px-3 py-2 rounded transition text-center justify-center"
           aria-label="Logout">
          <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M17 16l4-4m0 0l-4-4m4 4H9m4 8H7a2 2 0 01-2-2V6a2 2 0 012-2h6" />
          </svg>
          Logout
        </a>
      </div>
    </div>
  </aside>

  <!-- Content column -->
  <main class="flex-1">
    <!-- Top nav: name & role removed; only bell retained -->
    <nav class="bg-white shadow sticky top-0 z-30">
      <div class="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        <div>
          <h2 class="text-lg font-semibold text-gray-800"><?php echo h($page_title ?? 'Dashboard'); ?></h2>
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
    <!-- Page content continues -->