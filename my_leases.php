<?php
require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/csrf.php';
require_once 'includes/helpers.php';
require_once 'includes/billing.php';   // access billing helpers

// Ensure user is logged in and is a vendor
if (!isLoggedIn()) redirect('login.php?timeout=1');
$user_id = (int)($_SESSION['user_id'] ?? 0);
requireVendor();

$page_title = 'My Leases';

// Enforce billing rules for THIS vendor (cron-free safety)
try {
    ensureMonthlyInvoices($db, $user_id);        // make sure current-month invoice exists
    autoTerminateLeasesPastGrace($db, $user_id); // terminate any leases past grace window
} catch (Throwable $e) {
    error_log("my_leases enforce billing failed for user {$user_id}: ".$e->getMessage());
}

$graceDays = billing_grace_days();

// Tab handling: Active Leases | Terminated
$allowedTabs = ['active','terminated'];
$tab = isset($_GET['tab']) ? strtolower(trim(sanitize($_GET['tab']))) : 'active';
if (!in_array($tab, $allowedTabs, true)) $tab = 'active';

$activeStatuses     = ['active','ongoing','current'];
$terminatedStatuses = ['terminated','expired','ended','cancelled'];

// Build tab counts (badges)
$counts = ['active' => 0, 'terminated' => 0];
try {
    $rows = $db->fetchAll("
        SELECT LOWER(TRIM(status)) AS s, COUNT(*) AS c
        FROM leases
        WHERE vendor_id = ?
        GROUP BY LOWER(TRIM(status))
    ", [$user_id]) ?: [];
    foreach ($rows as $r) {
        $s = strtolower((string)($r['s'] ?? ''));
        $c = (int)($r['c'] ?? 0);
        if (in_array($s, $activeStatuses, true))      $counts['active']     += $c;
        if (in_array($s, $terminatedStatuses, true))  $counts['terminated'] += $c;
    }
} catch (Throwable $e) {
    error_log("my_leases: count badges failed: ".$e->getMessage());
}

// Build main WHERE for the selected tab
$where = "l.vendor_id = ?";
$params = [$user_id];

if ($tab === 'active') {
    $ph = implode(',', array_fill(0, count($activeStatuses), '?'));
    $where .= " AND LOWER(TRIM(l.status)) IN ($ph)";
    foreach ($activeStatuses as $s) $params[] = $s;
} else {
    $ph = implode(',', array_fill(0, count($terminatedStatuses), '?'));
    $where .= " AND LOWER(TRIM(l.status)) IN ($ph)";
    foreach ($terminatedStatuses as $s) $params[] = $s;
}

// Fetch leases for this vendor and tab, including balance computation
try {
    $leases = $db->fetchAll(
        "SELECT 
            l.*,
            s.stall_number, s.stall_size, 
            m.market_name,
            CASE 
                WHEN l.lease_end_date IS NULL OR l.lease_end_date = '0000-00-00' THEN NULL
                ELSE DATEDIFF(l.lease_end_date, CURDATE())
            END AS days_remaining,
            (SELECT COUNT(*) 
               FROM payments p 
              WHERE p.lease_id = l.lease_id 
                AND LOWER(TRIM(p.status)) IN ('pending','partial','overdue')
            ) AS pending_payments,
            (SELECT COUNT(*)
               FROM payments p
              WHERE p.lease_id = l.lease_id
                AND LOWER(TRIM(p.status)) IN ('pending','partial','overdue')
                AND CURDATE() > DATE(p.due_date)
                AND CURDATE() <= DATE_ADD(DATE(p.due_date), INTERVAL {$graceDays} DAY)
            ) AS in_grace_payments,
            COALESCE((
                SELECT SUM(
                    CASE 
                        WHEN p.amount IS NULL THEN 0
                        WHEN (SELECT COUNT(*) FROM information_schema.columns 
                              WHERE table_schema = DATABASE() AND table_name = 'payments' AND column_name = 'amount_paid') > 0
                             THEN (p.amount - COALESCE(p.amount_paid, 0))
                        ELSE p.amount
                    END
                )
                FROM payments p
                WHERE p.lease_id = l.lease_id
                  AND LOWER(TRIM(p.status)) IN ('pending','partial','overdue')
            ), 0) AS balance_amount
         FROM leases l
         JOIN stalls s ON l.stall_id = s.stall_id
         JOIN markets m ON s.market_id = m.market_id
         WHERE $where
         ORDER BY l.lease_start_date DESC",
        $params
    );
} catch (Throwable $e) {
    error_log("my_leases: failed to fetch leases for user {$user_id}: " . $e->getMessage());
    $leases = [];
}

logAudit($db, $user_id, 'View Leases', 'leases', null, null, null);

require_once 'includes/header.php';
require_once 'includes/vendor_sidebar.php';

// Preserve query for tab URLs
$preserve = [];
function tabUrl(array $preserve, string $tab): string {
    $q = array_filter($preserve, fn($v)=>$v!==null && $v!=='');
    $q['tab'] = $tab;
    return 'my_leases.php?' . http_build_query($q) . '#leases';
}
?>
<section class="max-w-7xl mx-auto p-6" id="leases">
  <!-- Tabs: Active | Terminated -->
  <div class="mb-4 flex flex-wrap gap-2">
    <a href="<?php echo htmlspecialchars(tabUrl($preserve, 'active')); ?>"
       class="px-4 py-2 rounded font-medium transition <?php echo $tab==='active' ? 'bg-green-600 text-white' : 'bg-gray-100 text-gray-800 hover:bg-gray-200'; ?>">
      Active Leases
      <span class="ml-2 text-xs px-2 py-0.5 rounded-full <?php echo $tab==='active' ? 'bg-white text-green-700' : 'bg-gray-200 text-gray-800'; ?>">
        <?php echo (int)$counts['active']; ?>
      </span>
    </a>
    <a href="<?php echo htmlspecialchars(tabUrl($preserve, 'terminated')); ?>"
       class="px-4 py-2 rounded font-medium transition <?php echo $tab==='terminated' ? 'bg-green-600 text-white' : 'bg-gray-100 text-gray-800 hover:bg-gray-200'; ?>">
      Terminated
      <span class="ml-2 text-xs px-2 py-0.5 rounded-full <?php echo $tab==='terminated' ? 'bg-white text-green-700' : 'bg-gray-200 text-gray-800'; ?>">
        <?php echo (int)$counts['terminated']; ?>
      </span>
    </a>
  </div>

  <?php if (!empty($leases)): ?>
    <div class="bg-white rounded shadow overflow-hidden">
      <div class="overflow-x-auto">
        <table class="w-full">
          <thead class="bg-gray-50">
            <tr>
              <th class="py-3 px-4 text-left text-sm font-medium text-gray-700">Business</th>
              <th class="py-3 px-4 text-left text-sm font-medium text-gray-700">Stall</th>
              <th class="py-3 px-4 text-left text-sm font-medium text-gray-700">Term</th>
              <th class="py-3 px-4 text-left text-sm font-medium text-gray-700">Rent</th>
              <th class="py-3 px-4 text-left text-sm font-medium text-gray-700">Balance</th>
              <th class="py-3 px-4 text-left text-sm font-medium text-gray-700">Notes</th>
              <th class="py-3 px-4 text-left text-sm font-medium text-gray-700">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-200">
            <?php foreach ($leases as $l): ?>
              <?php
                $lease_id      = (int)($l['lease_id'] ?? 0);
                $business_name = htmlspecialchars($l['business_name'] ?? '');
                $market_name   = htmlspecialchars($l['market_name'] ?? '');
                $stall_number  = htmlspecialchars($l['stall_number'] ?? '');
                $start         = !empty($l['lease_start_date']) ? formatDate($l['lease_start_date']) : '-';
                $end           = !empty($l['lease_end_date']) ? formatDate($l['lease_end_date'])   : ($tab==='active' ? 'Ongoing' : '-');
                $rent          = formatCurrency($l['monthly_rent'] ?? 0);

                $status_lc          = strtolower((string)($l['status'] ?? ''));
                $days_remaining     = isset($l['days_remaining']) ? (int)$l['days_remaining'] : null;
                $pending_payments   = isset($l['pending_payments']) ? (int)$l['pending_payments'] : 0;
                $in_grace_payments  = isset($l['in_grace_payments']) ? (int)$l['in_grace_payments'] : 0;
                $balance_amount     = (float)($l['balance_amount'] ?? 0);

                $notes = [];
                if ($days_remaining !== null) {
                    if ($days_remaining < 0) {
                        $notes[] = '<span class="text-xs text-red-600 font-semibold">Expired</span>';
                    } elseif ($days_remaining <= 30 && in_array($status_lc, $activeStatuses, true)) {
                        $notes[] = '<span class="text-xs text-orange-600 font-semibold">Expires in ' . $days_remaining . ' day' . ($days_remaining === 1 ? '' : 's') . '</span>';
                    }
                }
                if ($pending_payments > 0) {
                    $notes[] = '<span class="text-xs text-red-600">Open invoices: ' . $pending_payments . '</span>';
                }
                if ($in_grace_payments > 0) {
                    $notes[] = '<span class="text-xs text-amber-600">In grace: ' . $in_grace_payments . '</span>';
                }
                $notes_html = implode(' ', $notes);
              ?>
              <tr class="hover:bg-gray-50">
                <td class="py-3 px-4 align-top">
                  <div class="font-medium"><?php echo $business_name; ?></div>
                  <div class="text-xs text-gray-500"><?php echo $market_name; ?></div>
                </td>

                <td class="py-3 px-4 align-top"><?php echo $stall_number; ?></td>

                <td class="py-3 px-4 align-top">
                  <div class="text-sm text-gray-800"><?php echo $start; ?></div>
                  <div class="text-sm text-gray-800">to <?php echo $end; ?></div>
                </td>

                <td class="py-3 px-4 align-top"><?php echo $rent; ?></td>

                <td class="py-3 px-4 align-top">
                  <span class="font-semibold <?php echo ($balance_amount > 0) ? 'text-red-600' : 'text-green-600'; ?>">
                    <?php echo formatCurrency($balance_amount); ?>
                  </span>
                </td>

                <td class="py-3 px-4 align-top"><?php echo $notes_html ?: '-'; ?></td>

                <td class="py-3 px-4 align-top">
                  <div class="flex flex-wrap gap-2">
                    <a class="px-3 py-1 bg-blue-600 text-white rounded text-sm" href="lease_details.php?id=<?php echo $lease_id; ?>">View</a>

                    <?php if ($tab === 'active' && in_array($status_lc, $activeStatuses, true)): ?>
                      <?php if ($pending_payments > 0 || $balance_amount > 0): ?>
                        <button class="px-3 py-1 bg-gray-300 text-gray-700 rounded text-sm cursor-not-allowed" title="Settle open invoices and balance before requesting termination">Request Terminate</button>
                      <?php else: ?>
                        <a class="px-3 py-1 bg-red-600 text-white rounded text-sm" href="request_termination.php?id=<?php echo $lease_id; ?>" onclick="return confirm('Are you sure you want to request termination of this lease?');">Request Terminate</a>
                      <?php endif; ?>
                    <?php endif; ?>

                    <?php if (!empty($l['agreement_path'])): ?>
                      <a class="px-3 py-1 bg-gray-800 text-white rounded text-sm" href="<?php echo htmlspecialchars($l['agreement_path']); ?>" target="_blank" rel="noopener">Download</a>
                    <?php endif; ?>
                  </div>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>
  <?php else: ?>
    <div class="bg-white rounded shadow p-8 text-center text-gray-500">
      You have no leases in this tab.
    </div>
  <?php endif; ?>
</section>

<?php include 'includes/footer.php'; ?>