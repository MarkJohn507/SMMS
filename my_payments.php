<?php
require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/notifications.php';
require_once 'includes/csrf.php';
require_once 'includes/helpers.php';
require_once 'includes/billing.php'; // billing helpers

if (!isLoggedIn()) redirect('login.php?timeout=1');
$user_id = (int)($_SESSION['user_id'] ?? 0);
requireVendor();

$page_title = 'My Payments';

// Enforce billing for THIS vendor (cron-free safety)
try {
    ensureMonthlyInvoices($db, $user_id);
    autoTerminateLeasesPastGrace($db, $user_id);
} catch (Throwable $e) {
    error_log("my_payments enforce billing failed for user {$user_id}: ".$e->getMessage());
}

// Helper to check if a column exists (for amount_paid optional support)
function db_col_exists($db, string $table, string $col): bool {
    try {
        return (bool)$db->fetch("SELECT 1 FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? AND column_name=? LIMIT 1", [$table, $col]);
    } catch (Throwable $e) { return false; }
}

// Pagination helper
function paginate($total, $perPage, $currentPage) {
    $totalPages = max(1, (int)ceil($total / $perPage));
    $currentPage = max(1, min($currentPage, $totalPages));
    $offset = ($currentPage - 1) * $perPage;
    return ['totalPages'=>$totalPages, 'currentPage'=>$currentPage, 'offset'=>$offset, 'limit'=>$perPage];
}

// Filters & pagination & sorting
$lease_filter  = isset($_GET['lease_id']) ? (int)$_GET['lease_id'] : 0;
$status_filter = isset($_GET['status']) ? sanitize($_GET['status']) : 'all';
$page          = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
$perPage       = 10;

// Sorting
$allowedSortCols = ['due_date','amount','status','payment_date','balance'];
$sort_by  = (isset($_GET['sort_by']) && in_array($_GET['sort_by'], $allowedSortCols, true)) ? $_GET['sort_by'] : 'due_date';
$sort_dir = (isset($_GET['sort_dir']) && strtolower($_GET['sort_dir']) === 'asc') ? 'ASC' : 'DESC';

// Count total matching payments (scope by lease ownership)
$countSql = "
    SELECT COUNT(*) AS cnt
    FROM payments p
    JOIN leases l ON p.lease_id = l.lease_id
    WHERE l.vendor_id = ?
";
$countParams = [$user_id];
$allowedStatus = ['paid','pending','overdue','partial'];
if ($lease_filter > 0) { $countSql .= " AND p.lease_id = ?"; $countParams[] = $lease_filter; }
if ($status_filter !== 'all' && in_array($status_filter, $allowedStatus, true)) { $countSql .= " AND p.status = ?"; $countParams[] = $status_filter; }
$totalRow = $db->fetch($countSql, $countParams);
$total = (int)($totalRow['cnt'] ?? 0);

// Pagination
$pager = paginate($total, $perPage, $page);

// Fetch payments (NOTE: amount_paid may not exist; handle gracefully)
$limit  = (int)$pager['limit'];
$offset = (int)$pager['offset'];

$hasAmountPaid = db_col_exists($db, 'payments', 'amount_paid');

// Build fetch SQL including computed balance
$fetchSql = "
    SELECT 
        p.payment_id, p.lease_id, p.amount, p.status, p.due_date, p.payment_date, p.receipt_number, p.payment_method,
        ".($hasAmountPaid ? "COALESCE(p.amount_paid, 0)" : "0")." AS amount_paid,
        (p.amount - ".($hasAmountPaid ? "COALESCE(p.amount_paid,0)" : "0").") AS balance_amount,
        l.business_name, l.status AS lease_status,
        s.stall_number, m.market_name
    FROM payments p
    JOIN leases l ON p.lease_id = l.lease_id
    JOIN stalls s ON l.stall_id = s.stall_id
    JOIN markets m ON s.market_id = m.market_id
    WHERE l.vendor_id = ?
";
$fetchParams = [$user_id];
if ($lease_filter > 0) { $fetchSql .= " AND p.lease_id = ?"; $fetchParams[] = $lease_filter; }
if ($status_filter !== 'all' && in_array($status_filter, $allowedStatus, true)) { $fetchSql .= " AND p.status = ?"; $fetchParams[] = $status_filter; }

$colMap = [
    'due_date'     => 'p.due_date',
    'amount'       => 'p.amount',
    'status'       => 'p.status',
    'payment_date' => 'p.payment_date',
    'balance'      => 'balance_amount'
];
$orderBy = $colMap[$sort_by] ?? 'p.due_date';
$fetchSql .= " ORDER BY {$orderBy} {$sort_dir} LIMIT {$limit} OFFSET {$offset}";

$payments = $db->fetchAll($fetchSql, $fetchParams) ?: [];

logAudit($db, $user_id, 'View Payments', 'payments', null, null, null);

require_once 'includes/header.php';
require_once 'includes/vendor_sidebar.php';
?>
<section class="max-w-7xl mx-auto p-6">

  <div class="bg-white p-6 rounded shadow mb-6">
    <form method="GET" action="" class="flex gap-3 items-end flex-wrap">
      <div>
        <label class="block text-sm">Lease</label>
        <select name="lease_id" class="px-3 py-2 border rounded">
          <option value="0">All leases</option>
          <?php
            $leases = $db->fetchAll("SELECT lease_id, business_name FROM leases WHERE vendor_id = ? ORDER BY lease_start_date DESC", [$user_id]) ?: [];
            foreach ($leases as $l):
          ?>
            <option value="<?php echo (int)$l['lease_id']; ?>" <?php echo $lease_filter == $l['lease_id'] ? 'selected' : ''; ?>>
              <?php echo htmlspecialchars($l['business_name']); ?>
            </option>
          <?php endforeach; ?>
        </select>
      </div>

      <div>
        <label class="block text-sm">Status</label>
        <select name="status" class="px-3 py-2 border rounded">
          <option value="all" <?php echo $status_filter === 'all' ? 'selected' : ''; ?>>All</option>
          <option value="paid" <?php echo $status_filter === 'paid' ? 'selected' : ''; ?>>Paid</option>
          <option value="pending" <?php echo $status_filter === 'pending' ? 'selected' : ''; ?>>Pending</option>
          <option value="partial" <?php echo $status_filter === 'partial' ? 'selected' : ''; ?>>Partial</option>
          <option value="overdue" <?php echo $status_filter === 'overdue' ? 'selected' : ''; ?>>Overdue</option>
        </select>
      </div>

      <div>
        <label class="block text-sm">Sort by</label>
        <select name="sort_by" class="px-3 py-2 border rounded">
          <option value="due_date" <?php echo $sort_by === 'due_date' ? 'selected' : ''; ?>>Due Date</option>
          <option value="amount" <?php echo $sort_by === 'amount' ? 'selected' : ''; ?>>Amount</option>
          <option value="status" <?php echo $sort_by === 'status' ? 'selected' : ''; ?>>Status</option>
          <option value="payment_date" <?php echo $sort_by === 'payment_date' ? 'selected' : ''; ?>>Payment Date</option>
          <option value="balance" <?php echo $sort_by === 'balance' ? 'selected' : ''; ?>>Balance</option>
        </select>
      </div>

      <div>
        <label class="block text-sm">Direction</label>
        <select name="sort_dir" class="px-3 py-2 border rounded">
          <option value="desc" <?php echo strtolower($sort_dir) === 'desc' ? 'selected' : ''; ?>>Desc</option>
          <option value="asc" <?php echo strtolower($sort_dir) === 'asc' ? 'selected' : ''; ?>>Asc</option>
        </select>
      </div>

      <div>
        <button class="bg-green-600 text-white px-4 py-2 rounded">Filter</button>
      </div>
    </form>
  </div>

  <div class="bg-white rounded shadow overflow-hidden">
    <?php if (!empty($payments)): ?>
      <div class="overflow-x-auto">
        <table class="w-full">
          <thead class="bg-gray-50">
            <tr>
              <th class="py-3 px-4 text-left">Lease / Business</th>
              <th class="py-3 px-4 text-left">Stall</th>
              <th class="py-3 px-4 text-left">Due Date</th>
              <th class="py-3 px-4 text-left">Amount</th>
              <th class="py-3 px-4 text-left">Balance</th>
              <th class="py-3 px-4 text-left">Status</th>
              <th class="py-3 px-4 text-left">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-200">
            <?php foreach ($payments as $p): ?>
              <?php
                $paymentId   = (int)($p['payment_id'] ?? 0);
                $amount      = (float)($p['amount'] ?? 0);
                $amount_paid = (float)($p['amount_paid'] ?? 0);
                $balance     = max(0.0, round($amount - $amount_paid, 2));
                $statusLc    = strtolower((string)$p['status']);
                $statusText  = htmlspecialchars(ucfirst($statusLc));
              ?>
              <tr class="hover:bg-gray-50">
                <td class="py-3 px-4">
                  <div class="font-medium"><?php echo htmlspecialchars($p['business_name'] ?? ''); ?></div>
                  <div class="text-xs text-gray-500"><?php echo htmlspecialchars($p['market_name'] ?? ''); ?></div>
                </td>
                <td class="py-3 px-4"><?php echo htmlspecialchars($p['stall_number'] ?? ''); ?></td>
                <td class="py-3 px-4"><?php echo formatDate($p['due_date'] ?? null); ?></td>
                <td class="py-3 px-4">
                  <?php echo formatCurrency($amount); ?>
                  <?php if ($hasAmountPaid && $amount_paid > 0): ?>
                    <span class="text-xs text-gray-500">(Paid: <?php echo formatCurrency($amount_paid); ?>)</span>
                  <?php endif; ?>
                </td>
                <td class="py-3 px-4">
                  <span class="font-semibold <?php echo ($balance > 0 && $statusLc !== 'paid') ? 'text-red-600' : 'text-green-600'; ?>">
                    <?php echo formatCurrency($balance); ?>
                  </span>
                </td>
                <td class="py-3 px-4"><?php echo $statusText; ?></td>
                <td class="py-3 px-4">
                  <?php if ($statusLc === 'paid'): ?>
                    <a href="receipt.php?pid=<?php echo $paymentId; ?>"
                       class="inline-flex items-center gap-1 text-blue-600 hover:text-blue-800"
                       title="View receipt">
                      <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                              d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                              d="M2.458 12C3.732 7.943 7.523 5 12 5c4.477 0 8.268 2.943 9.542 7-1.274 4.057-5.065 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                      </svg>
                      <span class="text-sm">View</span>
                    </a>
                  <?php else: ?>
                    <span class="inline-flex items-center gap-1 text-gray-400 cursor-not-allowed" title="Receipt available after payment">
                      <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                              d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                              d="M2.458 12C3.732 7.943 7.523 5 12 5c4.477 0 8.268 2.943 9.542 7-1.274 4.057-5.065 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                      </svg>
                      <span class="text-sm">View</span>
                    </span>
                  <?php endif; ?>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>

      <div class="p-4 flex items-center justify-between">
        <div class="text-sm text-gray-600">Page <?php echo $pager['currentPage']; ?> of <?php echo $pager['totalPages']; ?> — <?php echo $total; ?> payments</div>
        <div class="space-x-2">
          <?php
            $baseParams = [];
            if ($lease_filter) $baseParams['lease_id'] = $lease_filter;
            if ($status_filter !== 'all') $baseParams['status'] = $status_filter;
            if ($sort_by) $baseParams['sort_by'] = $sort_by;
            if ($sort_dir) $baseParams['sort_dir'] = strtolower($sort_dir);
            $base = 'my_payments.php?' . http_build_query($baseParams);
          ?>
          <?php if ($pager['currentPage'] > 1): ?>
            <a class="px-3 py-1 bg-gray-200 rounded" href="<?php echo $base . '&page=1'; ?>">First</a>
            <a class="px-3 py-1 bg-gray-200 rounded" href="<?php echo $base . '&page=' . ($pager['currentPage'] - 1); ?>">Prev</a>
          <?php endif; ?>
          <?php for ($pg = 1; $pg <= $pager['totalPages']; $pg++): ?>
            <a class="px-3 py-1 <?php echo ($pg == $pager['currentPage']) ? 'bg-green-600 text-white rounded' : 'bg-gray-100 rounded'; ?>" href="<?php echo $base . '&page=' . $pg; ?>"><?php echo $pg; ?></a>
          <?php endfor; ?>
          <?php if ($pager['currentPage'] < $pager['totalPages']): ?>
            <a class="px-3 py-1 bg-gray-200 rounded" href="<?php echo $base . '&page=' . ($pager['currentPage'] + 1); ?>">Next</a>
            <a class="px-3 py-1 bg-gray-200 rounded" href="<?php echo $base . '&page=' . $pager['totalPages']; ?>">Last</a>
          <?php endif; ?>
        </div>
      </div>
    <?php else: ?>
      <div class="p-8 text-center text-gray-500">No payments found.</div>
    <?php endif; ?>
  </div>
</section>

<?php include 'includes/footer.php'; ?>