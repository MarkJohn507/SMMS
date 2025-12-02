<?php
/**
 * receipt.php
 * Dedicated receipt page shown after successful PayPal capture.
 * Robust display with optional amount_paid and latest capture info.
 * Also adds print styles to hide action buttons (Back/Print) when printing.
 * Restricts viewing: Vendors can only view receipts for PAID payments.
 */

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/helpers.php';
require_once 'includes/audit.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
if (!isLoggedIn()) { redirect('login.php'); }

$user_id = (int)($_SESSION['user_id'] ?? 0);

function db_col_exists($db, string $table, string $col): bool {
    try {
        return (bool)$db->fetch("SELECT 1 FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? AND column_name=? LIMIT 1", [$table, $col]);
    } catch (Throwable $e) { return false; }
}
function table_exists($db, string $table): bool {
    try {
        return (bool)$db->fetch("SELECT 1 FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=? LIMIT 1", [$table]);
    } catch (Throwable $e) { return false; }
}
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

$isVendor = function_exists('userIsInRole') && userIsInRole($db, $user_id, 'vendor');
$backUrl  = $isVendor ? 'my_payments.php' : 'manage_payments.php?tab=payments';

$pid = isset($_GET['pid']) ? (int)$_GET['pid'] : 0;
if ($pid <= 0) { http_response_code(400); echo "Invalid receipt."; exit; }

$hasAmountPaid = db_col_exists($db, 'payments', 'amount_paid');

// Load payment row
try {
    if ($hasAmountPaid) {
        $row = $db->fetch("
            SELECT
                p.payment_id, p.amount, p.amount_paid, p.status, p.payment_date, p.receipt_number, p.payment_method,
                p.paypal_capture_id, p.paypal_order_id,
                l.business_name, l.vendor_id,
                s.stall_number,
                m.market_name
            FROM payments p
            JOIN leases l ON p.lease_id = l.lease_id
            JOIN stalls s ON l.stall_id = s.stall_id
            JOIN markets m ON s.market_id = m.market_id
            WHERE p.payment_id = ?
            LIMIT 1
        ", [$pid]);
    } else {
        $row = $db->fetch("
            SELECT
                p.payment_id, p.amount, p.status, p.payment_date, p.receipt_number, p.payment_method,
                p.paypal_capture_id, p.paypal_order_id,
                l.business_name, l.vendor_id,
                s.stall_number,
                m.market_name
            FROM payments p
            JOIN leases l ON p.lease_id = l.lease_id
            JOIN stalls s ON l.stall_id = s.stall_id
            JOIN markets m ON s.market_id = m.market_id
            WHERE p.payment_id = ?
            LIMIT 1
        ", [$pid]);
    }
} catch (Throwable $e) {
    error_log("receipt: fetch failed: ".$e->getMessage());
    $row = null;
}

if (!$row) { http_response_code(404); echo "Receipt not found."; exit; }

// Scope check: vendor must own the lease/payment
if ($isVendor && (int)$row['vendor_id'] !== $user_id) { http_response_code(403); echo "Forbidden"; exit; }

// Restrict viewing for vendors: only when payment is PAID
$status_lc = strtolower((string)$row['status']);
if ($isVendor && $status_lc !== 'paid') {
    http_response_code(403);
    echo "Receipt is available only for paid payments.";
    exit;
}

$total_due    = (float)($row['amount'] ?? 0);
$paid_to_date = $hasAmountPaid ? (float)($row['amount_paid'] ?? 0) : (strtolower((string)$row['status']) === 'paid' ? $total_due : 0.0);
$remaining    = max(0.0, round($total_due - $paid_to_date, 2));

// Determine "this payment" (capture) amount
$this_capture_amount = null;
$this_capture_id     = null;
$this_order_id       = null;
$flash = $_SESSION['receipt_flash'] ?? null;
if ($flash && (int)($flash['payment_id'] ?? 0) === $pid) {
    $this_capture_amount = isset($flash['capture_amount']) ? (float)$flash['capture_amount'] : null;
    $this_capture_id     = $flash['capture_id'] ?? null;
    $this_order_id       = $flash['order_id'] ?? null;
    unset($_SESSION['receipt_flash']);
}
if ($this_capture_id === null && !empty($row['paypal_capture_id'])) $this_capture_id = $row['paypal_capture_id'];
if ($this_order_id   === null && !empty($row['paypal_order_id']))   $this_order_id   = $row['paypal_order_id'];

if ($this_capture_amount === null && table_exists($db, 'payment_captures')) {
    try {
        $cap = $db->fetch("SELECT capture_amount, paypal_capture_id FROM payment_captures WHERE payment_id=? ORDER BY captured_at DESC, created_at DESC LIMIT 1", [$pid]);
        if ($cap) {
            $this_capture_amount = (float)($cap['capture_amount'] ?? 0);
            if (empty($this_capture_id) && !empty($cap['paypal_capture_id'])) $this_capture_id = $cap['paypal_capture_id'];
        }
    } catch (Throwable $e) { error_log("receipt: load latest capture failed: ".$e->getMessage()); }
}
if ($this_capture_amount === null && !$hasAmountPaid && strtolower((string)$row['status']) === 'paid') {
    // Heuristic fallback if no amount_paid column: assume full payment
    $this_capture_amount = $total_due;
}

$page_title = 'Payment Receipt';
require_once 'includes/header.php';
if ($isVendor) require_once 'includes/vendor_sidebar.php';
else require_once 'includes/admin_sidebar.php';
?>
<!-- Hide action buttons when printing -->
<style>
@media print {
  .no-print, .print\:hidden { display: none !important; }
  a[href]:after { content: "" !important; }
  body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
</style>

<section class="max-w-3xl mx-auto p-6">
  <div class="bg-white rounded-lg shadow p-6">
    <div class="flex items-start justify-between mb-4">
      <div>
        <h1 class="text-xl font-semibold text-gray-900 flex items-center gap-2">
          <span class="inline-flex h-6 w-6 items-center justify-center rounded-full bg-green-100 text-green-700">✓</span>
          Payment Receipt
        </h1>
        <p class="text-xs text-gray-500 mt-1">Thank you. Your payment has been recorded.</p>
      </div>
      <div class="flex gap-2 no-print">
        <a href="<?php echo htmlspecialchars($backUrl); ?>" class="text-sm px-3 py-1 bg-gray-100 rounded">Back</a>
        <button onclick="window.print()" class="text-sm px-3 py-1 bg-blue-600 text-white rounded">Print</button>
      </div>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
      <div>
        <p class="text-xs text-gray-500">Receipt #</p>
        <p class="font-semibold text-gray-800"><?php echo htmlspecialchars($row['receipt_number'] ?: '—'); ?></p>
      </div>
      <div>
        <p class="text-xs text-gray-500">Payment Date</p>
        <p class="font-semibold text-gray-800"><?php echo formatDate($row['payment_date'], true); ?></p>
      </div>
      <div>
        <p class="text-xs text-gray-500">Status</p>
        <p class="font-semibold text-gray-800"><?php echo htmlspecialchars(ucfirst((string)$row['status'])); ?></p>
      </div>
      <div>
        <p class="text-xs text-gray-500">Method</p>
        <p class="font-semibold text-gray-800"><?php echo htmlspecialchars(ucfirst(str_replace('_', ' ', (string)($row['payment_method'] ?? 'paypal')))); ?></p>
      </div>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
      <div>
        <p class="text-xs text-gray-500">Business</p>
        <p class="font-semibold text-gray-800"><?php echo htmlspecialchars($row['business_name']); ?></p>
      </div>
      <div>
        <p class="text-xs text-gray-500">Market / Stall</p>
        <p class="font-semibold text-gray-800"><?php echo htmlspecialchars($row['market_name']); ?> • Stall <?php echo htmlspecialchars($row['stall_number']); ?></p>
      </div>
    </div>

    <div class="mt-4 rounded border bg-gray-50 p-4">
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div>
          <p class="text-xs text-gray-500">Invoice Total</p>
          <p class="font-semibold text-gray-800"><?php echo formatCurrency($total_due); ?></p>
        </div>
        <div>
          <p class="text-xs text-gray-500">This Payment</p>
          <p class="font-semibold text-gray-800">
            <?php echo $this_capture_amount !== null ? formatCurrency($this_capture_amount) : '—'; ?>
          </p>
        </div>
        <div>
          <p class="text-xs text-gray-500">Paid to Date</p>
          <p class="font-semibold text-gray-800">
            <?php echo $hasAmountPaid ? formatCurrency($paid_to_date) : (strtolower((string)$row['status']) === 'paid' ? formatCurrency($total_due) : '—'); ?>
          </p>
        </div>
      </div>
      <?php if ($hasAmountPaid): ?>
        <div class="mt-3 flex items-center justify-between">
          <p class="text-sm text-gray-700">Remaining Balance</p>
          <p class="text-sm font-semibold <?php echo ($remaining > 0 ? 'text-amber-700' : 'text-green-700'); ?>">
            <?php echo formatCurrency($remaining); ?>
          </p>
        </div>
      <?php endif; ?>
    </div>

    <div class="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
      <div class="text-xs text-gray-500">
        <p class="mb-1 font-semibold text-gray-700">References</p>
        <div class="space-y-1">
          <div>Payment ID: <span class="text-gray-800"><?php echo (int)$row['payment_id']; ?></span></div>
          <?php if (!empty($this_order_id)): ?>
            <div>PayPal Order: <span class="text-gray-800"><?php echo htmlspecialchars($this_order_id); ?></span></div>
          <?php elseif (!empty($row['paypal_order_id'])): ?>
            <div>PayPal Order: <span class="text-gray-800"><?php echo htmlspecialchars($row['paypal_order_id']); ?></span></div>
          <?php endif; ?>
          <?php if (!empty($this_capture_id) || !empty($row['paypal_capture_id'])): ?>
            <div>PayPal Capture: <span class="text-gray-800"><?php echo htmlspecialchars($this_capture_id ?: $row['paypal_capture_id']); ?></span></div>
          <?php endif; ?>
        </div>
      </div>
      <div class="text-xs text-gray-500">
        <p class="mb-1 font-semibold text-gray-700">Notes</p>
        <p>Keep this receipt for your records. If you believe there is an error, contact the market office with the Payment ID and PayPal reference.</p>
      </div>
    </div>

    <div class="mt-6 flex items-center gap-2 no-print">
      <button onclick="window.print()" class="px-3 py-2 bg-blue-600 text-white rounded">Print</button>
      <a href="<?php echo htmlspecialchars($backUrl); ?>" class="px-3 py-2 bg-gray-200 rounded text-gray-800">Back to Payments</a>
      <a href="my_leases.php" class="px-3 py-2 bg-gray-200 rounded text-gray-800">View Leases</a>
    </div>
  </div>
</section>

<?php include 'includes/footer.php'; ?>