<?php
/**
 * submit_payment.php
 *
 * Month-to-month billing with grace-based termination (no penalties):
 * - Shows only unpaid (pending/partial) payments for ACTIVE leases and only up to end of grace window.
 * - Within grace window: vendor can pay full or partial amount.
 * - After grace: lease is auto-terminated by billing cron; payments no longer shown here.
 * - Uses PayPal create_order/capture flow. After PayPal approval, the server captures and redirects to a dedicated receipt page.
 */

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/helpers.php';
require_once 'includes/audit.php';
require_once 'includes/csrf.php';
require_once 'includes/billing.php';

requireVendor(); // ensure vendor

$page_title = 'Submit Payment';
$vendor_id  = (int)($_SESSION['user_id'] ?? 0);

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

/* Generate invoices for this vendor for current month (idempotent) */
ensureMonthlyInvoices($db, $vendor_id);

$graceDays = billing_grace_days();

/* Fetch unpaid rows only for ACTIVE/ONGOING/CURRENT leases and only if not past grace */
try {
    $unpaid = $db->fetchAll("
        SELECT 
            p.payment_id, p.lease_id, p.amount, p.amount_paid, p.status, p.due_date,
            l.business_name, LOWER(TRIM(l.status)) AS lease_status
        FROM payments p
        JOIN leases l ON l.lease_id = p.lease_id
        WHERE l.vendor_id = ?
          AND LOWER(TRIM(l.status)) IN ('active','ongoing','current')
          AND LOWER(TRIM(p.status)) IN ('pending','partial')
          AND CURDATE() <= DATE_ADD(DATE(p.due_date), INTERVAL ? DAY)
        ORDER BY p.due_date ASC, p.payment_id ASC
    ", [$vendor_id, $graceDays]) ?: [];
} catch (Throwable $e) {
    error_log("submit_payment: unpaid fetch failed: ".$e->getMessage());
    $unpaid = [];
}

/* Recent paid (any lease status) */
try {
    $recent = $db->fetchAll("
        SELECT p.payment_id, p.amount, p.payment_date, l.business_name
        FROM payments p
        JOIN leases l ON l.lease_id = p.lease_id
        WHERE l.vendor_id = ?
          AND LOWER(TRIM(p.status)) = 'paid'
        ORDER BY p.payment_date DESC, p.payment_id DESC
        LIMIT 5
    ", [$vendor_id]) ?: [];
} catch (Throwable $e) {
    error_log("submit_payment: recent fetch failed: ".$e->getMessage());
    $recent = [];
}

/* PayPal availability flag */
$paypal_ready = (defined('PAYPAL_CLIENT_ID') && PAYPAL_CLIENT_ID !== '' && defined('PAYPAL_CLIENT_SECRET') && PAYPAL_CLIENT_SECRET !== '');

include 'includes/header.php';
include 'includes/vendor_sidebar.php';
?>
<section class="max-w-7xl mx-auto p-6">
  <div class="bg-green-50 border-l-4 border-green-400 text-green-800 px-4 py-3 rounded mb-6 text-sm">
    Monthly invoices are due on the <?php echo (int)(defined('INVOICE_DUE_DAY') ? INVOICE_DUE_DAY : 1); ?> of each month.
    A <?php echo (int)$graceDays; ?>-day grace period applies. Leases are automatically terminated after the grace period if unpaid.
  </div>

  <?php if (!$paypal_ready): ?>
    <div class="bg-yellow-50 border-l-4 border-yellow-400 text-yellow-800 px-4 py-3 rounded mb-6 text-sm">
      PayPal is not configured. Contact the administrator.
    </div>
  <?php endif; ?>

  <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- Unpaid within grace window -->
    <div class="lg:col-span-2 bg-white rounded shadow p-5">
      <h2 class="text-lg font-semibold mb-4">Unpaid (Within Grace)</h2>
      <?php if (empty($unpaid)): ?>
        <p class="text-sm text-gray-600">No payable invoices at this time.</p>
      <?php else: ?>
        <table class="w-full text-sm">
          <thead class="bg-gray-50">
            <tr>
              <th class="py-2 px-2 text-left">Business</th>
              <th class="py-2 px-2 text-left">Due Date</th>
              <th class="py-2 px-2 text-left">Total</th>
              <th class="py-2 px-2 text-left">Paid</th>
              <th class="py-2 px-2 text-left">Status</th>
              <th class="py-2 px-2 text-left">Partial (₱)</th>
              <th class="py-2 px-2 text-left">Action</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($unpaid as $row):
                $amount = (float)$row['amount'];
                $paid   = (float)$row['amount_paid'];
                $remaining = max(0, round($amount - $paid, 2));
                $s = strtolower(trim((string)$row['status']));
                $dueYmd = $row['due_date'] ? date('Y-m-d', strtotime($row['due_date'])) : null;

                $today = date('Y-m-d');
                $dueTs = $dueYmd ? strtotime($dueYmd) : false;
                $todayTs = strtotime($today);
                $label = '';
                $labelClass = '';

                if ($dueTs !== false) {
                    $daysUntilDue = (int)floor(($dueTs - $todayTs) / 86400);
                    $graceEndTs = strtotime("+{$graceDays} days", $dueTs);
                    $daysToGraceEnd = (int)floor(($graceEndTs - $todayTs) / 86400);

                    if ($daysUntilDue > 3) {
                        $label = '';
                    } elseif ($daysUntilDue >= 1) {
                        $label = 'Due Soon';
                        $labelClass = 'bg-amber-600';
                    } elseif ($daysUntilDue === 0) {
                        $label = 'Due Today';
                        $labelClass = 'bg-blue-600';
                    } else {
                        if ($daysToGraceEnd >= 0) {
                            $label = 'In Grace (' . $daysToGraceEnd . ' day' . ($daysToGraceEnd === 1 ? '' : 's') . ' left)';
                            $labelClass = 'bg-amber-600';
                        } else {
                            continue; // should not appear here
                        }
                    }
                }
            ?>
            <tr class="border-t">
              <td class="py-2 px-2"><?php echo htmlspecialchars($row['business_name']); ?></td>
              <td class="py-2 px-2"><?php echo formatDate($row['due_date']); ?></td>
              <td class="py-2 px-2"><?php echo formatCurrency($amount); ?></td>
              <td class="py-2 px-2"><?php echo formatCurrency($paid); ?></td>
              <td class="py-2 px-2">
                <span class="text-blue-700"><?php echo ucfirst($s); ?></span>
                <?php if ($label): ?>
                  <span class="ml-1 inline-block px-2 py-0.5 <?php echo $labelClass; ?> text-white text-xs rounded">
                    <?php echo htmlspecialchars($label); ?>
                  </span>
                <?php endif; ?>
              </td>
              <td class="py-2 px-2">
                <input
                  type="number"
                  step="0.01"
                  min="0.01"
                  max="<?php echo $remaining; ?>"
                  class="w-24 px-2 py-1 border rounded text-sm"
                  id="partial_amount_<?php echo (int)$row['payment_id']; ?>"
                  placeholder="≤ <?php echo $remaining; ?>">
              </td>
              <td class="py-2 px-2">
                <button
                  type="button"
                  data-payment-id="<?php echo (int)$row['payment_id']; ?>"
                  data-remaining="<?php echo htmlspecialchars((string)$remaining, ENT_QUOTES); ?>"
                  onclick="startPayPalPayment(this)"
                  class="bg-yellow-600 hover:bg-yellow-700 text-white px-3 py-1 rounded text-xs"
                  <?php echo ($paypal_ready && $remaining > 0) ? '' : 'disabled'; ?>>
                  Pay
                </button>
              </td>
            </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
        <div id="createOrderStatus" class="mt-4 text-xs text-gray-600"></div>
      <?php endif; ?>
    </div>

    <!-- Recent Paid -->
    <div class="bg-white rounded shadow p-5">
      <h2 class="text-lg font-semibold mb-4">Recent Paid</h2>
      <?php if (empty($recent)): ?>
        <p class="text-sm text-gray-600">No paid payments yet.</p>
      <?php else: ?>
        <ul class="space-y-3 text-sm">
          <?php foreach ($recent as $r): ?>
            <li class="border-b pb-2">
              <div class="font-medium"><?php echo htmlspecialchars($r['business_name']); ?></div>
              <div class="text-xs text-gray-500">Paid: <?php echo formatDate($r['payment_date']); ?></div>
              <div class="text-xs"><?php echo formatCurrency($r['amount']); ?></div>
            </li>
          <?php endforeach; ?>
        </ul>
      <?php endif; ?>
    </div>
  </div>
</section>

<script>
function buildBaseUrl() {
  const origin = window.location.origin;
  const scriptDir = <?php echo json_encode(rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/\\')); ?>;
  return origin + (scriptDir ? scriptDir : '');
}

/**
 * startPayPalPayment(btn)
 * Reads payment_id and optional partial input (#partial_amount_<id>).
 * Sends JSON payload to /paypal/create_order.php, then redirects to PayPal approval URL.
 * After approval, capture_order.php will finalize and redirect to receipt.php?pid=<payment_id>.
 */
function startPayPalPayment(btn){
  const paymentId = btn.getAttribute('data-payment-id');
  const remaining = parseFloat(btn.getAttribute('data-remaining') || '0') || 0;
  const partialInput = document.querySelector('#partial_amount_' + paymentId);
  const partialVal = partialInput && partialInput.value ? parseFloat(partialInput.value) : null;

  if (partialVal !== null) {
    if (isNaN(partialVal) || partialVal <= 0) { alert('Please enter a valid partial amount greater than 0.'); return; }
    if (partialVal > remaining + 0.00001) { alert('Partial amount exceeds remaining balance.'); return; }
  }

  const payload = { payment_id: Number(paymentId) };
  if (partialVal && partialVal > 0) payload.partial_amount = Math.round(partialVal * 100) / 100;

  const statusEl = document.getElementById('createOrderStatus');
  if (statusEl) statusEl.textContent = 'Creating PayPal order...';
  btn.disabled = true;

  const BASE = buildBaseUrl();
  fetch(BASE + '/paypal/create_order.php', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload),
    credentials: 'same-origin'
  })
  .then(async r => {
    const text = await r.text();
    try { return { ok: true, data: JSON.parse(text) }; }
    catch { return { ok: false, raw: text, status: r.status, statusText: r.statusText }; }
  })
  .then(res => {
    if (!res.ok) {
      alert('Server error while creating PayPal order. Check console for details.');
      console.error('create_order raw response:', res.raw, 'HTTP status:', res.status, res.statusText);
      btn.disabled = false;
      if (statusEl) statusEl.textContent = '';
      return;
    }
    const d = res.data;
    if (!d || d.error) {
      alert(d && d.error ? d.error : 'Failed to create PayPal order.');
      btn.disabled = false;
      if (statusEl) statusEl.textContent = '';
      return;
    }
    if (statusEl) statusEl.textContent = 'Redirecting to PayPal...';
    window.location.href = d.approveUrl;
  })
  .catch(e => {
    alert('Failed: ' + e);
    console.error(e);
    btn.disabled = false;
    if (statusEl) statusEl.textContent = '';
  });
}
</script>

<?php include 'includes/footer.php'; ?>