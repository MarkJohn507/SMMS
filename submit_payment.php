<?php
/**
 * submit_payment.php (FINAL FIX)
 *
 * Enables vendors to pay overdue invoices still within the grace period.
 *
 * Key Points:
 *  - Query now includes payment statuses: pending, partial, overdue.
 *  - Front-end displays overdue invoices with distinct styling.
 *  - Validation: still requires lease to be active and due_date + graceDays not exceeded.
 *  - Reminds implementers to update paypal/create_order.php to ACCEPT 'overdue'
 *    (change its status check to include 'overdue' in the payable statuses array).
 *
 * IMPORTANT: Your current paypal/create_order.php rejects overdue because:
 *     if (!in_array($status, ['pending','partial'], true)) { ... 'Payment not payable' }
 *  You MUST change that to: ['pending','partial','overdue'] or the payment will still fail.
 *
 * Also ensure capture_order.php does not prematurely reject overdue rows if still in grace.
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

/* Helpers (defensive if not globally defined) */
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

/* Ensure current month invoices exist (idempotent) */
try { ensureMonthlyInvoices($db, $vendor_id); } catch (Throwable $e) { error_log("submit_payment ensureMonthlyInvoices: ".$e->getMessage()); }

$graceDays = billing_grace_days();

/**
 * Fetch unpaid invoices within grace window:
 * - Lease status must be active/ongoing/current
 * - Payment status can be pending, partial, overdue
 * - Current date <= due_date + graceDays
 */
try {
    $unpaid = $db->fetchAll("
        SELECT 
            p.payment_id,
            p.lease_id,
            p.amount,
            p.amount_paid,
            p.status,
            p.due_date,
            l.business_name,
            LOWER(TRIM(l.status)) AS lease_status
        FROM payments p
        JOIN leases l ON l.lease_id = p.lease_id
        WHERE l.vendor_id = ?
          AND LOWER(TRIM(l.status)) IN ('active','ongoing','current')
          AND LOWER(TRIM(p.status)) IN ('pending','partial','overdue')
          AND CURDATE() <= DATE_ADD(DATE(p.due_date), INTERVAL ? DAY)
        ORDER BY p.due_date ASC, p.payment_id ASC
    ", [$vendor_id, $graceDays]) ?: [];
} catch (Throwable $e) {
    error_log("submit_payment unpaid fetch failed: ".$e->getMessage());
    $unpaid = [];
}

/* Recent paid list */
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
    error_log("submit_payment recent fetch failed: ".$e->getMessage());
    $recent = [];
}

/* PayPal availability check */
$paypal_ready = (
    defined('PAYPAL_CLIENT_ID') && PAYPAL_CLIENT_ID !== '' &&
    defined('PAYPAL_CLIENT_SECRET') && PAYPAL_CLIENT_SECRET !== ''
);

include 'includes/header.php';
include 'includes/vendor_sidebar.php';
?>
<section class="max-w-7xl mx-auto p-6">
  <div class="bg-green-50 border-l-4 border-green-400 text-green-800 px-4 py-3 rounded mb-6 text-sm">
    Monthly invoices are due on the <?php echo (int)(defined('INVOICE_DUE_DAY') ? INVOICE_DUE_DAY : 1); ?> of each month.
    A <?php echo (int)$graceDays; ?>-day grace period applies. You may still pay overdue invoices while in grace.
    After the grace period ends, the lease may be terminated and the invoice removed from this list.
  </div>

  <?php if (!$paypal_ready): ?>
    <div class="bg-yellow-50 border-l-4 border-yellow-400 text-yellow-800 px-4 py-3 rounded mb-6 text-sm">
      PayPal is not configured. Contact the administrator to enable online payments.
    </div>
  <?php endif; ?>

  <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- Payable invoices -->
    <div class="lg:col-span-2 bg-white rounded shadow p-5">
      <h2 class="text-lg font-semibold mb-4">Payable Invoices (Pending / Partial / Overdue In Grace)</h2>
      <?php if (empty($unpaid)): ?>
        <p class="text-sm text-gray-600">No invoices are payable at this time.</p>
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
              $paid   = (float)($row['amount_paid'] ?? 0);
              $remaining = max(0, round($amount - $paid, 2));

              $statusRaw = strtolower(trim((string)$row['status']));
              $dueYmd = $row['due_date'] ? date('Y-m-d', strtotime($row['due_date'])) : null;

              $today = date('Y-m-d');
              $dueTs = $dueYmd ? strtotime($dueYmd) : false;
              $todayTs = strtotime($today);
              $label = '';
              $labelClass = '';

              if ($dueTs !== false) {
                  $daysUntilDue  = (int)floor(($dueTs - $todayTs)/86400);
                  $graceEndTs    = strtotime("+{$graceDays} days", $dueTs);
                  $daysToGraceEnd= (int)floor(($graceEndTs - $todayTs)/86400);

                  if ($daysUntilDue > 3) {
                      $label = '';
                  } elseif ($daysUntilDue >= 1) {
                      $label = 'Due Soon';
                      $labelClass = 'bg-amber-600';
                  } elseif ($daysUntilDue === 0) {
                      $label = 'Due Today';
                      $labelClass = 'bg-blue-600';
                  } else {
                      // Overdue portion – still in grace?
                      if ($daysToGraceEnd >= 0) {
                          $label = 'In Grace (' . $daysToGraceEnd . ' day' . ($daysToGraceEnd === 1 ? '' : 's') . ' left)';
                          $labelClass = 'bg-amber-600';
                      } else {
                          // Out of grace; skip showing unpaid (would be terminated soon or already)
                          continue;
                      }
                  }
              }

              $statusColor = match ($statusRaw) {
                  'pending'  => 'text-blue-700',
                  'partial'  => 'text-purple-700',
                  'overdue'  => 'text-red-700 font-semibold',
                  default    => 'text-gray-700'
              };
          ?>
            <tr class="border-t">
              <td class="py-2 px-2"><?php echo htmlspecialchars($row['business_name']); ?></td>
              <td class="py-2 px-2"><?php echo formatDate($row['due_date']); ?></td>
              <td class="py-2 px-2"><?php echo formatCurrency($amount); ?></td>
              <td class="py-2 px-2"><?php echo formatCurrency($paid); ?></td>
              <td class="py-2 px-2">
                <span class="<?php echo $statusColor; ?>"><?php echo ucfirst($statusRaw); ?></span>
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
                  placeholder="≤ <?php echo $remaining; ?>"
                  <?php echo $remaining <= 0 ? 'disabled' : ''; ?>>
              </td>
              <td class="py-2 px-2">
                <button
                  type="button"
                  data-payment-id="<?php echo (int)$row['payment_id']; ?>"
                  data-remaining="<?php echo htmlspecialchars((string)$remaining, ENT_QUOTES); ?>"
                  onclick="startPayPalPayment(this)"
                  class="bg-yellow-600 hover:bg-yellow-700 text-white px-3 py-1 rounded text-xs disabled:opacity-40 disabled:cursor-not-allowed"
                  <?php echo ($paypal_ready && $remaining > 0) ? '' : 'disabled'; ?>>
                  Pay
                </button>
              </td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
        <div id="createOrderStatus" class="mt-4 text-xs text-gray-600"></div>
        <div class="mt-3 text-xs text-red-600">
          If you encounter "Payment not payable" errors for overdue invoices, ask support to update <code>paypal/create_order.php</code> to allow status 'overdue'.
        </div>
      <?php endif; ?>
    </div>

    <!-- Recent Paid -->
    <div class="bg-white rounded shadow p-5">
      <h2 class="text-lg font-semibold mb-4">Recent Paid</h2>
      <?php if (empty($recent)): ?>
        <p class="text-sm text-gray-600">No paid invoices yet.</p>
      <?php else: ?>
        <ul class="space-y-3 text-sm">
          <?php foreach ($recent as $r): ?>
            <li class="border-b pb-2">
              <div class="font-medium"><?php echo htmlspecialchars($r['business_name']); ?></div>
              <div class="text-xs text-gray-500">Paid: <?php echo formatDate($r['payment_date']); ?></div>
              <div class="text-xs"><?php echo formatCurrency((float)$r['amount']); ?></div>
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
 * Sends JSON payload to /paypal/create_order.php including optional partial_amount.
 * NOTE: Back-end must allow status 'overdue'. If not updated, response will show error.
 */
function startPayPalPayment(btn){
  const paymentId = btn.getAttribute('data-payment-id');
  const remaining = parseFloat(btn.getAttribute('data-remaining') || '0') || 0;
  if (remaining <= 0) { alert('Nothing to pay for this invoice.'); return; }

  const partialInput = document.getElementById('partial_amount_' + paymentId);
  const partialVal = partialInput && partialInput.value ? parseFloat(partialInput.value) : null;

  if (partialVal !== null) {
    if (isNaN(partialVal) || partialVal <= 0) { alert('Enter a valid partial amount > 0'); return; }
    if (partialVal > remaining + 0.00001) { alert('Partial amount exceeds remaining balance'); return; }
  }

  const payload = { payment_id: Number(paymentId) };
  if (partialVal && partialVal > 0 && partialVal < remaining) {
    payload.partial_amount = Math.round(partialVal * 100) / 100;
  }

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
    let parsed = null;
    try { parsed = JSON.parse(text); } catch(e){}
    return { ok: r.ok, status: r.status, data: parsed, raw: text };
  })
  .then(res => {
    if (!res.ok) {
      alert('Server error (HTTP ' + res.status + ').');
      console.error('create_order error raw:', res.raw);
      btn.disabled = false;
      if (statusEl) statusEl.textContent = '';
      return;
    }
    const d = res.data;
    if (!d || d.error) {
      alert(d && d.error ? d.error : 'Failed to create order.');
      if (d && d.error === 'Payment not payable') {
        console.warn('Back-end likely still disallows overdue payments. Update status validation.');
      }
      btn.disabled = false;
      if (statusEl) statusEl.textContent = '';
      return;
    }
    if (!d.approveUrl) {
      alert('No approve URL returned.');
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