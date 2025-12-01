<?php
require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/notifications.php';
require_once 'includes/csrf.php';
require_once 'includes/billing.php'; // grace window + monthly billing rules

if (!isLoggedIn()) redirect('login.php?timeout=1');
requireVendor();
$user_id = (int)($_SESSION['user_id'] ?? 0);

// helper to detect column presence
function payments_has_column($db, string $col): bool {
    try {
        return (bool)$db->fetch("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'payments' AND column_name = ? LIMIT 1", [$col]);
    } catch (Throwable $e) { return false; }
}

// Accept GET (show form) or POST (process)
$payment_id = isset($_REQUEST['payment_id']) ? (int)$_REQUEST['payment_id'] : 0;
if ($payment_id <= 0) {
    redirect('my_payments.php');
}

// Fetch payment and validate ownership; also fetch lease status for active check
$payment = $db->fetch("
    SELECT 
        p.*,
        l.vendor_id AS l_vendor_id,
        l.status    AS lease_status,
        l.business_name,
        s.stall_number
    FROM payments p
    JOIN leases l ON p.lease_id = l.lease_id
    JOIN stalls s ON l.stall_id = s.stall_id
    WHERE p.payment_id = ? LIMIT 1
", [$payment_id]);

if (!$payment) {
    http_response_code(404);
    echo "Payment not found.";
    exit;
}

// Ownership: accept either payments.vendor_id or leases.vendor_id
$pVendor = (int)($payment['vendor_id'] ?? 0);
$lVendor = (int)($payment['l_vendor_id'] ?? 0);
if ($user_id !== $pVendor && $user_id !== $lVendor) {
    http_response_code(403);
    echo "Forbidden";
    exit;
}

// Lease must be active/ongoing/current
$leaseStatus = strtolower(trim((string)$payment['lease_status']));
if (!in_array($leaseStatus, ['active','ongoing','current'], true)) {
    $_SESSION['error_message'] = 'Lease is not active. You cannot submit a payment for this lease.';
    redirect('my_payments.php');
}

// Enforce grace window: allow paying only until due_date + GRACE_DAYS (no penalties; after grace system auto-terminates)
$graceDays = billing_grace_days();
$dueDate = !empty($payment['due_date']) ? date('Y-m-d', strtotime($payment['due_date'])) : null;
if ($dueDate) {
    $graceEnd = date('Y-m-d', strtotime("+{$graceDays} days", strtotime($dueDate)));
    if (date('Y-m-d') > $graceEnd) {
        $_SESSION['error_message'] = 'Grace period has ended for this invoice. If unpaid, your lease may have been terminated.';
        redirect('my_payments.php');
    }
}

$page_title = 'Pay Payment';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF
    if (!csrf_validate_request()) {
        $_SESSION['error_message'] = 'Invalid CSRF token.';
        redirect('pay.php?payment_id=' . $payment_id);
    }

    // Validate amount against remaining balance
    $total      = (float)$payment['amount'];
    $alreadyPaid= (float)$payment['amount_paid'];
    $remaining  = max(0.0, round($total - $alreadyPaid, 2));
    $paid_amount= isset($_POST['amount']) ? (float)$_POST['amount'] : 0.0;
    if ($paid_amount <= 0) {
        $_SESSION['error_message'] = 'Amount must be greater than 0.';
        redirect('pay.php?payment_id=' . $payment_id);
    }
    if ($paid_amount - $remaining > 0.00001) {
        $_SESSION['error_message'] = 'Amount exceeds remaining balance.';
        redirect('pay.php?payment_id=' . $payment_id);
    }

    // Validate file upload (receipt)
    $allowed = ['image/jpeg','image/png','application/pdf'];
    $maxBytes = 5 * 1024 * 1024;
    if (empty($_FILES['receipt']) || $_FILES['receipt']['error'] !== UPLOAD_ERR_OK) {
        $_SESSION['error_message'] = 'Please upload a receipt file.';
        redirect('pay.php?payment_id=' . $payment_id);
    }

    $f = $_FILES['receipt'];
    if ($f['size'] > $maxBytes) {
        $_SESSION['error_message'] = 'Receipt too large (max 5MB).';
        redirect('pay.php?payment_id=' . $payment_id);
    }
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $f['tmp_name']);
    finfo_close($finfo);
    if (!in_array($mime, $allowed, true)) {
        $_SESSION['error_message'] = 'Receipt format not supported.';
        redirect('pay.php?payment_id=' . $payment_id);
    }

    // Store receipt
    $uploadDir = __DIR__ . '/uploads/payments';
    if (!is_dir($uploadDir)) mkdir($uploadDir, 0755, true);
    $ext = strtolower(pathinfo($f['name'], PATHINFO_EXTENSION));
    $safe = 'payment_' . $payment_id . '_' . time() . '.' . preg_replace('/[^a-z0-9.]/i', '', $ext);
    $dest = $uploadDir . '/' . $safe;
    if (!move_uploaded_file($f['tmp_name'], $dest)) {
        $_SESSION['error_message'] = 'Failed to store receipt.';
        redirect('pay.php?payment_id=' . $payment_id);
    }
    $receipt_path = 'uploads/payments/' . $safe;

    // Update payment: accumulate into amount_paid. Mark 'paid' when fully settled, else 'partial'
    $newPaid = round($alreadyPaid + $paid_amount, 2);
    $finalStatus = ($newPaid + 0.00001 >= $total) ? 'paid' : 'partial';

    // Use receipt_file if exists, else fallback to receipt_number to store path
    $useReceiptFileCol = payments_has_column($db, 'receipt_file');

    try {
        $db->beginTransaction();

        if ($useReceiptFileCol) {
            $db->query("
                UPDATE payments
                SET amount_paid = ?, status = ?, payment_date = NOW(), receipt_file = ?, updated_at = NOW(),
                    notes = CONCAT(COALESCE(notes,''), '\nManual receipt uploaded (', ?, ') amount ₱', ?, ' on ', NOW())
                WHERE payment_id = ? LIMIT 1
            ", [
                number_format($newPaid, 2, '.', ''),
                $finalStatus,
                $receipt_path,
                $safe,
                number_format($paid_amount, 2, '.', ''),
                $payment_id
            ]);
        } else {
            // Fallback: store file name in receipt_number
            $db->query("
                UPDATE payments
                SET amount_paid = ?, status = ?, payment_date = NOW(), receipt_number = ?, updated_at = NOW(),
                    notes = CONCAT(COALESCE(notes,''), '\nManual receipt uploaded (', ?, ') amount ₱', ?, ' on ', NOW())
                WHERE payment_id = ? LIMIT 1
            ", [
                number_format($newPaid, 2, '.', ''),
                $finalStatus,
                $safe,
                $safe,
                number_format($paid_amount, 2, '.', ''),
                $payment_id
            ]);
        }

        $db->commit();
    } catch (Throwable $e) {
        $db->rollBack();
        error_log("pay.php update failed: " . $e->getMessage());
        $_SESSION['error_message'] = 'Failed to save payment. Please try again.';
        redirect('pay.php?payment_id=' . $payment_id);
    }

    // Notify admin (same list as before)
    try {
        $admins = $db->fetchAll("SELECT u.user_id FROM user_roles ur JOIN roles r ON ur.role_id = r.role_id JOIN users u ON ur.user_id = u.user_id WHERE r.name IN ('super_admin','municipal_admin','issuer_admin','admin') AND ur.status = 'active' AND u.status = 'active'") ?: [];
        if (empty($admins)) $admins = $db->fetchAll("SELECT user_id FROM users WHERE role = 'admin' AND status = 'active'") ?: [];
        $msg = "Payment #{$payment_id} submitted by {$_SESSION['full_name']} for lease {$payment['lease_id']}. Amount: " . number_format($paid_amount,2) . ".";
        foreach ($admins as $a) {
            if (!empty($a['user_id'])) createNotification($db, (int)$a['user_id'], 'Payment Submitted', $msg, 'info', 'payment', $payment_id, 'payments');
        }
    } catch (Throwable $e) {
        error_log("pay.php admin notify failed: " . $e->getMessage());
    }

    logAudit($db, $user_id, 'Submit Payment (Manual)', 'payments', $payment_id, null, 'receipt uploaded');

    $_SESSION['success_message'] = ($finalStatus === 'paid')
        ? 'Payment submitted. Thank you!'
        : 'Partial payment submitted. Please settle the remaining balance within the grace period.';
    redirect('my_payments.php');
}

// GET -> show minimal payment upload form
require_once 'includes/header.php';
require_once 'includes/vendor_sidebar.php';
?>
<section class="max-w-xl mx-auto p-6">
  <h1 class="text-2xl font-bold mb-4">Pay: <?php echo htmlspecialchars($payment['business_name']); ?> — <?php echo htmlspecialchars($payment['stall_number']); ?></h1>

  <?php if (!empty($_SESSION['error_message'])): ?>
    <div class="bg-red-100 p-3 rounded mb-4"><?php echo htmlspecialchars($_SESSION['error_message']); unset($_SESSION['error_message']); ?></div>
  <?php endif; ?>
  <?php if (!empty($_SESSION['success_message'])): ?>
    <div class="bg-green-100 p-3 rounded mb-4"><?php echo htmlspecialchars($_SESSION['success_message']); unset($_SESSION['success_message']); ?></div>
  <?php endif; ?>

  <div class="bg-white rounded shadow p-6">
    <p class="mb-4">
      Due: <strong><?php echo formatDate($payment['due_date']); ?></strong>
      — Total: <strong><?php echo formatCurrency($payment['amount']); ?></strong>
      <?php
        $remaining = max(0.0, round(((float)$payment['amount']) - ((float)$payment['amount_paid']), 2));
        if ($remaining > 0) {
            echo ' — Remaining: <strong>' . formatCurrency($remaining) . '</strong>';
        }
      ?>
    </p>
    <p class="mb-4 text-xs text-gray-600">
      A <?php echo (int)$graceDays; ?>-day grace period applies after the due date. After the grace period, the lease may be automatically terminated if unpaid.
    </p>

    <form method="POST" enctype="multipart/form-data" action="pay.php">
      <?php echo csrf_field(); ?>
      <input type="hidden" name="payment_id" value="<?php echo (int)$payment_id; ?>">
      <div class="mb-4">
        <label class="block text-sm mb-1">Amount to pay</label>
        <input type="number" name="amount" step="0.01" value="<?php echo htmlspecialchars($remaining > 0 ? $remaining : 0); ?>" class="w-full px-3 py-2 border rounded" required>
        <p class="text-xs text-gray-500 mt-1">You can pay a partial amount. The status will update to "Partial" until fully paid.</p>
      </div>
      <div class="mb-4">
        <label class="block text-sm mb-1">Upload Receipt (PDF/JPG/PNG, max 5MB)</label>
        <input type="file" name="receipt" accept=".pdf,.jpg,.jpeg,.png" required>
      </div>
      <div class="flex gap-3">
        <button class="bg-green-600 text-white px-4 py-2 rounded">Submit Payment</button>
        <a href="my_payments.php" class="px-4 py-2 bg-gray-300 rounded">Cancel</a>
      </div>
    </form>
  </div>
</section>
<?php include 'includes/footer.php'; ?>