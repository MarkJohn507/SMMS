<?php
require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/notifications.php';

requireAdmin();

$page_title = 'Payments Review';
$error = '';
$success = '';

// Approve or reject payment verification (admin action)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && isset($_POST['payment_id'])) {
    $action = $_POST['action'];
    $payment_id = (int)$_POST['payment_id'];
    $admin_notes = sanitize($_POST['admin_notes'] ?? '');

    $p = $db->fetch("SELECT * FROM payments WHERE payment_id = ? LIMIT 1", [$payment_id]);
    if (!$p) {
        $error = 'Payment not found.';
    } else {
        if ($action === 'verify') {
            // mark as paid (verified)
            $ok = $db->query("UPDATE payments SET status = 'paid', payment_date = COALESCE(payment_date, CURDATE()), receipt_number = COALESCE(receipt_number, receipt_number) WHERE payment_id = ?", [$payment_id]);
            if ($ok) {
                logAudit($db, $_SESSION['user_id'], 'Payment Verified', 'payments', $payment_id, null, $admin_notes);
                createNotification($db, $p['vendor_id'], 'Payment Verified', "Payment #{$payment_id} has been verified by admin.", 'success', 'payment', $payment_id, 'payments');
                $success = 'Payment verified.';
            } else $error = 'Failed to verify payment.';
        } elseif ($action === 'reject') {
            // mark as pending or rejected; we keep 'pending' so vendor can resubmit, and save admin notes
            $ok = $db->query("UPDATE payments SET status = 'pending', notes = CONCAT(COALESCE(notes,''), ?) WHERE payment_id = ?", ["\n[Admin Rejection] {$_SESSION['user_id']}: {$admin_notes}", $payment_id]);
            if ($ok) {
                logAudit($db, $_SESSION['user_id'], 'Payment Rejected', 'payments', $payment_id, null, $admin_notes);
                createNotification($db, $p['vendor_id'], 'Payment Rejected', "Your payment #{$payment_id} was rejected by admin. Reason: {$admin_notes}", 'warning', 'payment', $payment_id, 'payments');
                $success = 'Payment rejected and vendor notified.';
            } else $error = 'Failed to reject payment.';
        }
    }
}

// List payments with uploaded receipts pending admin review
$filter = isset($_GET['filter']) ? sanitize($_GET['filter']) : 'pending';
$page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
$perPage = 20;
$offset = ($page - 1) * $perPage;

$where = "WHERE (p.status IN ('pending','overdue','partial'))";
$params = [];

$sqlCount = "SELECT COUNT(*) as cnt FROM payments p $where";
$totalRow = $db->fetch($sqlCount, $params);
$total = (int)($totalRow['cnt'] ?? 0);

$sql = "SELECT p.*, l.business_name, l.lease_id, s.stall_number, u.full_name as vendor_name, u.contact_number
        FROM payments p
        LEFT JOIN leases l ON p.lease_id = l.lease_id
        LEFT JOIN stalls s ON p.lease_id IS NOT NULL AND l.stall_id = s.stall_id
        JOIN users u ON p.vendor_id = u.user_id
        $where
        ORDER BY p.due_date DESC
        LIMIT {$perPage} OFFSET {$offset}";

$payments = $db->fetchAll($sql, $params);

// Render
require_once 'includes/header.php';
require_once 'includes/admin_sidebar.php';
?>
<div class="mb-6">
  <h3 class="text-2xl font-bold">Payments Review</h3>
  <p class="text-gray-600">Verify uploaded payment receipts submitted by vendors</p>
</div>

<?php if ($error): ?><div class="bg-red-100 p-3 rounded mb-4"><?php echo htmlspecialchars($error); ?></div><?php endif; ?>
<?php if ($success): ?><div class="bg-green-100 p-3 rounded mb-4"><?php echo htmlspecialchars($success); ?></div><?php endif; ?>

<div class="bg-white rounded shadow p-4 mb-6">
  <?php if (!empty($payments)): ?>
    <div class="overflow-x-auto">
      <table class="w-full">
        <thead class="bg-gray-50">
          <tr>
            <th class="py-2 px-3 text-left">Payment ID</th>
            <th class="py-2 px-3 text-left">Vendor</th>
            <th class="py-2 px-3 text-left">Lease / Stall</th>
            <th class="py-2 px-3 text-left">Due Date</th>
            <th class="py-2 px-3 text-left">Amount</th>
            <th class="py-2 px-3 text-left">Status</th>
            <th class="py-2 px-3 text-left">Receipt</th>
            <th class="py-2 px-3 text-left">Actions</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach ($payments as $p): ?>
            <tr class="border-t">
              <td class="py-2 px-3"><?php echo (int)$p['payment_id']; ?></td>
              <td class="py-2 px-3"><?php echo htmlspecialchars($p['vendor_name']); ?> <div class="text-xs text-gray-500"><?php echo htmlspecialchars($p['contact_number']); ?></div></td>
              <td class="py-2 px-3"><?php echo htmlspecialchars($p['business_name'] ?? ''); ?> <div class="text-xs text-gray-500">Stall: <?php echo htmlspecialchars($p['stall_number'] ?? ''); ?></div></td>
              <td class="py-2 px-3"><?php echo formatDate($p['due_date']); ?></td>
              <td class="py-2 px-3"><?php echo formatCurrency($p['amount']); ?></td>
              <td class="py-2 px-3"><?php echo getStatusBadge($p['status']); ?></td>
              <td class="py-2 px-3">
                <?php if (!empty($p['receipt_number'])): ?>
                  <a class="text-blue-600" href="download_receipt.php?payment_id=<?php echo (int)$p['payment_id']; ?>" target="_blank">View Receipt</a>
                <?php else: ?>
                  <span class="text-gray-500">No receipt</span>
                <?php endif; ?>
              </td>
              <td class="py-2 px-3">
                <form method="POST" action="" class="space-y-1">
                  <input type="hidden" name="payment_id" value="<?php echo (int)$p['payment_id']; ?>">
                  <textarea name="admin_notes" placeholder="Optional admin notes" class="w-full border rounded px-2 py-1 text-sm"></textarea>
                  <div class="flex gap-2 mt-2">
                    <button type="submit" name="action" value="verify" class="bg-green-600 text-white px-3 py-1 rounded text-sm">Verify</button>
                    <button type="submit" name="action" value="reject" class="bg-red-600 text-white px-3 py-1 rounded text-sm">Reject</button>
                  </div>
                </form>
              </td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>

    <!-- pagination simple -->
    <div class="mt-4 flex justify-between items-center">
      <div class="text-sm text-gray-600">Showing <?php echo count($payments); ?> of <?php echo $total; ?> results</div>
      <div class="space-x-2">
        <?php if ($page > 1): ?><a class="px-3 py-1 bg-gray-200 rounded" href="?page=<?php echo $page-1; ?>">Prev</a><?php endif; ?>
        <?php if ($offset + $perPage < $total): ?><a class="px-3 py-1 bg-gray-200 rounded" href="?page=<?php echo $page+1; ?>">Next</a><?php endif; ?>
      </div>
    </div>

  <?php else: ?>
    <p class="text-center text-gray-500 p-6">No payments pending review.</p>
  <?php endif; ?>
</div>

<?php include 'includes/footer.php'; ?>