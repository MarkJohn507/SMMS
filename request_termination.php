<?php
// request_termination.php
// Vendor requests lease termination, but ONLY if there are no unpaid invoices (pending/partial/overdue)

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/csrf.php';
require_once 'includes/helpers.php';
require_once 'includes/notifications.php';

if (!isLoggedIn()) redirect('login.php?timeout=1');
$user_id = (int)($_SESSION['user_id'] ?? 0);
requireVendor();

$page_title = 'Request Lease Termination';
$errors = [];
$success = '';

// Validate lease id
$lease_id = isset($_GET['id']) ? (int)$_GET['id'] : (isset($_POST['lease_id']) ? (int)$_POST['lease_id'] : 0);
if ($lease_id <= 0) {
    $errors[] = 'Invalid lease specified.';
} else {
    // Load lease and ensure it belongs to this vendor
    try {
        $lease = $db->fetch("
            SELECT l.*, s.stall_number, m.market_name
            FROM leases l
            JOIN stalls s ON l.stall_id = s.stall_id
            JOIN markets m ON s.market_id = m.market_id
            WHERE l.lease_id = ? AND l.vendor_id = ?
            LIMIT 1
        ", [$lease_id, $user_id]);
        if (!$lease) {
            $errors[] = 'Lease not found or you do not have permission to manage this lease.';
        } else {
            // Check if lease is already terminated or requested
            $status_lc = strtolower(trim((string)$lease['status']));
            if (in_array($status_lc, ['terminated','expired','ended','cancelled'], true)) {
                $errors[] = 'This lease is already inactive.';
            } elseif (in_array($status_lc, ['termination_requested','terminate_requested','requested_termination'], true)) {
                $errors[] = 'A termination request has already been submitted for this lease.';
            } else {
                // Enforce: vendor cannot request if there are unpaid invoices (pending/partial/overdue)
                try {
                    $unpaid = $db->fetch("
                        SELECT COUNT(*) AS cnt
                        FROM payments
                        WHERE lease_id = ?
                          AND LOWER(TRIM(status)) IN ('pending','partial','overdue')
                    ", [$lease_id]);
                    $unpaid_cnt = (int)($unpaid['cnt'] ?? 0);
                    if ($unpaid_cnt > 0) {
                        $errors[] = 'You must settle all open invoices before requesting termination.';
                    }
                } catch (Throwable $e) {
                    error_log("termination: unpaid check failed: ".$e->getMessage());
                    $errors[] = 'Unable to verify payment status. Please try again later.';
                }
            }
        }
    } catch (Throwable $e) {
        error_log("termination: fetch lease failed: ".$e->getMessage());
        $errors[] = 'Failed to load lease details.';
    }
}

// Handle POST submit
if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($errors) && isset($_POST['confirm_termination'])) {
    if (!csrf_validate_request()) {
        $errors[] = 'Invalid CSRF token.';
    } else {
        $reason = sanitize($_POST['reason'] ?? '');
        if (strlen($reason) > 1000) $reason = substr($reason, 0, 1000);

        // Optional: create a separate termination requests table to track requests
        try {
            $db->query("CREATE TABLE IF NOT EXISTS termination_requests (
                request_id INT AUTO_INCREMENT PRIMARY KEY,
                lease_id INT NOT NULL,
                vendor_id INT NOT NULL,
                reason TEXT NULL,
                status VARCHAR(32) NOT NULL DEFAULT 'pending',
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                INDEX (lease_id),
                INDEX (vendor_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            // Prevent duplicate pending requests
            $existing = $db->fetch("
                SELECT request_id, status FROM termination_requests
                WHERE lease_id = ? AND status IN ('pending','review')
                ORDER BY created_at DESC
                LIMIT 1
            ", [$lease_id]);

            if ($existing) {
                $errors[] = 'A termination request is already pending review for this lease.';
            } else {
                $db->beginTransaction();

                // Insert request row
                $okReq = $db->query("
                    INSERT INTO termination_requests (lease_id, vendor_id, reason, status, created_at, updated_at)
                    VALUES (?, ?, ?, 'pending', NOW(), NOW())
                ", [$lease_id, $user_id, $reason]);

                if (!$okReq) throw new Exception('Failed to create termination request.');

                // Mark lease status as 'termination_requested' to reflect vendor action
                $okLease = $db->query("
                    UPDATE leases
                    SET status = 'termination_requested',
                        admin_notes = CONCAT(COALESCE(admin_notes,''), ?),
                        updated_at = NOW()
                    WHERE lease_id = ? AND vendor_id = ?
                ", ["\n[Vendor requested termination on ".date('Y-m-d H:i')."] Reason: ".($reason ?: '—'), $lease_id, $user_id]);

                if (!$okLease) throw new Exception('Failed to update lease status.');

                $db->commit();

                // Notify admins/market managers (optional: adjust role recipients as needed)
                try {
                    if (function_exists('createNotification')) {
                        // Notify vendor (confirmation)
                        createNotification($db, $user_id, 'Termination Request Submitted',
                            'Your termination request has been submitted and is pending review.',
                            'info', 'lease', $lease_id, 'leases');

                        // Attempt to notify relevant managers (simple broadcast; refine per your system)
                        $mgrs = $db->fetchAll("
                            SELECT DISTINCT ur.user_id
                            FROM user_roles ur
                            JOIN roles r ON ur.role_id = r.role_id
                            WHERE LOWER(r.name) IN ('market_manager','accountant','admin','municipal_admin','agency_admin','super_admin')
                              AND ur.status='active'
                            LIMIT 50
                        ") ?: [];
                        foreach ($mgrs as $m) {
                            $mid = (int)$m['user_id'];
                            if ($mid > 0) {
                                createNotification($db, $mid, 'Lease Termination Request',
                                    'A vendor requested termination for Lease #'.$lease_id.'. Please review.',
                                    'warning', 'lease', $lease_id, 'leases');
                            }
                        }
                    }
                } catch (Throwable $e) { /* ignore notify failures */ }

                logAudit($db, $user_id, 'Termination Requested', 'leases', $lease_id, null, $reason ?: null);
                $success = 'Your termination request has been submitted and is now pending review.';
            }
        } catch (Throwable $e) {
            try { $db->rollBack(); } catch (Throwable $e2) {}
            error_log("termination: submit failed: ".$e->getMessage());
            $errors[] = 'Failed to submit termination request.';
        }
    }
}

// If success, show simple confirmation and link back
if (!empty($success)) {
    require_once 'includes/header.php';
    require_once 'includes/vendor_sidebar.php';
    ?>
    <section class="max-w-3xl mx-auto p-6">
      <div class="bg-white rounded shadow p-6">
        <h2 class="text-lg font-semibold text-gray-800 mb-2">Termination Request Submitted</h2>
        <p class="text-gray-700 mb-4"><?php echo htmlspecialchars($success); ?></p>
        <a href="my_leases.php?tab=active#leases" class="inline-block px-4 py-2 bg-blue-600 text-white rounded">Back to My Leases</a>
      </div>
    </section>
    <?php
    require_once 'includes/footer.php';
    exit;
}

// Render form if no success
require_once 'includes/header.php';
require_once 'includes/vendor_sidebar.php';
?>
<section class="max-w-3xl mx-auto p-6">
  <div class="bg-white rounded shadow p-6">
    <h2 class="text-lg font-semibold text-gray-800 mb-4">Request Lease Termination</h2>

    <?php if ($errors): ?>
      <div class="mb-4 bg-red-50 border border-red-200 text-red-700 rounded p-4">
        <?php foreach ($errors as $e) echo '<div>'.htmlspecialchars($e).'</div>'; ?>
      </div>
    <?php endif; ?>

    <?php if (!empty($lease)): ?>
      <div class="mb-4 text-sm text-gray-700">
        <div><strong>Lease ID:</strong> <?php echo (int)$lease_id; ?></div>
        <div><strong>Market:</strong> <?php echo htmlspecialchars($lease['market_name'] ?? ''); ?></div>
        <div><strong>Stall:</strong> <?php echo htmlspecialchars($lease['stall_number'] ?? ''); ?></div>
        <div><strong>Status:</strong> <?php echo htmlspecialchars($lease['status'] ?? ''); ?></div>
      </div>
    <?php endif; ?>

    <?php if (empty($errors) && !empty($lease)): ?>
      <p class="text-gray-700 mb-4">
        You can request lease termination only if all invoices are fully paid. Once submitted, your request will be reviewed by the market administration.
      </p>
      <form method="POST">
        <?php echo csrf_field(); ?>
        <input type="hidden" name="lease_id" value="<?php echo (int)$lease_id; ?>">
        <input type="hidden" name="confirm_termination" value="1">

        <div class="mb-4">
          <label class="block text-sm font-medium mb-1">Reason (optional)</label>
          <textarea name="reason" rows="4" class="w-full border rounded px-3 py-2" placeholder="Describe your reason (optional)"></textarea>
        </div>

        <div class="flex items-center gap-3">
          <button type="submit" class="px-4 py-2 bg-red-600 text-white rounded">Submit Request</button>
          <a href="my_leases.php?tab=active#leases" class="px-4 py-2 bg-gray-200 rounded">Cancel</a>
        </div>
      </form>
    <?php else: ?>
      <a href="my_leases.php?tab=active#leases" class="inline-block px-4 py-2 bg-gray-200 rounded">Back</a>
    <?php endif; ?>
  </div>
</section>

<?php require_once 'includes/footer.php'; ?>