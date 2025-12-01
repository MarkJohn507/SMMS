<?php
/**
 * application_details.php (Vendor/Admin view – refined)
 * - Preferred Start Date clearly displayed, formatted with formatDate and raw date tooltip.
 * - Vendor can cancel if pending.
 * - Admin/Market Manager can approve/reject (optional).
 * - Hardening: permissions, CSRF validation, consistent refresh after actions.
 */

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/csrf.php';
require_once 'includes/notifications.php';
require_once 'includes/helpers.php'; // for formatDate, getStatusBadge, sanitize

if (!isLoggedIn()) redirect('login.php?timeout=1');

$uid = $_SESSION['user_id'] ?? null;
$application_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
if ($application_id <= 0) redirect('my_applications.php');

$page_title = 'Application Details';
$error = '';
$success = '';

function fetchApp($db, int $application_id) {
    return $db->fetch("
        SELECT a.application_id, a.vendor_id, a.business_name, a.business_type,
               a.status, a.application_date, a.preferred_start_date,
               a.admin_notes, a.reviewed_at, a.reviewed_by,
               s.stall_id, s.stall_number, s.floor_number, s.stall_size, s.monthly_rent,
               m.market_name, m.location,
               u.full_name AS vendor_name, u.email AS vendor_email
        FROM applications a
        JOIN stalls s ON a.stall_id = s.stall_id
        JOIN markets m ON s.market_id = m.market_id
        JOIN users u ON a.vendor_id = u.user_id
        WHERE a.application_id = ? LIMIT 1
    ", [$application_id]);
}

// Load app
$app = fetchApp($db, $application_id);
if (!$app) redirect('my_applications.php');

// Role flags
$isVendorOwner = ((int)$app['vendor_id'] === (int)$uid);
$isAdmin = isAdmin() || (function_exists('userIsInRole') && (userIsInRole($db,$uid,'super_admin') || userIsInRole($db,$uid,'market_manager')));

// Handle POST actions (vendor cancel, admin approve/reject)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Vendor cancel
    if (isset($_POST['cancel_application']) && $isVendorOwner && strtolower((string)$app['status']) === 'pending') {
        if (!csrf_validate_request()) {
            $error = 'Invalid CSRF token.';
        } else {
            try {
                $db->query(
                    "UPDATE applications
                     SET status='cancelled',
                         admin_notes = CONCAT(COALESCE(admin_notes,''), ?),
                         reviewed_at=NOW(), reviewed_by=?
                     WHERE application_id=?",
                    ["\n[Cancelled by vendor at ".date('Y-m-d H:i:s')."]", $uid, $application_id]
                );
                // Free stall
                try { $db->query("UPDATE stalls SET status='available' WHERE stall_id=?", [$app['stall_id']]); } catch (Throwable $e){}
                logAudit($db,$uid,'Application Cancelled','applications',$application_id,null,null);
                $success = 'Application cancelled.';
                $app = fetchApp($db, $application_id);
            } catch (Throwable $e) {
                $error = 'Failed to cancel application.';
                error_log("application_details cancel failed: ".$e->getMessage());
            }
        }
    }

    // Admin approve
    if (isset($_POST['approve_application']) && $isAdmin && strtolower((string)$app['status']) === 'pending') {
        if (!csrf_validate_request()) {
            $error = 'Invalid CSRF token.';
        } else {
            try {
                $db->query("UPDATE applications SET status='approved', reviewed_by=?, reviewed_at=NOW() WHERE application_id=?",
                    [$uid, $application_id]);
                logAudit($db,$uid,'Application Approved','applications',$application_id,null,null);
                $success = 'Application approved.';
                $app = fetchApp($db, $application_id);
            } catch (Throwable $e) {
                $error = 'Failed to approve.';
            }
        }
    }

    // Admin reject
    if (isset($_POST['reject_application']) && $isAdmin && strtolower((string)$app['status']) === 'pending') {
        if (!csrf_validate_request()) {
            $error = 'Invalid CSRF token.';
        } else {
            $reason = sanitize($_POST['rejection_reason'] ?? '');
            if (empty($reason)) {
                $error = 'Provide a rejection reason.';
            } else {
                try {
                    $db->query("UPDATE applications SET status='rejected', admin_notes=CONCAT(COALESCE(admin_notes,''), ?), reviewed_by=?, reviewed_at=NOW() WHERE application_id=?",
                        ["\n[Rejected: {$reason}]", $uid, $application_id]);
                    // Make stall available again
                    try { $db->query("UPDATE stalls SET status='available' WHERE stall_id=?", [$app['stall_id']]); } catch (Throwable $e){}
                    logAudit($db,$uid,'Application Rejected','applications',$application_id,null,$reason);
                    $success = 'Application rejected.';
                    $app = fetchApp($db, $application_id);
                } catch (Throwable $e) {
                    $error = 'Failed to reject.';
                }
            }
        }
    }
}

logAudit($db,$uid,'View Application Details','applications',$application_id,null,null);

require_once 'includes/header.php';
require_once ($isAdmin ? 'includes/admin_sidebar.php' : 'includes/vendor_sidebar.php');
?>
<section class="max-w-4xl mx-auto p-6">
  <div class="flex items-center justify-between mb-6">
    <h1 class="text-2xl font-bold">Application #<?php echo (int)$app['application_id']; ?></h1>
    <div><?php echo getStatusBadge($app['status']); ?></div>
  </div>

  <?php if ($error): ?>
    <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4"><?php echo htmlspecialchars($error); ?></div>
  <?php endif; ?>
  <?php if ($success): ?>
    <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-4"><?php echo htmlspecialchars($success); ?></div>
  <?php endif; ?>

  <!-- Business -->
  <div class="bg-white rounded shadow p-5 mb-6">
    <h2 class="text-lg font-semibold mb-2">Business Information</h2>
    <p><strong><?php echo htmlspecialchars($app['business_name']); ?></strong>
       <span class="text-sm text-gray-600"> — <?php echo htmlspecialchars($app['business_type'] ?? ''); ?></span></p>
    <p class="text-sm text-gray-600">Applicant: <?php echo htmlspecialchars($app['vendor_name']); ?> (<?php echo htmlspecialchars($app['vendor_email']); ?>)</p>
  </div>

  <!-- Stall & Market -->
  <div class="bg-white rounded shadow p-5 mb-6">
    <h2 class="text-lg font-semibold mb-2">Stall & Market</h2>
    <p><strong>Stall:</strong> <?php echo htmlspecialchars($app['stall_number']); ?><?php if (!empty($app['floor_number'])): ?> (Floor <?php echo (int)$app['floor_number']; ?>)<?php endif; ?></p>
    <p><strong>Size:</strong> <?php echo htmlspecialchars($app['stall_size']); ?></p>
    <p><strong>Market:</strong> <?php echo htmlspecialchars($app['market_name']); ?> — <?php echo htmlspecialchars($app['location']); ?></p>
    <p><strong>Monthly Rent:</strong> <?php echo formatCurrency($app['monthly_rent']); ?></p>
  </div>

  <!-- Application Dates -->
  <div class="bg-white rounded shadow p-5 mb-6">
    <h2 class="text-lg font-semibold mb-2">Dates</h2>
    <p><strong>Applied:</strong> <?php echo formatDate($app['application_date']); ?></p>
    <p><strong>Preferred Start:</strong>
      <?php
        $pref = $app['preferred_start_date'];
        echo !empty($pref)
          ? '<span title="'.htmlspecialchars($pref).'">'.htmlspecialchars(formatDate($pref)).'</span>'
          : '-';
      ?>
    </p>
    <?php if (!empty($app['reviewed_at'])): ?>
      <p><strong>Reviewed At:</strong> <?php echo formatDate($app['reviewed_at'], true); ?></p>
    <?php endif; ?>
  </div>

  <!-- Admin Notes -->
  <div class="bg-white rounded shadow p-5 mb-6">
    <h2 class="text-lg font-semibold mb-2">Admin Notes</h2>
    <?php if (!empty($app['admin_notes'])): ?>
      <pre class="whitespace-pre-wrap text-sm text-gray-700 bg-gray-50 p-3 rounded"><?php echo htmlspecialchars($app['admin_notes']); ?></pre>
    <?php else: ?>
      <p class="text-sm text-gray-600">No notes added.</p>
    <?php endif; ?>
  </div>

  <!-- Actions -->
  <div class="bg-white rounded shadow p-5">
    <h2 class="text-lg font-semibold mb-4">Actions</h2>

    <?php if ($isVendorOwner && strtolower((string)$app['status']) === 'pending'): ?>
      <form method="POST" onsubmit="return confirm('Cancel this application?');" class="inline-block">
        <?php echo csrf_field(); ?>
        <input type="hidden" name="application_id" value="<?php echo (int)$app['application_id']; ?>">
        <button type="submit" name="cancel_application" class="px-4 py-2 bg-red-600 text-white rounded">
          Cancel Application
        </button>
      </form>
    <?php endif; ?>

    <?php if ($isAdmin && strtolower((string)$app['status']) === 'pending'): ?>
      <form method="POST" class="inline-block ml-3" onsubmit="return confirm('Approve this application?');">
        <?php echo csrf_field(); ?>
        <input type="hidden" name="application_id" value="<?php echo (int)$app['application_id']; ?>">
        <button type="submit" name="approve_application" class="px-4 py-2 bg-green-600 text-white rounded">
          Approve
        </button>
      </form>

      <button type="button"
              onclick="document.getElementById('rejectBox').classList.remove('hidden');"
              class="px-4 py-2 bg-yellow-600 text-white rounded ml-2">
        Reject
      </button>

      <div id="rejectBox" class="hidden mt-4">
        <form method="POST" onsubmit="return confirm('Reject this application?');">
          <?php echo csrf_field(); ?>
          <input type="hidden" name="application_id" value="<?php echo (int)$app['application_id']; ?>">
            <div class="mb-2">
              <label class="text-sm font-medium">Reason *</label>
              <textarea name="rejection_reason" rows="3" required class="w-full px-3 py-2 border rounded"></textarea>
            </div>
            <button type="submit" name="reject_application" class="px-4 py-2 bg-red-600 text-white rounded">
              Confirm Reject
            </button>
            <button type="button" onclick="document.getElementById('rejectBox').classList.add('hidden');"
                    class="px-4 py-2 bg-gray-300 text-gray-800 rounded ml-2">Cancel</button>
        </form>
      </div>
    <?php endif; ?>

    <?php if (!$isVendorOwner && !$isAdmin): ?>
      <p class="text-sm text-gray-500">No actions available.</p>
    <?php endif; ?>
  </div>
</section>

<?php include 'includes/footer.php'; ?>