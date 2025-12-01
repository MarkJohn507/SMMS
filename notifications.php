<?php
require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/notifications.php';
require_once 'includes/csrf.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

if (!isLoggedIn()) redirect('login.php');

$user_id = (int)($_SESSION['user_id'] ?? 0);
$page_title = 'Notifications';
$error = '';
$success = '';

/**
 * Helper: check whether a user has any of the provided role names.
 * Uses userIsInRole() when available, otherwise falls back to session roles or _fetchUserRoleNames().
 */
function userHasAnyRoleNames($db, int $userId, array $roleNames): bool {
    $roleNames = array_map('strtolower', $roleNames);
    try {
        if (function_exists('userIsInRole')) {
            foreach ($roleNames as $r) {
                if (userIsInRole($db, $userId, $r)) return true;
            }
            return false;
        }
    } catch (Throwable $e) {
        error_log("userHasAnyRoleNames: userIsInRole failed: " . $e->getMessage());
    }

    // Fallback to list of roles
    try {
        if (function_exists('_fetchUserRoleNames')) {
            $roles = _fetchUserRoleNames($userId, $db) ?: [];
        } else {
            $roles = $_SESSION['roles'] ?? [];
        }
        $roles = array_map('strtolower', (array)$roles);
        foreach ($roleNames as $r) {
            if (in_array($r, $roles, true)) return true;
        }
    } catch (Throwable $e) {
        error_log("userHasAnyRoleNames fallback failed: " . $e->getMessage());
    }

    return false;
}

// Mark all read (POST)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['mark_all_read'])) {
    if (!csrf_validate_request()) {
        $error = 'Invalid CSRF token.';
    } else {
        try {
            $db->query("UPDATE notifications SET is_read = 1 WHERE user_id = ?", [$user_id]);
            logAudit($db, $user_id, 'Mark All Notifications Read', 'notifications', null, null, null);
            $success = 'All notifications marked read.';
        } catch (Throwable $e) {
            error_log("notifications: mark_all_read failed for user {$user_id}: " . $e->getMessage());
            $error = 'Failed to mark notifications as read.';
        }
    }
}

// Delete all notifications for current user (POST)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_all'])) {
    if (!csrf_validate_request()) {
        $error = 'Invalid CSRF token.';
    } else {
        try {
            // count for audit / user feedback
            $countRow = $db->fetch("SELECT COUNT(*) AS cnt FROM notifications WHERE user_id = ?", [$user_id]);
            $count = (int)($countRow['cnt'] ?? 0);

            if ($count === 0) {
                $success = 'No notifications to delete.';
            } else {
                $db->query("DELETE FROM notifications WHERE user_id = ?", [$user_id]);
                logAudit($db, $user_id, 'Delete All Notifications', 'notifications', null, null, "deleted_count: {$count}");
                $success = 'All notifications deleted.';
            }
        } catch (Throwable $e) {
            error_log("notifications: delete_all failed for user {$user_id}: " . $e->getMessage());
            $error = 'Failed to delete notifications.';
        }
    }
}

// Delete single notification (POST)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_notification'])) {
    if (!csrf_validate_request()) {
        $error = 'Invalid CSRF token.';
    } else {
        $nid = (int)($_POST['notification_id'] ?? 0);
        try {
            $n = $db->fetch("SELECT * FROM notifications WHERE notification_id = ? LIMIT 1", [$nid]);
            // allow delete if owned by user or user is admin-like
            $adminLikeRoles = ['super_admin','municipal_admin','issuer_admin','admin','agency_admin'];
            $isAdminLike = userHasAnyRoleNames($db, $user_id, $adminLikeRoles);
            if ($n && ($n['user_id'] == $user_id || $isAdminLike)) {
                $db->query("DELETE FROM notifications WHERE notification_id = ?", [$nid]);
                logAudit($db, $user_id, 'Delete Notification', 'notifications', $nid, null, null);
                $success = 'Notification deleted.';
            } else {
                $error = 'Notification not found or forbidden.';
            }
        } catch (Throwable $e) {
            error_log("notifications: delete_notification failed for user {$user_id}, nid={$nid}: " . $e->getMessage());
            $error = 'Failed to delete notification.';
        }
    }
}

// Fetch notifications
try {
    $notifications = $db->fetchAll("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 100", [$user_id]) ?: [];
} catch (Throwable $e) {
    error_log("notifications: fetch failed for user {$user_id}: " . $e->getMessage());
    $notifications = [];
}

// Decide which sidebar to include.
// Previously the page used isAdmin() only which caused accountant/inspector/market_manager to receive vendor sidebar.
// We'll treat admin-like roles (including accountant, inspector, market_manager) as seeing admin_sidebar.
$adminLikeRoles = ['super_admin','municipal_admin','issuer_admin','admin','agency_admin','accountant','inspector','market_manager'];
$showAdminSidebar = userHasAnyRoleNames($db, $user_id, $adminLikeRoles);

require_once 'includes/header.php';
require_once ($showAdminSidebar ? 'includes/admin_sidebar.php' : 'includes/vendor_sidebar.php');
?>

<section class="max-w-4xl mx-auto p-6">
  <div class="mb-4 flex items-center justify-between">
    <h1 class="text-2xl font-bold">Notifications</h1>

    <div class="flex items-center gap-2">
      <form method="POST" class="inline">
        <?php echo csrf_field(); ?>
        <button name="mark_all_read" class="px-3 py-2 bg-gray-200 rounded">Mark all read</button>
      </form>

      <form method="POST" class="inline" onsubmit="return confirmDeleteAll();">
        <?php echo csrf_field(); ?>
        <button name="delete_all" type="submit" class="px-3 py-2 bg-red-600 text-white rounded">Delete all</button>
      </form>
    </div>
  </div>

  <?php if ($error): ?>
    <div class="bg-red-100 p-3 rounded mb-4"><?php echo htmlspecialchars($error); ?></div>
  <?php endif; ?>
  <?php if ($success): ?>
    <div class="bg-green-100 p-3 rounded mb-4"><?php echo htmlspecialchars($success); ?></div>
  <?php endif; ?>

  <?php if ($notifications && count($notifications) > 0): ?>
    <div class="space-y-3">
      <?php foreach ($notifications as $n): ?>
        <div class="bg-white border rounded p-4 flex justify-between items-start">
          <div>
            <p class="font-semibold"><?php echo htmlspecialchars($n['title']); ?></p>
            <p class="text-sm text-gray-600"><?php echo htmlspecialchars($n['message']); ?></p>
            <p class="text-xs text-gray-400 mt-2"><?php echo htmlspecialchars($n['created_at']); ?></p>
          </div>
          <div class="flex flex-col items-end gap-2">
            <?php if (empty($n['is_read'])): ?>
              <form method="POST" action="mark_notification_read.php" class="inline" onsubmit="return markReadAjax(this);">
                <?php echo csrf_field(); ?>
                <input type="hidden" name="notification_id" value="<?php echo (int)$n['notification_id']; ?>">
                <button type="submit" class="px-3 py-1 bg-blue-600 text-white rounded text-sm">Mark read</button>
              </form>
            <?php endif; ?>
            <form method="POST" class="inline" onsubmit="return confirm('Delete this notification?');">
              <?php echo csrf_field(); ?>
              <input type="hidden" name="notification_id" value="<?php echo (int)$n['notification_id']; ?>">
              <button type="submit" name="delete_notification" class="px-3 py-1 bg-red-600 text-white rounded text-sm">Delete</button>
            </form>
          </div>
        </div>
      <?php endforeach; ?>
    </div>
  <?php else: ?>
    <div class="bg-white p-8 rounded text-center text-gray-500">No notifications.</div>
  <?php endif; ?>
</section>

<script>
function markReadAjax(form) {
  const fd = new FormData(form);
  fetch(form.action, {
    method: 'POST',
    body: fd,
    credentials: 'same-origin',
    headers: {'X-Requested-With': 'XMLHttpRequest'}
  }).then(r => r.json()).then(j => {
    if (j.ok) location.reload();
    else alert('Failed: ' + (j.error || 'unknown'));
  }).catch(e => alert('Error: ' + e));
  return false;
}

function confirmDeleteAll() {
  return confirm('Are you sure you want to permanently delete ALL your notifications? This action cannot be undone.');
}
</script>

</section>

<?php include 'includes/footer.php'; ?>