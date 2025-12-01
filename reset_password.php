<?php
require_once 'config.php';
require_once 'includes/helpers.php';
require_once 'includes/audit.php';
require_once 'includes/csrf.php';
require_once 'includes/notifications.php';

$page_title = 'Reset Password';
$error = '';
$success = '';
$token = $_GET['token'] ?? ($_POST['token'] ?? '');

if (empty($token)) {
    $error = 'Invalid token.';
} else {
    $row = $db->fetch("SELECT pr.*, u.user_id FROM password_resets pr JOIN users u ON pr.user_id = u.user_id WHERE pr.token = ? ORDER BY pr.created_at DESC LIMIT 1", [$token]);
    if (!$row || strtotime($row['expires_at']) < time()) {
        $error = 'Token invalid or expired.';
    } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!csrf_validate_request()) {
            $error = 'Invalid CSRF token.';
        } else {
            $new = $_POST['new_password'] ?? '';
            if (strlen($new) < 6) $error = 'Password must be at least 6 characters.';
            else {
                $hash = password_hash($new, PASSWORD_DEFAULT);
                $db->query("UPDATE users SET password = ? WHERE user_id = ?", [$hash, $row['user_id']]);
                $db->query("DELETE FROM password_resets WHERE user_id = ?", [$row['user_id']]);
                logAudit($db, $row['user_id'], 'Password Reset', 'users', $row['user_id'], null, null);
                createNotification($db, $row['user_id'], 'Password Reset', 'Your password has been reset.', 'info', 'general', null, null);
                $success = 'Password updated. You may now login.';
            }
        }
    }
}

require_once 'includes/header.php';
?>
<div class="max-w-md mx-auto p-6 bg-white rounded shadow">
  <h2 class="text-xl font-bold mb-4">Reset Password</h2>
  <?php if ($error): ?><div class="text-red-600 mb-3"><?php echo htmlspecialchars($error); ?></div><?php endif; ?>
  <?php if ($success): ?><div class="text-green-600 mb-3"><?php echo htmlspecialchars($success); ?></div><?php else: ?>
  <form method="POST">
    <?php echo csrf_field(); ?>
    <input type="hidden" name="token" value="<?php echo htmlspecialchars($token); ?>">
    <div class="mb-3"><label class="block text-sm">New Password</label><input name="new_password" type="password" class="w-full border px-3 py-2"></div>
    <div><button class="bg-blue-600 text-white px-4 py-2 rounded">Set New Password</button></div>
  </form>
  <?php endif; ?>
</div>
<?php include 'includes/footer.php'; ?>