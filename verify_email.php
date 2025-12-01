<?php
require_once 'config.php';
require_once 'includes/helpers.php';
require_once 'includes/audit.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

$token = $_GET['token'] ?? '';
$token = trim($token);
$message = '';
$success = false;

if ($token === '') {
    $message = 'Missing token.';
} else {
    try {
        $row = $db->fetch("SELECT ev.id, ev.user_id, ev.expires_at, u.email, u.full_name, u.status FROM email_verifications ev JOIN users u ON ev.user_id = u.user_id WHERE ev.token = ? LIMIT 1", [$token]);
        if (!$row) {
            $message = 'Invalid or expired token.';
        } else {
            $expires = $row['expires_at'];
            if (strtotime($expires) < time()) {
                $message = 'Token expired. Please request a new verification email.';
                // optionally remove expired token
                $db->query("DELETE FROM email_verifications WHERE id = ?", [$row['id']]);
            } else {
                // mark user as verified (do not auto-activate roles unless you want to)
                $db->query("UPDATE users SET verified_at = NOW() WHERE user_id = ?", [$row['user_id']]);
                // remove token
                $db->query("DELETE FROM email_verifications WHERE id = ?", [$row['id']]);

                // audit & notify user + admins
                logAudit($db, $row['user_id'], 'Email Verified', 'users', $row['user_id'], null, null);

                // Notify admins that a user verified (helpful for approval workflow)
                try {
                    $admins = $db->fetchAll("SELECT u.user_id FROM user_roles ur JOIN roles r ON ur.role_id = r.role_id JOIN users u ON ur.user_id = u.user_id WHERE r.name IN ('municipal_admin','super_admin') AND ur.status = 'active'");
                    $msg = "User {$row['full_name']} ({$row['email']}) verified their email.";
                    foreach ($admins as $a) {
                        $db->query("INSERT INTO notifications (user_id, title, message, type, category, created_at) VALUES (?, 'User Verified', ?, 'info', 'system', NOW())", [$a['user_id'], $msg]);
                    }
                } catch (Throwable $e) {
                    error_log("verify_email: admin notify failed: " . $e->getMessage());
                }

                $message = 'Email verified successfully. Your account will be reviewed if approval is required.';
                $success = true;
            }
        }
    } catch (Throwable $e) {
        error_log("verify_email error: " . $e->getMessage());
        $message = 'Verification failed, please try again later.';
    }
}

// Render a simple page
require_once 'includes/header.php';
?>
<div class="max-w-lg mx-auto mt-12 bg-white p-6 rounded shadow">
  <h2 class="text-lg font-semibold mb-4">Email Verification</h2>
  <?php if ($success): ?>
    <div class="text-green-700"><?php echo htmlspecialchars($message); ?></div>
  <?php else: ?>
    <div class="text-red-600"><?php echo htmlspecialchars($message); ?></div>
  <?php endif; ?>
  <div class="mt-4">
    <a href="login.php" class="text-blue-600">Return to login</a>
  </div>
</div>
<?php include 'includes/footer.php'; ?>