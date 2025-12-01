<?php
require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/helpers.php';
require_once 'includes/csrf.php';

if (!isLoggedIn()) redirect('login.php');
$user_id = $_SESSION['user_id'];

$page_title = 'My Profile';
$success = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_profile'])) {
    if (!csrf_validate_request()) {
        $error = 'Invalid CSRF token.';
    } else {
        $full_name = sanitize($_POST['full_name'] ?? '');
        $email = sanitize($_POST['email'] ?? '');
        $contact = sanitize($_POST['contact_number'] ?? '');

        if (!empty($email) && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Invalid email address.';
        } else {
            if ($db->query("UPDATE users SET full_name = ?, email = ?, contact_number = ? WHERE user_id = ?", [$full_name, $email, $contact, $user_id])) {
                logAudit($db, $user_id, 'Profile Updated', 'users', $user_id, null, null);
                $_SESSION['full_name'] = $full_name;
                $success = 'Profile updated.';
            } else $error = 'Failed to update profile.';
        }
    }
}

// load user
$user = $db->fetch("SELECT * FROM users WHERE user_id = ? LIMIT 1", [$user_id]);

require_once 'includes/header.php';
?>
<div class="max-w-md mx-auto p-6 bg-white rounded shadow">
  <h2 class="text-xl font-bold mb-4">My Profile</h2>
  <?php if ($error): ?><div class="text-red-600 mb-3"><?php echo htmlspecialchars($error); ?></div><?php endif; ?>
  <?php if ($success): ?><div class="text-green-600 mb-3"><?php echo htmlspecialchars($success); ?></div><?php endif; ?>

  <form method="POST">
    <?php echo csrf_field(); ?>
    <div class="mb-3">
      <label class="block text-sm">Full name</label>
      <input name="full_name" value="<?php echo htmlspecialchars($user['full_name'] ?? ''); ?>" class="w-full border px-3 py-2">
    </div>
    <div class="mb-3">
      <label class="block text-sm">Email</label>
      <input name="email" value="<?php echo htmlspecialchars($user['email'] ?? ''); ?>" class="w-full border px-3 py-2">
    </div>
    <div class="mb-3">
      <label class="block text-sm">Contact Number</label>
      <input name="contact_number" value="<?php echo htmlspecialchars($user['contact_number'] ?? ''); ?>" class="w-full border px-3 py-2">
    </div>
    <div>
      <button name="update_profile" class="bg-blue-600 text-white px-4 py-2 rounded">Update Profile</button>
    </div>
  </form>

  <div class="mt-6">
    <a href="reset_password.php" class="text-sm text-blue-600 hover:underline">Change password</a>
  </div>
</div>
<?php include 'includes/footer.php'; ?>