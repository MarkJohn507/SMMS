<?php
require_once 'config.php';
require_once 'includes/helpers.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';

// This page expects the login flow to have set:
// $_SESSION['pending_2fa_user_id']  - user awaiting 2FA challenge
// $_SESSION['login_return_to']      - optional return URL after successful login
//
// If not present, redirect to login.
if (empty($_SESSION['pending_2fa_user_id'])) {
    redirect('login.php');
}

$user_id = (int)$_SESSION['pending_2fa_user_id'];
$page_title = 'Two-factor Authentication Challenge';

// Helper: Base32 decode (for TOTP secrets stored in base32)
if (!function_exists('base32_decode')) {
    function base32_decode($b32) {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $b32 = strtoupper(preg_replace('/[^A-Z2-7]/', '', $b32));
        $bits = '';
        $out = '';
        for ($i = 0; $i < strlen($b32); $i++) {
            $val = strpos($alphabet, $b32[$i]);
            $bits .= str_pad(decbin($val), 5, '0', STR_PAD_LEFT);
            while (strlen($bits) >= 8) {
                $byte = substr($bits, 0, 8);
                $bits = substr($bits, 8);
                $out .= chr(bindec($byte));
            }
        }
        return $out;
    }
}

// Helper: TOTP verify (time-step 30s, allow ±1 step window)
if (!function_exists('verify_totp')) {
    function verify_totp($secret_base32, $code, $drift = 1) {
        $secret = base32_decode($secret_base32);
        $timeSlice = floor(time() / 30);
        for ($i = -$drift; $i <= $drift; $i++) {
            $ts = $timeSlice + $i;
            $tsBytes = pack('N*', 0) . pack('N*', $ts); // 8-byte int
            $hash = hash_hmac('sha1', $tsBytes, $secret, true);
            $offset = ord(substr($hash, -1)) & 0x0F;
            $truncated = substr($hash, $offset, 4);
            $value = unpack('N', $truncated)[1] & 0x7fffffff;
            $generatedCode = str_pad($value % 1000000, 6, '0', STR_PAD_LEFT);
            if (hash_equals($generatedCode, (string)$code)) return true;
        }
        return false;
    }
}

// Fetch user's primary active TOTP device (prefer is_primary)
$device = $db->fetch(
    "SELECT device_id, device_type, secret, phone_number, status, is_primary FROM twofactor_devices WHERE user_id = ? AND status = 'active' ORDER BY is_primary DESC LIMIT 1",
    [$user_id]
);

// If no active device, fall back - disallow and ask to contact admin
if (!$device) {
    // Clear pending session and show message
    unset($_SESSION['pending_2fa_user_id']);
    $_SESSION['error_message'] = 'Two-factor authentication is required but no active device was found. Contact support.';
    redirect('login.php');
}

// Handle POST (verify code)
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $code = trim($_POST['totp_code'] ?? '');
    if (empty($code)) {
        $error = 'Please enter the authentication code.';
    } else {
        $ok = false;
        if ($device['device_type'] === 'totp' && !empty($device['secret'])) {
            try {
                $ok = verify_totp($device['secret'], $code, 1);
            } catch (Throwable $e) {
                $ok = false;
            }
        } elseif ($device['device_type'] === 'sms') {
            // If using SMS, the code should match a previously generated OTP stored somewhere.
            // Here we assume there's a simple table payment_reminders or similar — but since none exists,
            // we won't implement SMS OTP storage. Reject and ask vendor to use TOTP or contact admin.
            $ok = false;
        }

        if ($ok) {
            // Mark 2FA success: promote pending login to authenticated session
            // (Depending on your login flow, you may have stored user data before 2FA)
            $_SESSION['user_id'] = $user_id;
            // Optionally set other session fields from users table
            $u = $db->fetch("SELECT username, full_name, role FROM users WHERE user_id = ? LIMIT 1", [$user_id]);
            if ($u) {
                $_SESSION['username'] = $u['username'];
                $_SESSION['full_name'] = $u['full_name'];
                $_SESSION['role'] = $u['role'];
            }
            // remove pending 2FA marker and note passed
            unset($_SESSION['pending_2fa_user_id']);
            $_SESSION['2fa_passed'] = true;

            // Audit
            logAudit($db, $user_id, 'Two-factor Challenge Passed', 'users', $user_id, null, null);

            // Redirect to desired page or dashboard
            $return = $_SESSION['login_return_to'] ?? null;
            if ($return) {
                unset($_SESSION['login_return_to']);
                redirect($return);
            }

            // Redirect based on role (RBAC-aware)
            $is_vendor = $db->fetch("SELECT 1 FROM user_roles ur JOIN roles r ON ur.role_id = r.role_id WHERE ur.user_id = ? AND ur.status = 'active' AND r.name = 'vendor' LIMIT 1", [$user_id]);
            if ($is_vendor) redirect('vendor_dashboard.php');

            $is_admin = isAdmin();
            if ($is_admin) redirect('admin_dashboard.php');

            // fallback
            redirect('vendor_dashboard.php');
        } else {
            // audit failed attempt
            logAudit($db, $user_id, 'Two-factor Challenge Failed', 'users', $user_id, null, null);
            $error = 'Invalid authentication code. Please try again.';
        }
    }
}

// Render challenge form
require_once 'includes/header.php';
require_once (isAdmin() ? 'includes/admin_sidebar.php' : 'includes/vendor_sidebar.php');
?>
<section class="max-w-xl mx-auto p-6">
  <div class="bg-white rounded shadow p-6">
    <h1 class="text-2xl font-bold mb-4">Two-factor Authentication</h1>

    <p class="mb-4 text-sm text-gray-600">
      Enter the 6-digit code from your authenticator app to continue.
      <?php if ($device['device_type'] !== 'totp'): ?>
        <br><strong>Note:</strong> your configured 2FA device is <?php echo htmlspecialchars($device['device_type']); ?>. If you cannot complete this step contact support.
      <?php endif; ?>
    </p>

    <?php if ($error): ?>
      <div class="bg-red-100 border border-red-300 text-red-700 p-3 rounded mb-4"><?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>

    <form method="POST" action="twofactor_challenge.php" class="space-y-4">
      <input type="hidden" name="csrf_token" value="<?php echo csrf_get_token(); ?>">
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-1">Authentication code</label>
        <input name="totp_code" type="text" inputmode="numeric" pattern="\d{6}" maxlength="6" minlength="6" required
               class="w-full px-4 py-2 border rounded" placeholder="123456" autofocus>
      </div>

      <div class="flex items-center justify-between">
        <button type="submit" class="px-4 py-2 bg-green-600 text-white rounded">Verify</button>
        <a href="login.php" class="text-sm text-gray-600 hover:underline">Cancel</a>
      </div>
    </form>

    <div class="mt-6 text-xs text-gray-500">
      If you don't have access to your authenticator app, contact an administrator to reset your 2FA settings.
    </div>
  </div>
</section>

<?php include 'includes/footer.php'; ?>