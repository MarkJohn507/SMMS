<?php
require_once 'config.php';
require_once 'includes/helpers.php';
require_once 'includes/audit.php';
require_once 'includes/csrf.php';
require_once 'includes/notifications.php';
require_once __DIR__ . '/API/send_sms.php'; // prefer sendSMS(), fallback to send_sms()

$page_title = 'Forgot Password';
$info = '';
$error = '';

/**
 * Generate an easy-to-type temporary password (alphanumeric only).
 * Avoid punctuation to reduce SMS/keyboard mangling.
 */
function generate_temporary_password_safe(int $len = 10): string {
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'; // Exclude ambiguous 0/O, 1/l
    $max = strlen($chars) - 1;
    $pwd = '';
    try {
        for ($i = 0; $i < $len; $i++) {
            $pwd .= $chars[random_int(0, $max)];
        }
    } catch (Throwable $e) {
        for ($i = 0; $i < $len; $i++) $pwd .= $chars[mt_rand(0, $max)];
    }
    return $pwd;
}

// Generic info message (do not reveal whether an account exists)
$genericInfo = 'If we recognize your email and a phone number is on file, we will send a temporary password by SMS. If you do not receive an SMS, please contact support.';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_validate_request()) {
        $error = 'Invalid CSRF token.';
    } else {
        $email = sanitize($_POST['email'] ?? '');
        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Please enter a valid email.';
        } else {
            try {
                $u = $db->fetch("SELECT user_id, email, contact_number FROM users WHERE email = ? LIMIT 1", [$email]);
            } catch (Throwable $e) {
                error_log("forgot_password: user lookup failed: " . $e->getMessage());
                $u = false;
            }

            // Always show generic response
            if (!$u) {
                $info = $genericInfo;
            } else {
                $user_id = (int)$u['user_id'];
                $contact_raw = trim((string)($u['contact_number'] ?? ''));

                if (empty($contact_raw)) {
                    // No phone on file — do not change anything, ask user to contact support
                    logAudit($db, $user_id, 'Forgot password attempted - no phone on file', 'users', $user_id, null, null);
                    $info = $genericInfo;
                } else {
                    // Normalize phone if helper exists
                    if (function_exists('normalize_phone_e164')) {
                        $phone = normalize_phone_e164($contact_raw, defined('DEFAULT_COUNTRY_CODE') ? DEFAULT_COUNTRY_CODE : '+63');
                    } else {
                        $phone = $contact_raw;
                    }

                    if (empty($phone)) {
                        logAudit($db, $user_id, 'Forgot password attempted - phone normalization failed', 'users', $user_id, null, $contact_raw);
                        $info = $genericInfo;
                    } else {
                        // Generate safe temp password (alphanumeric)
                        $tempPwd = generate_temporary_password_safe(10);
                        $hash = password_hash($tempPwd, PASSWORD_DEFAULT);

                        // Persist-first + send SMS inside DB transaction so we can roll back if SMS fails.
                        $sentOk = false;
                        try {
                            if (method_exists($db, 'beginTransaction')) $db->beginTransaction();

                            // Persist password
                            $db->query("UPDATE users SET password = ?, updated_at = NOW() WHERE user_id = ?", [$hash, $user_id]);

                            // Attempt to send SMS
                            $smsMsg = "Temporary password: {$tempPwd}. Log in and change it immediately.";
                            $sendResponse = null;
                            try {
                                if (function_exists('sendSMS')) {
                                    $sendResponse = sendSMS($phone, $smsMsg, null, null, $db);
                                    $sentOk = !empty($sendResponse['ok']);
                                } elseif (function_exists('send_sms')) {
                                    $sendResponse = send_sms($phone, $smsMsg);
                                    if (is_bool($sendResponse)) $sentOk = $sendResponse;
                                    elseif (is_array($sendResponse)) $sentOk = !empty($sendResponse['ok']);
                                    else $sentOk = false;
                                } else {
                                    error_log("forgot_password: no SMS function available");
                                    $sentOk = false;
                                }
                            } catch (Throwable $e) {
                                error_log("forgot_password: send SMS exception for user {$user_id} phone {$phone}: " . $e->getMessage());
                                $sentOk = false;
                            }

                            if ($sentOk) {
                                if (method_exists($db, 'commit')) $db->commit();
                                // Invalidate other sessions if a sessions table exists
                                try { $db->query("DELETE FROM sessions WHERE user_id = ?", [$user_id]); } catch (Throwable $e){}
                                // record audit + optional notification
                                logAudit($db, $user_id, 'Temporary password issued via SMS', 'users', $user_id, null, null);
                                if (function_exists('createNotification')) {
                                    createNotification($db, $user_id, 'Temporary password sent', 'A temporary password was sent to your registered phone.', 'info', 'security', null, null);
                                }
                                // Optionally log the sendResponse for debug (do NOT log plaintext password)
                                error_log("forgot_password: SMS sent ok for user {$user_id}, provider_resp=" . json_encode($sendResponse));
                                $info = $genericInfo;
                            } else {
                                // SMS failed — rollback DB to previous password
                                if (method_exists($db, 'rollBack')) $db->rollBack();
                                logAudit($db, $user_id, 'Temporary password SMS failed - rolled back', 'users', $user_id, null, null);
                                error_log("forgot_password: SMS send failed for user {$user_id} phone {$phone}, provider_resp=" . json_encode($sendResponse));
                                $info = $genericInfo;
                            }
                        } catch (Throwable $e) {
                            // Ensure rollback on DB error
                            try { if (method_exists($db,'rollBack')) $db->rollBack(); } catch (Throwable $e2) {}
                            error_log("forgot_password: transaction failed for user {$user_id}: " . $e->getMessage());
                            $info = $genericInfo;
                        }
                    }
                }
            }
        }
    }
}

require_once 'includes/header.php';
?>
<div class="max-w-md mx-auto p-6 bg-white rounded shadow">
  <h2 class="text-xl font-bold mb-4">Forgot Password</h2>
  <?php if ($error): ?><div class="mb-3 text-red-600"><?php echo htmlspecialchars($error); ?></div><?php endif; ?>
  <?php if ($info): ?><div class="mb-3 text-green-600"><?php echo htmlspecialchars($info); ?></div><?php endif; ?>
  <form method="POST">
    <?php echo csrf_field(); ?>
    <div class="mb-3">
      <label class="block text-sm">Email</label>
      <input name="email" class="w-full border px-3 py-2" required>
    </div>

    <div class="flex items-center gap-3">
      <button class="bg-blue-600 text-white px-4 py-2 rounded">Submit</button>
      <a href="login.php" class="inline-block text-sm bg-gray-100 hover:bg-gray-200 text-gray-800 px-3 py-2 rounded">Go back to Sign In</a>
    </div>
  </form>

  <p class="text-xs text-gray-500 mt-3">
    If we recognize your email and a phone number is on file, we will send a temporary password by SMS. If you do not receive an SMS, please contact support.
  </p>
</div>
<?php include 'includes/footer.php'; ?>