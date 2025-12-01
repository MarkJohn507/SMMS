<?php
require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/csrf.php';
require_once 'includes/notifications.php';

requireVendor();

$page_title = 'My Profile';
$vendor_id = getCurrentUserId();
$error = '';
$success = '';

// Defensive vendor fetch
try {
    $vendor = $db->fetch("SELECT * FROM users WHERE user_id = ? LIMIT 1", [$vendor_id]);
    if (!$vendor) {
        // Shouldn't happen for logged-in vendor, but guard anyway
        logout();
        redirect('login.php?timeout=1');
    }
} catch (Throwable $e) {
    error_log("vendor_profile: failed to fetch vendor: " . $e->getMessage());
    $vendor = [
        'user_id' => $vendor_id,
        'full_name' => '',
        'username' => '',
        'email' => '',
        'contact_number' => '',
        'verification_data' => null,
        'status' => 'inactive',
        'role' => 'vendor',
        'created_at' => null,
        'updated_at' => null,
        'password' => ''
    ];
    $error = 'Failed to load profile. Please try again later.';
}

// Helpers for verification_data
$verification_info = $vendor['verification_data'] ? json_decode($vendor['verification_data'], true) : null;
if (json_last_error() !== JSON_ERROR_NONE) $verification_info = null;
$verification_status = function_exists('getVerificationStatus') ? getVerificationStatus($vendor['verification_data']) : ($verification_info ? 'pending' : 'not_submitted');

// --- Handle profile update ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_profile'])) {
    if (!csrf_validate_request()) {
        $error = 'Invalid CSRF token.';
    } else {
        $full_name = sanitize($_POST['full_name'] ?? '');
        $email = sanitize($_POST['email'] ?? '');
        $contact_number = sanitize($_POST['contact_number'] ?? '');

        // Basic validation
        if ($full_name === '' || $email === '') {
            $error = 'Full name and email are required.';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Please provide a valid email address.';
        } else {
            try {
                $ok = $db->query("UPDATE users SET full_name = ?, email = ?, contact_number = ?, updated_at = NOW() WHERE user_id = ?", [$full_name, $email, $contact_number, $vendor_id]);
                if ($ok) {
                    $_SESSION['full_name'] = $full_name;
                    logAudit($db, $vendor_id, 'Profile Updated', 'users', $vendor_id, null, null);

                    // Notify user (best-effort)
                    try {
                        if (function_exists('createNotification')) {
                            createNotification($db, $vendor_id, 'Profile Updated', 'Your profile information was updated successfully.', 'info', 'profile', $vendor_id, 'users');
                        }
                    } catch (Throwable $e) {
                        error_log("vendor_profile: createNotification failed (profile update): " . $e->getMessage());
                    }

                    $success = 'Profile updated successfully!';
                    // Refresh vendor data
                    $vendor = $db->fetch("SELECT * FROM users WHERE user_id = ? LIMIT 1", [$vendor_id]);
                    $verification_info = $vendor['verification_data'] ? json_decode($vendor['verification_data'], true) : null;
                } else {
                    $error = 'Failed to update profile.';
                }
            } catch (Throwable $e) {
                error_log("vendor_profile: update profile failed: " . $e->getMessage());
                $error = 'Failed to update profile (server error).';
            }
        }
    }
}

// --- Handle password change ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['change_password'])) {
    if (!csrf_validate_request()) {
        $error = 'Invalid CSRF token.';
    } else {
        $current_password = $_POST['current_password'] ?? '';
        $new_password = $_POST['new_password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';

        $min_len = defined('PASSWORD_MIN_LENGTH') ? PASSWORD_MIN_LENGTH : 8;

        if ($current_password === '' || $new_password === '' || $confirm_password === '') {
            $error = 'All password fields are required.';
        } elseif ($new_password !== $confirm_password) {
            $error = 'New passwords do not match.';
        } elseif (strlen($new_password) < $min_len) {
            $error = "Password must be at least {$min_len} characters long.";
        } else {
            try {
                // Re-fetch fresh vendor record to ensure current password is up-to-date
                $fresh = $db->fetch("SELECT password FROM users WHERE user_id = ? LIMIT 1", [$vendor_id]);
                $storedHash = $fresh['password'] ?? $vendor['password'] ?? '';
                if (empty($storedHash) || !password_verify($current_password, $storedHash)) {
                    $error = 'Current password is incorrect.';
                } else {
                    $hashed = password_hash($new_password, PASSWORD_DEFAULT);
                    $ok = $db->query("UPDATE users SET password = ?, updated_at = NOW() WHERE user_id = ?", [$hashed, $vendor_id]);
                    if ($ok) {
                        logAudit($db, $vendor_id, 'Password Changed', 'users', $vendor_id, null, null);

                        // Best-effort: notify user
                        try {
                            if (function_exists('createNotification')) {
                                createNotification($db, $vendor_id, 'Password Changed', 'Your account password was changed.', 'warning', 'security', $vendor_id, 'users');
                            }
                        } catch (Throwable $e) {
                            error_log("vendor_profile: createNotification failed (password): " . $e->getMessage());
                        }

                        $success = 'Password changed successfully!';
                    } else {
                        $error = 'Failed to change password.';
                    }
                }
            } catch (Throwable $e) {
                error_log("vendor_profile: change password error: " . $e->getMessage());
                $error = 'Failed to change password (server error).';
            }
        }
    }
}

// --- Handle verification resubmission ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['resubmit_verification'])) {
    if (!csrf_validate_request()) {
        $error = 'Invalid CSRF token.';
    } else {
        $address = sanitize($_POST['address'] ?? '');
        $id_type = sanitize($_POST['id_type'] ?? '');
        $id_number = sanitize($_POST['id_number'] ?? '');

        if ($address === '' || $id_type === '' || $id_number === '') {
            $error = 'All verification fields are required.';
        } else {
            // Build sanitized verification payload (whitelist keys)
            $payload = [
                'address' => mb_substr($address, 0, 2000),
                'id_type' => $id_type,
                'id_number' => mb_substr($id_number, 0, 200),
                'resubmitted_at' => date('Y-m-d H:i:s'),
                'status' => 'pending'
            ];
            $verification_data = json_encode($payload);

            try {
                $ok = $db->query("UPDATE users SET verification_data = ?, updated_at = NOW() WHERE user_id = ?", [$verification_data, $vendor_id]);
                if ($ok) {
                    logAudit($db, $vendor_id, 'Verification Resubmitted', 'users', $vendor_id, null, null);

                    // Notify admin(s) best-effort
                    try {
                        $admin = $db->fetch("SELECT user_id FROM users WHERE role = 'admin' AND status = 'active' LIMIT 1");
                        if ($admin && function_exists('createNotification')) {
                            createNotification($db, $admin['user_id'],
                                'Verification Resubmitted',
                                "Vendor '" . ($vendor['full_name'] ?? $vendor['username']) . "' has resubmitted verification documents.",
                                'info', 'vendor_verification', $vendor_id, 'users');
                        }
                    } catch (Throwable $ne) {
                        error_log("vendor_profile: notify admin failed: " . $ne->getMessage());
                    }

                    $success = 'Verification documents resubmitted successfully! Please wait for admin review.';
                    // Refresh vendor data
                    $vendor = $db->fetch("SELECT * FROM users WHERE user_id = ? LIMIT 1", [$vendor_id]);
                    $verification_info = $vendor['verification_data'] ? json_decode($vendor['verification_data'], true) : null;
                } else {
                    $error = 'Failed to resubmit verification.';
                }
            } catch (Throwable $e) {
                error_log("vendor_profile: resubmit verification error: " . $e->getMessage());
                $error = 'Failed to resubmit verification (server error).';
            }
        }
    }
}

// --- Vendor statistics (defensive queries) ---
$total_applications = 0;
$active_leases = 0;
$total_payments = 0.0;

try {
    $r = $db->fetch("SELECT COUNT(*) AS total FROM applications WHERE vendor_id = ?", [$vendor_id]);
    $total_applications = (int)($r['total'] ?? 0);
} catch (Throwable $e) {
    error_log("vendor_profile: total applications query failed: " . $e->getMessage());
}

try {
    $r = $db->fetch("SELECT COUNT(*) AS total FROM leases WHERE vendor_id = ? AND status = 'active'", [$vendor_id]);
    $active_leases = (int)($r['total'] ?? 0);
} catch (Throwable $e) {
    error_log("vendor_profile: active leases query failed: " . $e->getMessage());
}

try {
    $r = $db->fetch("SELECT COALESCE(SUM(amount),0) AS total FROM payments WHERE vendor_id = ? AND status = 'paid'", [$vendor_id]);
    $total_payments = (float)($r['total'] ?? 0.0);
} catch (Throwable $e) {
    error_log("vendor_profile: total payments query failed: " . $e->getMessage());
}

// Refresh verification-related variables
$verification_info = $vendor['verification_data'] ? json_decode($vendor['verification_data'], true) : null;
if (json_last_error() !== JSON_ERROR_NONE) $verification_info = null;
$verification_status = function_exists('getVerificationStatus') ? getVerificationStatus($vendor['verification_data']) : ($verification_info ? 'pending' : 'not_submitted');

include 'includes/header.php';
include 'includes/vendor_sidebar.php';
?>

<!-- Page Header -->
<div class="mb-6">
    <h3 class="text-2xl font-bold text-gray-800 mb-2">My Profile</h3>
    <p class="text-gray-600">Manage your account information and settings</p>
</div>

<!-- Messages -->
<?php if ($error): ?>
    <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-6" role="alert">
        <span class="block sm:inline"><?php echo htmlspecialchars($error); ?></span>
    </div>
<?php endif; ?>

<?php if ($success): ?>
    <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-6" role="alert">
        <span class="block sm:inline"><?php echo htmlspecialchars($success); ?></span>
    </div>
<?php endif; ?>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- Left Column - Profile Info -->
    <div class="lg:col-span-1">
        <!-- Profile Card -->
        <div class="bg-white rounded-lg shadow-md p-6 mb-6">
            <div class="text-center">
                <div class="w-32 h-32 bg-gradient-to-br from-green-400 to-green-600 rounded-full mx-auto mb-4 flex items-center justify-center text-white text-4xl font-bold">
                    <?php echo strtoupper(substr($vendor['full_name'] ?? '', 0, 2)); ?>
                </div>
                <div class="flex items-center justify-center gap-2 flex-wrap">
                    <h3 class="text-xl font-bold text-gray-800 mb-1"><?php echo htmlspecialchars($vendor['full_name'] ?? ''); ?></h3>
                    <?php if ($verification_status === 'verified'): ?>
                        <span class="inline-flex items-center px-2 py-0.5 bg-blue-100 text-blue-800 rounded-full text-xs font-medium mb-1">
                            Verified
                        </span>
                    <?php endif; ?>
                </div>
                <p class="text-gray-600 mb-2"><?php echo htmlspecialchars($vendor['username'] ?? ''); ?></p>
                <span class="inline-block px-3 py-1 bg-green-100 text-green-800 rounded-full text-sm font-medium">
                    Vendor
                </span>

                <div class="mt-4 pt-4 border-t border-gray-200">
                    <p class="text-sm text-gray-600">Member since</p>
                    <p class="font-semibold text-gray-800"><?php echo !empty($vendor['created_at']) ? formatDate($vendor['created_at']) : '-'; ?></p>
                </div>
            </div>
        </div>

        <!-- Statistics Card -->
        <div class="bg-white rounded-lg shadow-md p-6">
            <h4 class="text-lg font-semibold text-gray-800 mb-4">Account Statistics</h4>
            <div class="space-y-4">
                <div class="flex items-center justify-between">
                    <span class="text-gray-600">Total Applications</span>
                    <span class="font-bold text-gray-800"><?php echo $total_applications; ?></span>
                </div>
                <div class="flex items-center justify-between">
                    <span class="text-gray-600">Active Leases</span>
                    <span class="font-bold text-green-600"><?php echo $active_leases; ?></span>
                </div>
                <div class="flex items-center justify-between">
                    <span class="text-gray-600">Total Paid</span>
                    <span class="font-bold text-blue-600"><?php echo function_exists('formatCurrency') ? formatCurrency($total_payments) : number_format($total_payments,2); ?></span>
                </div>
            </div>
        </div>
    </div>

    <!-- Right Column - Forms -->
    <div class="lg:col-span-2">
        <!-- Verification Status block (as before) -->
        <?php if ($verification_status === 'pending'): ?>
            <div class="bg-yellow-50 border border-yellow-300 rounded-lg p-6 mb-6">
                <div class="flex items-start">
                    <div class="flex-1">
                        <h4 class="text-lg font-semibold text-yellow-800 mb-2">Verification Pending</h4>
                        <p class="text-sm text-yellow-700 mb-3">Your account verification is currently under review by the administrator. You will be notified once the review is complete.</p>
                        <?php if ($verification_info): ?>
                            <div class="bg-yellow-100 rounded p-3 text-xs text-yellow-800">
                                <p><strong>Submitted Information:</strong></p>
                                <p>Address: <?php echo htmlspecialchars($verification_info['address'] ?? 'N/A'); ?></p>
                                <p>ID Type: <?php echo htmlspecialchars(strtoupper(str_replace('_',' ',$verification_info['id_type'] ?? 'N/A'))); ?></p>
                                <p>ID Number: <?php echo htmlspecialchars($verification_info['id_number'] ?? 'N/A'); ?></p>
                                <?php if (!empty($verification_info['resubmitted_at'])): ?>
                                    <p>Resubmitted: <?php echo date('M d, Y h:i A', strtotime($verification_info['resubmitted_at'])); ?></p>
                                <?php endif; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        <?php elseif ($verification_status === 'verified'): ?>
            <div class="bg-blue-50 border border-blue-300 rounded-lg p-6 mb-6">
                <div class="flex items-start">
                    <div class="flex-1">
                        <h4 class="text-lg font-semibold text-blue-800 mb-2">Account Verified</h4>
                        <p class="text-sm text-blue-700">Your account has been verified by the administrator. This badge indicates you are a trusted vendor with full access to all features.</p>
                    </div>
                </div>
            </div>
        <?php elseif ($verification_status === 'rejected'): ?>
            <div class="bg-red-50 border border-red-300 rounded-lg p-6 mb-6">
                <div class="flex items-start">
                    <div class="flex-1">
                        <h4 class="text-lg font-semibold text-red-800 mb-2">Verification Rejected</h4>
                        <p class="text-sm text-red-700 mb-4">Your verification documents were rejected by the administrator. Please review the information and resubmit with correct details.</p>
                        <?php if ($verification_info && isset($verification_info['rejection_reason'])): ?>
                            <div class="bg-red-100 rounded p-3 mb-4 text-sm text-red-800">
                                <p><strong>Rejection Reason:</strong></p>
                                <p><?php echo htmlspecialchars($verification_info['rejection_reason']); ?></p>
                            </div>
                        <?php endif; ?>
                        <button onclick="openResubmitModal()" class="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition text-sm font-medium">
                            Resubmit Verification Documents
                        </button>
                    </div>
                </div>
            </div>
        <?php endif; ?>

        <!-- Profile Information Form -->
        <div class="bg-white rounded-lg shadow-md p-6 mb-6">
            <h4 class="text-lg font-semibold text-gray-800 mb-6">Profile Information</h4>
            <form method="POST" action="">
                <?php echo csrf_field(); ?>
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Username</label>
                        <input type="text" value="<?php echo htmlspecialchars($vendor['username'] ?? ''); ?>" disabled class="w-full px-4 py-2 border border-gray-300 rounded-lg bg-gray-100 text-gray-600">
                        <p class="text-xs text-gray-500 mt-1">Username cannot be changed</p>
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Full Name *</label>
                        <input type="text" name="full_name" value="<?php echo htmlspecialchars($vendor['full_name'] ?? ''); ?>" required class="w-full px-4 py-2 border border-gray-300 rounded-lg">
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Email Address *</label>
                        <input type="email" name="email" value="<?php echo htmlspecialchars($vendor['email'] ?? ''); ?>" required class="w-full px-4 py-2 border border-gray-300 rounded-lg">
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Contact Number</label>
                        <input type="text" name="contact_number" value="<?php echo htmlspecialchars($vendor['contact_number'] ?? ''); ?>" class="w-full px-4 py-2 border border-gray-300 rounded-lg" placeholder="e.g., 09171234567">
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Verification Status</label>
                        <div class="flex items-center">
                            <?php echo function_exists('getVerificationBadge') ? getVerificationBadge($vendor['verification_data']) : '<span class="text-xs text-gray-600">-</span>'; ?>
                        </div>
                    </div>

                    <div class="pt-4">
                        <button type="submit" name="update_profile" class="w-full bg-green-600 text-white py-3 rounded-lg">Update Profile</button>
                    </div>
                </div>
            </form>
        </div>

        <!-- Change Password Form -->
        <div class="bg-white rounded-lg shadow-md p-6">
            <h4 class="text-lg font-semibold text-gray-800 mb-6">Change Password</h4>
            <form method="POST" action="">
                <?php echo csrf_field(); ?>
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Current Password *</label>
                        <input type="password" name="current_password" required class="w-full px-4 py-2 border border-gray-300 rounded-lg">
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">New Password *</label>
                        <input type="password" name="new_password" required minlength="<?php echo defined('PASSWORD_MIN_LENGTH') ? PASSWORD_MIN_LENGTH : 8; ?>" class="w-full px-4 py-2 border border-gray-300 rounded-lg">
                        <p class="text-xs text-gray-500 mt-1">Password must be at least <?php echo defined('PASSWORD_MIN_LENGTH') ? PASSWORD_MIN_LENGTH : 8; ?> characters long</p>
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Confirm New Password *</label>
                        <input type="password" name="confirm_password" required minlength="<?php echo defined('PASSWORD_MIN_LENGTH') ? PASSWORD_MIN_LENGTH : 8; ?>" class="w-full px-4 py-2 border border-gray-300 rounded-lg">
                    </div>

                    <div class="pt-4">
                        <button type="submit" name="change_password" class="w-full bg-blue-600 text-white py-3 rounded-lg">Change Password</button>
                    </div>
                </div>
            </form>
        </div>

        <!-- Account Activity -->
        <div class="bg-white rounded-lg shadow-md p-6 mt-6">
            <h4 class="text-lg font-semibold text-gray-800 mb-4">Account Activity</h4>
            <div class="space-y-3">
                <div class="flex items-center justify-between py-2 border-b border-gray-200">
                    <span class="text-gray-600">Last Login</span>
                    <span class="text-gray-800 font-medium"><?php echo !empty($_SESSION['last_activity']) ? date('M d, Y h:i A', $_SESSION['last_activity']) : 'Just now'; ?></span>
                </div>
                <div class="flex items-center justify-between py-2 border-b border-gray-200">
                    <span class="text-gray-600">Account Created</span>
                    <span class="text-gray-800 font-medium"><?php echo !empty($vendor['created_at']) ? formatDate($vendor['created_at']) : '-'; ?></span>
                </div>
                <div class="flex items-center justify-between py-2">
                    <span class="text-gray-600">Last Profile Update</span>
                    <span class="text-gray-800 font-medium"><?php echo !empty($vendor['updated_at']) ? formatDate($vendor['updated_at']) : '-'; ?></span>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Resubmit Verification Modal -->
<div id="resubmitModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
    <div class="bg-white rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div class="p-6">
            <div class="flex items-center justify-between mb-6">
                <h3 class="text-2xl font-bold text-gray-800">Resubmit Verification Documents</h3>
                <button onclick="closeResubmitModal()" class="text-gray-500 hover:text-gray-700">✕</button>
            </div>

            <form method="POST" action="">
                <?php echo csrf_field(); ?>
                <div class="space-y-4">
                    <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-4">
                        <p class="text-sm text-yellow-800"><strong>Note:</strong> Please ensure all information is accurate. Your documents will be reviewed by an administrator.</p>
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Complete Address *</label>
                        <textarea name="address" required rows="3" class="w-full px-4 py-2 border border-gray-300 rounded-lg"><?php echo htmlspecialchars($verification_info['address'] ?? ''); ?></textarea>
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">ID Type *</label>
                        <select name="id_type" required class="w-full px-4 py-2 border border-gray-300 rounded-lg">
                            <option value="">Select ID Type</option>
                            <?php
                            $idTypes = ['national_id'=>'National ID','drivers_license'=>"Driver's License",'passport'=>'Passport','sss_id'=>'SSS ID','umid'=>'UMID','tin_id'=>'TIN ID','postal_id'=>'Postal ID','voters_id'=>"Voter's ID"];
                            foreach ($idTypes as $k=>$label): ?>
                                <option value="<?php echo $k; ?>" <?php echo (isset($verification_info['id_type']) && $verification_info['id_type'] === $k) ? 'selected' : ''; ?>><?php echo $label; ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">ID Number *</label>
                        <input type="text" name="id_number" required value="<?php echo htmlspecialchars($verification_info['id_number'] ?? ''); ?>" class="w-full px-4 py-2 border border-gray-300 rounded-lg">
                    </div>

                    <div class="bg-blue-50 border border-blue-200 rounded-lg p-4">
                        <p class="text-xs text-blue-800"><strong>Privacy Notice:</strong> Your information will be kept confidential and used only for verification purposes.</p>
                    </div>

                    <div class="flex gap-4 pt-4">
                        <button type="submit" name="resubmit_verification" class="flex-1 bg-blue-600 text-white py-3 rounded-lg">Submit for Review</button>
                        <button type="button" onclick="closeResubmitModal()" class="flex-1 bg-gray-300 text-gray-700 py-3 rounded-lg">Cancel</button>
                    </div>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
function openResubmitModal() {
    document.getElementById('resubmitModal').classList.remove('hidden');
}
function closeResubmitModal() {
    document.getElementById('resubmitModal').classList.add('hidden');
}
document.addEventListener('keydown', function(e) { if (e.key === 'Escape') closeResubmitModal(); });
const modalEl = document.getElementById('resubmitModal'); if (modalEl) modalEl.addEventListener('click', function(e){ if (e.target === this) closeResubmitModal(); });
</script>

<?php include 'includes/footer.php'; ?>