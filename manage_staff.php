<?php
/**
 * manage_staff.php
 *
 * List and manage staff (inspector / accountant) accounts for markets the
 * current market_manager manages. Includes create-staff modal and reset-password
 * which sends an SMS (uses API/send_sms.php).
 *
 * NOTE: This file expects csrf_field() and csrf_validate_request() helpers,
 * a $db PDO-like wrapper, and that config.php sets things up.
 */

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/csrf.php';
require_once 'includes/audit.php';
require_once 'includes/notifications.php';
require_once 'includes/helpers.php';
require_once 'API/send_sms.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

// Must be logged in
if (empty($_SESSION['user_id'])) {
    redirect('login.php');
}
$uid = (int)$_SESSION['user_id'];

/*
 * Resolve active roles for current user (cache in session when possible)
 */
$roles = $_SESSION['roles'] ?? [];
if (empty($roles)) {
    try {
        $rows = $db->fetchAll(
            "SELECT r.name
             FROM user_roles ur
             JOIN roles r ON ur.role_id = r.role_id
             WHERE ur.user_id = ? AND ur.status = 'active'",
            [$uid]
        ) ?: [];
        foreach ($rows as $rr) {
            if (!empty($rr['name'])) $roles[] = $rr['name'];
        }
    } catch (Throwable $e) {
        error_log("manage_staff: role lookup failed: " . $e->getMessage());
    }
}
$roles = array_values(array_unique($roles));

/*
 * Small helper guards — declare only if not already declared to avoid redeclare
 * errors when other includes define the same helpers.
 */
if (!function_exists('hasRoleLocal')) {
    function hasRoleLocal(array $roles, string $role): bool {
        return in_array($role, $roles, true);
    }
}

if (!function_exists('getManagedMarketIds')) {
    /**
     * Returns array of market_id integers that this user manages (via market_managers
     * table) or created (fallback).
     */
    function getManagedMarketIds($db, int $userId): array {
        $ids = [];
        try {
            $rows = $db->fetchAll("SELECT market_id FROM market_managers WHERE user_id = ?", [$userId]) ?: [];
            foreach ($rows as $r) {
                if (!empty($r['market_id'])) $ids[] = (int)$r['market_id'];
            }
        } catch (Throwable $e) {
            error_log("getManagedMarketIds: market_managers query failed: " . $e->getMessage());
        }
        if (empty($ids)) {
            try {
                $rows2 = $db->fetchAll("SELECT market_id FROM markets WHERE created_by = ?", [$userId]) ?: [];
                foreach ($rows2 as $r) {
                    if (!empty($r['market_id'])) $ids[] = (int)$r['market_id'];
                }
            } catch (Throwable $e) {
                error_log("getManagedMarketIds: markets fallback failed: " . $e->getMessage());
            }
        }
        return array_values(array_unique($ids));
    }
}

if (!function_exists('normalize_for_sms')) {
    /**
     * Best-effort normalize phone number for SMS (E.164-like).
     * Defers to normalize_phone_e164() when available.
     */
    function normalize_for_sms(?string $raw): ?string {
        if (empty($raw)) return null;
        if (function_exists('normalize_phone_e164')) {
            try {
                $n = normalize_phone_e164($raw);
                if (!empty($n)) return $n;
            } catch (Throwable $e) {
                // fallback
            }
        }
        $s = trim((string)$raw);
        $digits = preg_replace('/\D+/', '', $s);
        if ($digits === '') return null;
        // Philippines heuristics:
        if (strlen($digits) === 10 && $digits[0] === '9') {
            return '+63' . $digits;
        }
        if (strlen($digits) >= 10 && $digits[0] === '0') {
            return '+63' . ltrim($digits, '0');
        }
        if (strpos($digits, '63') === 0) {
            return '+' . $digits;
        }
        if (strpos($s, '+') === 0) {
            return $s;
        }
        return '+' . $digits;
    }
}

/* Flags */
$is_super          = hasRoleLocal($roles, 'super_admin');
$is_market_manager = hasRoleLocal($roles, 'market_manager');

/* Hard deny: super_admin forbidden on this page */
if ($is_super) {
    http_response_code(403);
    echo "Forbidden";
    exit;
}
/* Access: only market_manager */
if (!$is_market_manager) {
    http_response_code(403);
    echo "Forbidden";
    exit;
}

/* Managed markets */
$managed_market_ids = getManagedMarketIds($db, $uid);

/* Managed markets list for create modal */
$managed_markets = [];
if (!empty($managed_market_ids)) {
    $ph = implode(',', array_fill(0, count($managed_market_ids), '?'));
    try {
        $managed_markets = $db->fetchAll("SELECT market_id, market_name FROM markets WHERE market_id IN ($ph) ORDER BY market_name", $managed_market_ids) ?: [];
    } catch (Throwable $e) {
        error_log("manage_staff: fetch managed markets failed: " . $e->getMessage());
        $managed_markets = [];
    }
}

/* Staff roles */
$allowed_staff_roles = ['inspector', 'accountant'];

$page_title = 'Manage Staff Accounts';
$errors  = '';
$success = '';

/* -------------------- POST actions -------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST)) {
    if (!csrf_validate_request()) {
        $errors = 'Invalid CSRF token.';
    } else {
        $action = $_POST['action'] ?? '';

        // Scope checker: find the market_id assigned to target user_role (latest)
        $checkScope = function(int $target_user_id) use ($managed_market_ids, $db): bool {
            if (empty($managed_market_ids)) return false;
            try {
                $row = $db->fetch(
                    "SELECT ur.market_id
                     FROM user_roles ur
                     WHERE ur.user_id = ?
                       AND ur.market_id IS NOT NULL
                     ORDER BY ur.assigned_at DESC
                     LIMIT 1",
                    [$target_user_id]
                );
                if (!$row || $row['market_id'] === null) return false;
                return in_array((int)$row['market_id'], $managed_market_ids, true);
            } catch (Throwable $e) {
                return false;
            }
        };

        /* Change status */
        if ($action === 'change_status') {
            $target_id  = (int)($_POST['user_id'] ?? 0);
            $new_status = sanitize($_POST['status'] ?? '');
            if ($target_id <= 0 || $new_status === '') {
                $errors = 'Invalid request.';
            } else {
                if (!$checkScope($target_id)) {
                    $errors = 'Forbidden: out of scope.';
                } else {
                    try {
                        $old = $db->fetch("SELECT status, full_name FROM users WHERE user_id = ? LIMIT 1", [$target_id]);
                        $ok  = $db->query("UPDATE users SET status = ?, updated_at = NOW() WHERE user_id = ?", [$new_status, $target_id]);
                        if ($ok) {
                            logAudit($db, $uid, 'Staff status changed', 'users', $target_id, $old['status'] ?? null, $new_status);
                            if (function_exists('createNotification')) {
                                createNotification($db, $target_id, 'Account Status Changed',
                                    "Your account status was changed to {$new_status}.",
                                    $new_status === 'active' ? 'success' : 'warning',
                                    'account', $target_id, 'users');
                            }
                            $success = "Status updated for " . htmlspecialchars($old['full_name'] ?? 'user');
                        } else {
                            $errors = 'Failed to update status.';
                        }
                    } catch (Throwable $e) {
                        error_log("manage_staff: change_status failed: " . $e->getMessage());
                        $errors = 'Server error while updating status.';
                    }
                }
            }
        }

        /* Reset password (sends SMS instead of email) */
        if ($action === 'reset_password') {
            $target_id = (int)($_POST['user_id'] ?? 0);
            if ($target_id <= 0) {
                $errors = 'Invalid user.';
            } else {
                if (!$checkScope($target_id)) {
                    $errors = 'Forbidden: out of scope.';
                } else {
                    $temp = substr(bin2hex(random_bytes(6)), 0, 12);
                    $hash = password_hash($temp, PASSWORD_DEFAULT);
                    try {
                        $ok = $db->query("UPDATE users SET password = ?, updated_at = NOW() WHERE user_id = ?", [$hash, $target_id]);
                        if ($ok) {
                            logAudit($db, $uid, 'Staff password reset', 'users', $target_id, null, null);

                            // Attempt to send SMS with temporary password
                            $userRow = $db->fetch("SELECT contact_number, full_name FROM users WHERE user_id = ? LIMIT 1", [$target_id]);
                            $sentSms = false;
                            $smsError = null;

                            if ($userRow && !empty($userRow['contact_number'])) {
                                $to = normalize_for_sms($userRow['contact_number']);
                                $name = trim($userRow['full_name'] ?? '');
                                $labelName = $name !== '' ? $name : 'User';
                                $message = "Hello {$labelName}, your password was reset by your market manager. Temporary password: {$temp}. Please login and change it.";

                                try {
                                    if (function_exists('send_sms')) {
                                        $smsResult = send_sms($to, $message);
                                    } else {
                                        // No SMS gateway helper available
                                        $smsResult = false;
                                    }
                                    if ($smsResult) {
                                        $sentSms = true;
                                        if (function_exists('createNotification')) {
                                            createNotification($db, $target_id, 'Password Reset (SMS)',
                                                'Your password was reset and a temporary password was sent via SMS.',
                                                'success', 'security', $target_id, 'users');
                                        }
                                    } else {
                                        $smsError = 'SMS gateway returned failure or not configured.';
                                    }
                                } catch (Throwable $e) {
                                    $smsError = 'SMS send failed: ' . $e->getMessage();
                                    error_log("manage_staff: SMS send failed: " . $e->getMessage());
                                }
                            }

                            if ($sentSms) {
                                $success = 'Password reset. Temporary password has been sent via SMS if the user\'s phone number is valid.';
                            } else {
                                // Fallback: notify user via internal notification and instruct manager
                                if (function_exists('createNotification')) {
                                    createNotification($db, $target_id, 'Password Reset',
                                        'Your password was reset. Contact your market manager for the temporary password.',
                                        'warning', 'security', $target_id, 'users');
                                }
                                $errors = 'Password reset but SMS could not be delivered. Ask the user to provide a valid phone number.';
                                if (!empty($smsError)) {
                                    error_log("manage_staff: reset_password SMS error for user {$target_id}: {$smsError}");
                                }
                            }
                        } else {
                            $errors = 'Failed to reset password.';
                        }
                    } catch (Throwable $e) {
                        error_log("manage_staff: reset_password failed: " . $e->getMessage());
                        $errors = 'Server error while resetting password.';
                    }
                }
            }
        }
    }
}

/* -------------------- Listing Filters & Query -------------------- */
$status_filter = isset($_GET['status']) ? sanitize($_GET['status']) : 'all';
$role_filter   = isset($_GET['role'])   ? sanitize($_GET['role'])   : 'all';
$search        = isset($_GET['search']) ? sanitize($_GET['search']) : '';

$ph_u = implode(',', array_fill(0, count($allowed_staff_roles), '?'));
$ph_r = implode(',', array_fill(0, count($allowed_staff_roles), '?'));

$sql = "SELECT u.user_id, u.username, u.full_name, u.email, u.contact_number,
               u.status, COALESCE(r.name, u.role) AS role_name, ur.market_id
        FROM users u
        LEFT JOIN user_roles ur ON u.user_id = ur.user_id
        LEFT JOIN roles r      ON ur.role_id = r.role_id
        WHERE (u.role IN ($ph_u) OR r.name IN ($ph_r))";

$params = array_merge($allowed_staff_roles, $allowed_staff_roles);

// Scope by market
if (empty($managed_market_ids)) {
    $staff = []; // no managed markets => empty list
} else {
    $ph_m = implode(',', array_fill(0, count($managed_market_ids), '?'));
    $sql .= " AND ur.market_id IN ($ph_m)";
    $params = array_merge($params, $managed_market_ids);
}

// Filters
if ($status_filter !== 'all') {
    $sql .= " AND u.status = ?";
    $params[] = $status_filter;
}
if ($role_filter !== 'all') {
    $sql .= " AND (u.role = ? OR r.name = ?)";
    $params[] = $role_filter;
    $params[] = $role_filter;
}
if ($search !== '') {
    $sql .= " AND (u.full_name LIKE ? OR u.username LIKE ? OR u.email LIKE ?)";
    $like = "%{$search}%";
    $params[] = $like; $params[] = $like; $params[] = $like;
}

$sql .= " GROUP BY u.user_id ORDER BY u.created_at DESC";

try {
    if (!isset($staff)) {
        $staff = $db->fetchAll($sql, $params) ?: [];
    }
} catch (Throwable $e) {
    error_log("manage_staff: listing failed: " . $e->getMessage());
    $staff = [];
}

/* Messages from create_staff.php redirect */
$create_staff_error = $_SESSION['staff_error'] ?? null;
$create_staff_success = $_SESSION['staff_success'] ?? null;
unset($_SESSION['staff_error'], $_SESSION['staff_success']);

require_once 'includes/header.php';
require_once 'includes/admin_sidebar.php';
?>
<!-- Inline availability CSS for the Create Staff modal -->
<style>
.availability-status { font-weight: 600; font-size: 0.9rem; min-width:84px; display:inline-block; }
.av-checked { opacity: 0.95; transition: opacity 120ms ease-in-out; }
.av-checking { color: #6b7280; } /* gray */
.av-available { color: #16a34a; } /* green */
.av-taken { color: #dc2626; } /* red */
.av-error { color: #6b7280; }
.animate-pulse { opacity: 0.7; }
</style>

<div class="max-w-7xl mx-auto p-6">
    <div class="mb-6 flex items-center justify-between">
        <div>
            <p class="text-gray-600 text-sm">Inspector / Accountant accounts for your managed markets.</p>
        </div>

        <?php if (empty($managed_market_ids) || empty($managed_markets)): ?>
            <button disabled title="You do not manage any markets" class="bg-gray-300 text-gray-700 px-4 py-2 rounded cursor-not-allowed">
                Create Staff
            </button>
        <?php else: ?>
            <button id="createStaffBtn" onclick="openCreateStaffModal()" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded">
                Create Staff
            </button>
        <?php endif; ?>
    </div>

    <?php if ($errors): ?>
        <div class="bg-red-100 border border-red-300 text-red-800 px-4 py-3 rounded mb-4">
            <?php echo htmlspecialchars($errors); ?>
        </div>
    <?php endif; ?>
    <?php if ($success): ?>
        <div class="bg-green-100 border border-green-300 text-green-800 px-4 py-3 rounded mb-4">
            <?php echo htmlspecialchars($success); ?>
        </div>
    <?php endif; ?>

    <!-- Messages from create_staff.php -->
    <?php if ($create_staff_error): ?>
      <div class="bg-red-100 border border-red-300 text-red-800 px-4 py-3 rounded mb-4">
        <?php echo htmlspecialchars($create_staff_error); ?>
      </div>
    <?php endif; ?>
    <?php if ($create_staff_success): ?>
      <div class="bg-green-100 border border-green-300 text-green-800 px-4 py-3 rounded mb-4">
        <?php echo htmlspecialchars($create_staff_success); ?>
      </div>
    <?php endif; ?>

    <form method="GET" class="mb-4 grid grid-cols-1 md:grid-cols-4 gap-3">
        <input type="text" name="search" value="<?php echo htmlspecialchars($search); ?>" placeholder="Search name / username / email" class="px-3 py-2 border rounded">
        <select name="role" class="px-3 py-2 border rounded">
            <option value="all">All Roles</option>
            <?php foreach ($allowed_staff_roles as $rname): ?>
                <option value="<?php echo htmlspecialchars($rname); ?>" <?php echo $role_filter === $rname ? 'selected' : ''; ?>>
                    <?php echo htmlspecialchars(ucwords($rname)); ?>
                </option>
            <?php endforeach; ?>
        </select>
        <select name="status" class="px-3 py-2 border rounded">
            <option value="all">All Status</option>
            <option value="active"   <?php echo $status_filter === 'active' ? 'selected' : ''; ?>>Active</option>
            <option value="inactive" <?php echo $status_filter === 'inactive' ? 'selected' : ''; ?>>Inactive</option>
            <option value="rejected" <?php echo $status_filter === 'rejected' ? 'selected' : ''; ?>>Rejected</option>
        </select>
        <div class="flex items-center">
            <button class="px-4 py-2 bg-gray-200 rounded">Filter</button>
            <a href="manage_staff.php" class="ml-2 px-4 py-2 bg-gray-100 rounded">Reset</a>
        </div>
    </form>

    <div class="bg-white rounded shadow overflow-x-auto">
        <table class="w-full text-sm">
            <thead class="bg-gray-50">
                <tr>
                    <th class="text-left px-4 py-3">Name</th>
                    <th class="text-left px-4 py-3">Username</th>
                    <th class="text-left px-4 py-3">Email</th>
                    <th class="text-left px-4 py-3">Contact</th>
                    <th class="text-left px-4 py-3">Role</th>
                    <th class="text-left px-4 py-3">Market</th>
                    <th class="text-left px-4 py-3">Status</th>
                    <th class="text-left px-4 py-3">Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($staff)): ?>
                    <tr><td colspan="8" class="p-6 text-center text-gray-500">No staff accounts found.</td></tr>
                <?php else: foreach ($staff as $row): ?>
                    <?php
                        $marketName = '';
                        if (!empty($row['market_id'])) {
                            try {
                                $m = $db->fetch("SELECT market_name FROM markets WHERE market_id = ? LIMIT 1", [(int)$row['market_id']]);
                                $marketName = $m['market_name'] ?? '';
                            } catch (Throwable $e) {
                                $marketName = '';
                            }
                        }
                    ?>
                    <tr class="hover:bg-gray-50">
                        <td class="px-4 py-3"><?php echo htmlspecialchars($row['full_name'] ?? ''); ?></td>
                        <td class="px-4 py-3"><?php echo htmlspecialchars($row['username'] ?? ''); ?></td>
                        <td class="px-4 py-3"><?php echo htmlspecialchars($row['email'] ?? ''); ?></td>
                        <td class="px-4 py-3"><?php echo htmlspecialchars($row['contact_number'] ?? ''); ?></td>
                        <td class="px-4 py-3"><?php echo htmlspecialchars($row['role_name'] ?? ''); ?></td>
                        <td class="px-4 py-3"><?php echo htmlspecialchars($marketName); ?></td>
                        <td class="px-4 py-3"><?php echo htmlspecialchars($row['status'] ?? ''); ?></td>
                        <td class="px-4 py-3">
                            <div class="flex gap-2">
                                <button
                                  onclick="openChangeStatusModal(<?php echo (int)$row['user_id']; ?>,'<?php echo htmlspecialchars(addslashes($row['full_name'] ?? '')); ?>','<?php echo htmlspecialchars($row['status'] ?? ''); ?>')"
                                  class="px-2 py-1 bg-yellow-500 text-white rounded text-xs">
                                  Status
                                </button>
                                <button
                                  onclick="openResetPasswordModal(<?php echo (int)$row['user_id']; ?>,'<?php echo htmlspecialchars(addslashes($row['full_name'] ?? '')); ?>')"
                                  class="px-2 py-1 bg-red-500 text-white rounded text-xs">
                                  Reset PW
                                </button>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; endif; ?>
            </tbody>
        </table>
    </div>
</div>

<!-- Create Staff Modal -->
<div id="createStaffModal" data-backdrop-close="false" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
  <div class="bg-white rounded-lg w-full max-w-lg p-6">
    <div class="flex items-center justify-between mb-4">
      <h3 class="text-lg font-semibold">Create Staff Account</h3>
      <button type="button" onclick="closeCreateStaffModal()" class="text-gray-600">✕</button>
    </div>

    <!-- enctype required for file upload -->
    <form id="createStaffForm" method="POST" action="create_staff.php" class="space-y-3" enctype="multipart/form-data">
      <?php echo csrf_field(); ?>
      <input type="hidden" name="from_page" value="<?php echo htmlspecialchars($_SERVER['REQUEST_URI'] ?? 'manage_staff.php'); ?>">

      <div>
        <label class="block text-sm mb-1">Username *</label>
        <div class="flex items-center gap-3">
          <input id="create_username" name="username" required class="w-full px-3 py-2 border rounded" />
          <span id="status_create_username" class="availability-status" data-status-for="create_username"></span>
        </div>
      </div>

      <div>
        <label class="block text-sm mb-1">Password *</label>
        <input type="password" name="password" required class="w-full px-3 py-2 border rounded" />
      </div>

      <div>
        <label class="block text-sm mb-1">Full name *</label>
        <input name="full_name" required class="w-full px-3 py-2 border rounded" />
      </div>

      <div>
        <label class="block text-sm mb-1">Email</label>
        <div class="flex items-center gap-3">
          <input id="create_email" name="email" type="email" class="w-full px-3 py-2 border rounded" />
          <span id="status_create_email" class="availability-status" data-status-for="create_email"></span>
        </div>
      </div>

      <div>
        <label class="block text-sm mb-1">Contact number</label>
        <div class="flex items-center gap-3">
          <input id="create_contact_number" name="contact_number" class="w-full px-3 py-2 border rounded" placeholder="+639..." />
          <span id="status_create_contact_number" class="availability-status" data-status-for="create_contact_number"></span>
        </div>
      </div>

      <div>
        <label class="block text-sm mb-1">Role *</label>
        <select name="role" id="create_staff_role" required class="w-full px-3 py-2 border rounded">
          <option value="">Select role</option>
          <?php foreach ($allowed_staff_roles as $r): ?>
            <option value="<?php echo htmlspecialchars($r); ?>"><?php echo htmlspecialchars(ucfirst($r)); ?></option>
          <?php endforeach; ?>
        </select>
        <p id="roleHint" class="text-xs text-gray-500 mt-1">Inspector / Accountant require an ID upload for verification.</p>
      </div>

      <div>
        <label class="block text-sm mb-1">Market *</label>
        <select name="market_id" id="create_staff_market" required class="w-full px-3 py-2 border rounded">
          <option value="">Select market</option>
          <?php foreach ($managed_markets as $m): ?>
            <option value="<?php echo (int)$m['market_id']; ?>"><?php echo htmlspecialchars($m['market_name']); ?></option>
          <?php endforeach; ?>
        </select>
      </div>

      <!-- ID upload (required for inspector/accountant) -->
      <div id="idUploadRow" style="display:none;">
        <label class="block text-sm mb-1">ID Document (JPEG/PNG/PDF) * (max 5MB)</label>
        <input type="file" name="id_document" accept=".jpg,.jpeg,.png,.pdf" class="w-full" />
        <p class="text-xs text-gray-500 mt-1">This document will be submitted for super admin verification.</p>
      </div>

      <div class="flex justify-end gap-2 mt-4">
        <button type="button" onclick="closeCreateStaffModal()" class="px-4 py-2 bg-gray-200 rounded">Cancel</button>
        <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded">Create</button>
      </div>
    </form>
  </div>
</div>

<!-- Change Status Modal -->
<div id="changeStatusModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
  <div class="bg-white rounded-lg w-full max-w-md p-6">
    <h3 class="text-lg font-semibold mb-4">Change Account Status</h3>
    <form method="POST" action="manage_staff.php">
      <?php echo csrf_field(); ?>
      <input type="hidden" name="action" value="change_status">
      <input type="hidden" name="user_id" id="change_status_user_id">
      <div class="mb-3"><p id="change_status_user_label" class="font-medium"></p></div>
      <div class="mb-4">
        <label class="block text-sm mb-1">New Status</label>
        <select name="status" id="change_status_select" class="w-full px-3 py-2 border rounded">
          <option value="active">Active</option>
          <option value="inactive">Inactive</option>
          <option value="pending">Pending</option>
          <option value="rejected">Rejected</option>
        </select>
      </div>
      <div class="flex justify-end gap-2">
        <button type="button" onclick="closeChangeStatusModal()" class="px-4 py-2 bg-gray-200 rounded">Cancel</button>
        <button type="submit" class="px-4 py-2 bg-yellow-500 text-white rounded">Save</button>
      </div>
    </form>
  </div>
</div>

<!-- Reset Password Modal -->
<div id="resetPasswordModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
  <div class="bg-white rounded-lg w-full max-w-md p-6">
    <h3 class="text-lg font-semibold mb-4">Reset Password</h3>
    <form method="POST" action="manage_staff.php">
      <?php echo csrf_field(); ?>
      <input type="hidden" name="action" value="reset_password">
      <input type="hidden" name="user_id" id="reset_password_user_id">
      <div class="mb-3"><p id="reset_password_user_label" class="font-medium"></p></div>
      <p class="text-sm text-gray-600 mb-4">
        A temporary password will be generated and sent to the user via SMS if a phone number exists; otherwise the user will be notified to contact you.
      </p>
      <div class="flex justify-end gap-2">
        <button type="button" onclick="closeResetPasswordModal()" class="px-4 py-2 bg-gray-200 rounded">Cancel</button>
        <button type="submit" class="px-4 py-2 bg-red-500 text-white rounded">Reset Password</button>
      </div>
    </form>
  </div>
</div>

<script>
function qs(id){return document.getElementById(id);}

function openChangeStatusModal(uid,label,current){
  qs('change_status_user_id').value = uid;
  qs('change_status_user_label').textContent = label + ' (current: ' + current + ')';
  qs('changeStatusModal').classList.remove('hidden');
  qs('change_status_select').focus();
}
function closeChangeStatusModal(){ qs('changeStatusModal').classList.add('hidden'); }

function openResetPasswordModal(uid,label){
  qs('reset_password_user_id').value = uid;
  qs('reset_password_user_label').textContent = label;
  qs('resetPasswordModal').classList.remove('hidden');
}
function closeResetPasswordModal(){ qs('resetPasswordModal').classList.add('hidden'); }

/* Create staff modal logic: do NOT reset form on close to avoid losing input.
   Handles role-based ID upload visibility and pre-selects market if exactly one available.
   Includes live availability checks for username/email/contact using check_availability.php
*/
(function(){
  const modal = qs('createStaffModal');
  const form = qs('createStaffForm');
  const roleSel = qs('create_staff_role');
  const idRow = qs('idUploadRow');
  const marketSel = qs('create_staff_market');

  // Pre-select market if manager has exactly one managed market
  try {
    if (marketSel && marketSel.options.length === 2) { // empty option + one market option
      marketSel.selectedIndex = 1;
    }
  } catch(e){}

  window.openCreateStaffModal = function(){
    if (!modal) return;
    modal.classList.remove('hidden');
    // Do not reset form here (preserve user input)
    const first = form.querySelector('input,select,textarea,button');
    if (first && typeof first.focus === 'function') first.focus();
  };

  window.closeCreateStaffModal = function(){
    if (!modal) return;
    modal.classList.add('hidden');
    // Keep form values to avoid accidental data loss.
  };

  function updateIdRow(){
    const v = roleSel ? roleSel.value : '';
    if (v === 'inspector' || v === 'accountant') {
      idRow.style.display = 'block';
    } else {
      idRow.style.display = 'none';
    }
  }
  if (roleSel) {
    roleSel.addEventListener('change', updateIdRow);
    updateIdRow();
  }

  // Respect data-backdrop-close attribute: only close on backdrop if explicitly allowed
  document.addEventListener('click', function(e){
    if (!modal || modal.classList.contains('hidden')) return;
    if (e.target === modal) {
      if (modal.getAttribute('data-backdrop-close') === 'true') {
        window.closeCreateStaffModal();
      }
    }
  });

  // Allow Escape to close
  document.addEventListener('keydown', function(e){
    if (e.key === 'Escape') {
      if (!modal.classList.contains('hidden')) window.closeCreateStaffModal();
    }
  });

  // ---------------- Live availability checks ----------------
  const ENDPOINT = 'check_availability.php'; // relative path (file should be in same folder)

  const debounce = (fn, wait) => {
    let t = null;
    return (...args) => {
      if (t) clearTimeout(t);
      t = setTimeout(()=> fn(...args), wait);
    };
  };

  const showStatus = (el, text, state) => {
    el.classList.remove('av-checked','av-checking','av-available','av-taken','av-error','animate-pulse');
    el.textContent = text || '';
    el.classList.add('av-checked');
    if (state === 'checking') el.classList.add('av-checking','animate-pulse');
    else if (state === 'available') el.classList.add('av-available');
    else if (state === 'taken') el.classList.add('av-taken');
    else el.classList.add('av-error');
  };

  async function doCheck(field, value, statusEl){
    if (!value || value.trim() === '') { showStatus(statusEl,'',''); return; }
    showStatus(statusEl, 'Checking…', 'checking');
    try {
      const url = `${ENDPOINT}?field=${encodeURIComponent(field)}&value=${encodeURIComponent(value)}`;
      const res = await fetch(url, { method: 'GET', credentials: 'same-origin' });
      if (!res.ok) { showStatus(statusEl,'Error','error'); return; }
      const js = await res.json();
      if (!js || !js.ok) { showStatus(statusEl,'Error','error'); return; }
      if (js.available) showStatus(statusEl,'Available','available'); else showStatus(statusEl,'Taken','taken');
    } catch (err) {
      console.error('availability check failed', err);
      showStatus(statusEl,'Error','error');
    }
  }

  const attachAvailability = (inputId, fieldName, statusId) => {
    const input = qs(inputId);
    const status = qs(statusId);
    if (!input || !status) return;
    const deb = debounce((v)=> doCheck(fieldName, v, status), 450);
    input.addEventListener('input', (e) => deb(e.target.value));
    input.addEventListener('blur', (e)=> deb(e.target.value));
    // initial check if prefilled
    if (input.value && input.value.trim() !== '') setTimeout(()=> deb(input.value), 200);
  };

  attachAvailability('create_username','username','status_create_username');
  attachAvailability('create_email','email','status_create_email');
  attachAvailability('create_contact_number','contact_number','status_create_contact_number');

})();
</script>

<?php include 'includes/footer.php'; ?>