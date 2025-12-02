<?php
/**
 * manage_users_action.php
 *
 * Handles admin actions from manage_users.php.
 * Currently supports:
 * - action=set_status (Activate/Deactivate account)
 *
 * Security:
 * - CSRF validation
 * - Only super_admins may toggle account status
 * - Cannot change status of a super_admin account
 * - Uses transaction and audit log
 */

require_once 'config.php';
require_once 'includes/helpers.php';
require_once 'includes/csrf.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

function redirect_back($user_id, $ok = '', $err = '') {
    if ($ok !== '') $_SESSION['manage_user_msg'] = $ok;
    if ($err !== '') $_SESSION['manage_user_error'] = $err;
    $uid = (int)$user_id;
    header("Location: manage_users.php?user_id={$uid}");
    exit;
}

function currentUserIsSuperAdmin($db): bool {
    $uid = $_SESSION['user_id'] ?? null;
    if (!$uid) return false;
    // Prefer role helper if available
    try {
        if (function_exists('userIsInRole') && userIsInRole($db, (int)$uid, 'super_admin')) return true;
    } catch (Throwable $e) {}
    // Fallback to session roles
    $roles = array_map('strtolower', (array)($_SESSION['roles'] ?? []));
    return in_array('super_admin', $roles, true);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo "Method Not Allowed";
    exit;
}

if (!csrf_validate_request()) {
    redirect_back($_POST['user_id'] ?? 0, '', 'Invalid CSRF token.');
}

if (!isLoggedIn()) {
    header('Location: login.php?timeout=1');
    exit;
}

// Only super admins may toggle account status
if (!currentUserIsSuperAdmin($db)) {
    redirect_back($_POST['user_id'] ?? 0, '', 'Permission denied. Only Super Admins can change account status.');
}

$action = isset($_POST['action']) ? strtolower(trim((string)$_POST['action'])) : '';
$target_user_id = isset($_POST['user_id']) ? (int)$_POST['user_id'] : 0;

if ($target_user_id <= 0) {
    redirect_back(0, '', 'Invalid user.');
}

try {
    $user = $db->fetch("SELECT * FROM users WHERE user_id=? LIMIT 1", [$target_user_id]);
    if (!$user) {
        redirect_back($target_user_id, '', 'User not found.');
    }
} catch (Throwable $e) {
    error_log("manage_users_action load user failed: ".$e->getMessage());
    redirect_back($target_user_id, '', 'Server error while loading user.');
}

// Helper to determine if target user is a super_admin (protect)
function targetIsSuperAdmin($db, array $user): bool {
    // Check roles table
    try {
        $row = $db->fetch("
            SELECT 1
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.role_id
            WHERE ur.user_id = ? AND LOWER(r.name) = 'super_admin'
            LIMIT 1
        ", [$user['user_id']]);
        if ($row) return true;
    } catch (Throwable $e) {}
    // Check users.role column if it exists
    try {
        $col = $db->fetch("SHOW COLUMNS FROM users LIKE 'role'");
        if ($col && !empty($user['role']) && strtolower((string)$user['role']) === 'super_admin') return true;
    } catch (Throwable $e) {}
    return false;
}

switch ($action) {
    case 'set_status': {
        $new_status_raw = strtolower(trim((string)($_POST['status'] ?? '')));
        $new_status = in_array($new_status_raw, ['active','inactive'], true) ? $new_status_raw : '';

        if ($new_status === '') {
            redirect_back($target_user_id, '', 'Invalid status value.');
        }

        // Protect super_admin accounts
        if (targetIsSuperAdmin($db, $user)) {
            redirect_back($target_user_id, '', 'Cannot change status of a Super Admin account.');
        }

        try {
            $db->beginTransaction();

            // Update users.status
            $ok = $db->query("UPDATE users SET status = ?, updated_at = NOW() WHERE user_id = ?", [$new_status, $target_user_id]);
            if (!$ok) {
                $db->rollBack();
                redirect_back($target_user_id, '', 'Failed to update account status.');
            }

            // If deactivating, optionally revoke active sessions for the user
            if ($new_status === 'inactive') {
                try {
                    // If you have a sessions table similar to other code paths
                    $db->query("DELETE FROM sessions WHERE user_id = ?", [$target_user_id]);
                } catch (Throwable $e) {
                    // Non-fatal; continue
                    error_log("manage_users_action revoke sessions failed for user {$target_user_id}: ".$e->getMessage());
                }
            }

            $db->commit();

            // Audit
            try {
                $admin_id = (int)($_SESSION['user_id'] ?? 0);
                logAudit($db, $admin_id, 'User Status Changed', 'users', $target_user_id, null, json_encode([
                    'old_status' => $user['status'] ?? null,
                    'new_status' => $new_status,
                ]));
            } catch (Throwable $e) {}

            // Notify user (optional)
            try {
                if (function_exists('createNotification')) {
                    $title = $new_status === 'active' ? 'Account Activated' : 'Account Deactivated';
                    $msg   = $new_status === 'active'
                        ? 'Your account has been activated by an administrator.'
                        : 'Your account has been deactivated by an administrator. Please contact support if this is unexpected.';
                    createNotification($db, $target_user_id, $title, $msg, 'info', 'user', $target_user_id, 'users');
                }
            } catch (Throwable $e) {}

            $okMsg = $new_status === 'active' ? 'Account activated.' : 'Account deactivated.';
            redirect_back($target_user_id, $okMsg, '');
        } catch (Throwable $e) {
            try { $db->rollBack(); } catch (Throwable $e2) {}
            error_log("manage_users_action set_status failed: ".$e->getMessage());
            redirect_back($target_user_id, '', 'Server error while updating status.');
        }

        break;
    }

    default:
        redirect_back($target_user_id, '', 'Unknown action.');
}