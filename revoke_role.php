<?php
/**
 * revoke_role.php
 *
 * Revokes an active / provisional_active / under_review role assignment.
 * Sets status='revoked' + appends admin note.
 * Optionally restores vendor role if no elevated role remains active.
 */

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/csrf.php';
require_once 'includes/helpers.php';
require_once 'includes/audit.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
requireAdmin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') redirect('admin_pending_requests.php');
if (!csrf_validate_request()) redirect('admin_pending_requests.php?error=csrf');

$user_role_id = (int)($_POST['user_role_id'] ?? 0);
$reason_raw   = trim((string)($_POST['reason'] ?? ''));
$reason       = $reason_raw === '' ? null : mb_substr($reason_raw, 0, 1000);

if ($user_role_id <= 0) redirect('admin_pending_requests.php?error=invalid');

$RESTORE_VENDOR = true;

try {
    $row = $db->fetch(
        "SELECT ur.user_role_id, ur.user_id, ur.status, ur.role_id,
                u.email, u.full_name,
                r.name AS role_name
         FROM user_roles ur
         JOIN users u ON ur.user_id = u.user_id
         JOIN roles r ON ur.role_id = r.role_id
         WHERE ur.user_role_id = ? LIMIT 1",
        [$user_role_id]
    );
    if (!$row) throw new RuntimeException('Role assignment not found.');

    $currentStatus = strtolower(trim((string)$row['status']));
    $allowed = ['active','provisional_active','under_review'];
    if (!in_array($currentStatus,$allowed,true)) {
        throw new RuntimeException("Role in status '$currentStatus' cannot be revoked.");
    }

    $appendNote = "\n[Revoked by admin " . ($_SESSION['user_id'] ?? '0') . " at " . date('Y-m-d H:i:s') . "]";
    if ($reason) $appendNote .= " Reason: ".$reason;

    $db->query(
        "UPDATE user_roles
         SET status='revoked',
             admin_notes = CONCAT(COALESCE(admin_notes,''), ?),
             reviewed_by = ?,
             reviewed_at = NOW()
         WHERE user_role_id = ?",
        [$appendNote, $_SESSION['user_id'], $user_role_id]
    );

    logAudit($db, $_SESSION['user_id'], 'Revoked Role', 'user_roles', $user_role_id, $currentStatus, 'revoked');

    // Notification
    try {
        $msg = "Your '" . ($row['role_name'] ?? 'role') . "' role was revoked." . ($reason ? " Reason: $reason" : "");
        $db->query("INSERT INTO notifications (user_id, title, message, type, category, created_at)
                    VALUES (?, 'Role Revoked', ?, 'danger', 'role_request', NOW())",
                   [$row['user_id'], $msg]);
    } catch (Throwable $e) { error_log("revoke_role notif failed: ".$e->getMessage()); }

    // Restore vendor if necessary
    if ($RESTORE_VENDOR) {
        try {
            $activeElevated = $db->fetch(
                "SELECT 1
                 FROM user_roles ur
                 JOIN roles r ON ur.role_id = r.role_id
                 WHERE ur.user_id = ?
                   AND ur.status = 'active'
                   AND LOWER(r.name) IN ('super_admin','municipal_admin','issuer_admin','market_manager','accountant','inspector','admin')
                 LIMIT 1",
                [$row['user_id']]
            );
            if (empty($activeElevated)) {
                $vendorRole = $db->fetch("SELECT role_id FROM roles WHERE LOWER(name)='vendor' LIMIT 1");
                if ($vendorRole) {
                    $vendorRoleId = (int)$vendorRole['role_id'];
                    $vendorExisting = $db->fetch("SELECT user_role_id, status FROM user_roles WHERE user_id=? AND role_id=? LIMIT 1",
                        [$row['user_id'],$vendorRoleId]);
                    if ($vendorExisting) {
                        if ($vendorExisting['status'] !== 'active') {
                            $db->query("UPDATE user_roles SET status='active', assigned_at=NOW() WHERE user_role_id=?",
                                [$vendorExisting['user_role_id']]);
                        }
                    } else {
                        $db->query("INSERT INTO user_roles (user_id, role_id, status, assigned_at)
                                    VALUES (?, ?, 'active', NOW())",
                                    [$row['user_id'],$vendorRoleId]);
                    }
                }
            }
        } catch (Throwable $e) { error_log("revoke_role vendor restore fail: ".$e->getMessage()); }
    }

    // Invalidate sessions (best-effort)
    try { $db->query("DELETE FROM sessions WHERE user_id=?", [$row['user_id']]); } catch (Throwable $e) {}
    try {
        $col = $db->fetch("SHOW COLUMNS FROM users LIKE 'session_version'");
        if ($col) $db->query("UPDATE users SET session_version = session_version + 1 WHERE user_id=?", [$row['user_id']]);
    } catch (Throwable $e) {}

    // Email (optional)
    if (!empty($row['email']) && function_exists('sendMail')) {
        try {
            $subject = APP_NAME . " — Role Revoked";
            $html  = "<p>Hi " . htmlspecialchars($row['full_name'] ?? '') . ",</p>";
            $html .= "<p>Your role <strong>" . htmlspecialchars($row['role_name'] ?? 'Role') . "</strong> has been revoked.</p>";
            if ($reason) $html .= "<p><strong>Reason:</strong> " . nl2br(htmlspecialchars($reason)) . "</p>";
            sendMail($row['email'], $subject, $html);
        } catch (Throwable $e) { error_log("revoke_role email failed: ".$e->getMessage()); }
    }

    redirect('admin_pending_requests.php?msg=revoked');
} catch (Throwable $e) {
    error_log("revoke_role error: " . $e->getMessage());
    redirect('admin_pending_requests.php?error=1');
}