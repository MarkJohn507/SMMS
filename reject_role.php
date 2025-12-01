<?php
/**
 * reject_role.php
 * Rejects a role request (pending / under_review / provisional_active) with a reason.
 * Sets status='rejected', fills resubmission_reason (if column exists).
 */

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/csrf.php';
require_once 'includes/audit.php';
require_once 'includes/helpers.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') redirect('admin_pending_requests.php');
if (!isLoggedIn() || !isAdmin()) redirect('login.php?timeout=1');
if (!csrf_validate_request()) redirect('admin_pending_requests.php?error=csrf');

$user_role_id = (int)($_POST['user_role_id'] ?? 0);
$reason_raw   = trim((string)($_POST['reason'] ?? ''));
$reason       = $reason_raw === '' ? null : mb_substr($reason_raw, 0, 2000);

if ($user_role_id <= 0) redirect('admin_pending_requests.php?error=invalid');
if ($reason === null) {
    $_SESSION['last_reject_error'] = 'Please provide a rejection reason.';
    redirect('admin_pending_requests.php?error=1');
}

try {
    $ur = $db->fetch(
        "SELECT ur.user_role_id, ur.user_id, ur.role_id, ur.status,
                u.email, u.full_name, r.name AS role_name
         FROM user_roles ur
         JOIN users u ON ur.user_id = u.user_id
         JOIN roles r ON ur.role_id = r.role_id
         WHERE ur.user_role_id = ? LIMIT 1",
        [$user_role_id]
    );
    if (!$ur) throw new RuntimeException('Role request not found');

    $currentStatus = strtolower(trim((string)$ur['status']));
    if (!in_array($currentStatus, ['pending','under_review','provisional_active'], true)) {
        throw new RuntimeException('Cannot reject: status is not pending / under_review / provisional_active');
    }

    $hasResubmissionReason = false;
    try {
        $c = $db->fetch("SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='user_roles' AND COLUMN_NAME='resubmission_reason' LIMIT 1");
        $hasResubmissionReason = !empty($c);
    } catch (Throwable $e) {}

    $appendNote = "\n[Rejected by admin " . ($_SESSION['user_id'] ?? '0') . " at " . date('Y-m-d H:i:s') . "] Reason: " . $reason;

    if ($hasResubmissionReason) {
        $db->query(
            "UPDATE user_roles
             SET status='rejected',
                 admin_notes = CONCAT(COALESCE(admin_notes,''), ?),
                 resubmission_reason = ?,
                 reviewed_by = ?,
                 reviewed_at = NOW()
             WHERE user_role_id = ?",
            [$appendNote, $reason, $_SESSION['user_id'], $user_role_id]
        );
    } else {
        $db->query(
            "UPDATE user_roles
             SET status='rejected',
                 admin_notes = CONCAT(COALESCE(admin_notes,''), ?),
                 reviewed_by = ?,
                 reviewed_at = NOW()
             WHERE user_role_id = ?",
            [$appendNote, $_SESSION['user_id'], $user_role_id]
        );
    }

    logAudit($db, $_SESSION['user_id'], 'Rejected Role Request', 'user_roles', $user_role_id, $currentStatus, 'rejected');

    // Notification
    try {
        $msg = "Your role request for '" . ($ur['role_name'] ?? 'requested role') . "' was rejected. Reason: " . $reason;
        $db->query("INSERT INTO notifications (user_id, title, message, type, category, created_at)
                    VALUES (?, 'Role Request Rejected', ?, 'danger', 'role_request', NOW())",
                   [$ur['user_id'], $msg]);
    } catch (Throwable $e) { error_log("reject_role notif failed: ".$e->getMessage()); }

    // Email
    if (!empty($ur['email']) && function_exists('sendMail')) {
        try {
            $subject = APP_NAME . " — Role request rejected";
            $html  = "<p>Hi " . htmlspecialchars($ur['full_name'] ?? '') . ",</p>";
            $html .= "<p>Your request for the role <strong>" . htmlspecialchars($ur['role_name'] ?? 'requested role') . "</strong> was rejected.</p>";
            $html .= "<p><strong>Reason:</strong> " . nl2br(htmlspecialchars($reason)) . "</p>";
            $html .= "<p>Please log in to correct and resubmit required documents.</p>";
            sendMail($ur['email'], $subject, $html);
        } catch (Throwable $e) { error_log("reject_role email failed: ".$e->getMessage()); }
    }

    redirect('admin_pending_requests.php?msg=rejected');
} catch (Throwable $e) {
    error_log("reject_role error: " . $e->getMessage());
    $_SESSION['last_reject_error'] = substr($e->getMessage(), 0, 250);
    redirect('admin_pending_requests.php?error=1');
}