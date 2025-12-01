<?php
// reject_role_document.php
// Reject a document and save a reason/admin note.
// Robust: safe CSRF handling, uses DB wrapper, and falls back if audit_log() missing.

require_once 'config.php';
require_once 'includes/csrf.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
if (session_status() !== PHP_SESSION_ACTIVE) session_start();
requireAdmin();

$redirect = $_SERVER['HTTP_REFERER'] ?? '/admin_pending_requests.php';

// CSRF token extraction and validation (supports different csrf_validate signatures)
$csrfToken = $_POST['csrf_token'] ?? $_POST['csrf'] ?? $_POST['_csrf'] ?? $_REQUEST['csrf_token'] ?? null;
$csrfOk = false;
try {
    $csrfOk = (bool) csrf_validate($csrfToken);
} catch (ArgumentCountError $e) {
    try {
        $csrfOk = (bool) csrf_validate($_POST);
    } catch (Throwable $e2) {
        $csrfOk = false;
    }
} catch (Throwable $e) {
    $csrfOk = false;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !$csrfOk) {
    $_SESSION['manage_user_error'] = 'Invalid request (CSRF).';
    header('Location: ' . $redirect);
    exit;
}

// reason required
$reason = trim((string)($_POST['reason'] ?? ''));
if ($reason === '') {
    $_SESSION['manage_user_error'] = 'Rejection reason is required.';
    header('Location: ' . $redirect);
    exit;
}

$roleDocId  = isset($_POST['user_role_document_id']) ? (int)$_POST['user_role_document_id'] : 0;
$identityId = isset($_POST['identity_id']) ? (int)$_POST['identity_id'] : 0;
$adminId    = $_SESSION['user_id'] ?? null;

if ($roleDocId <= 0 && $identityId <= 0) {
    $_SESSION['manage_user_error'] = 'No document id provided.';
    header('Location: ' . $redirect);
    exit;
}

try {
    $do_audit = function($adminId, $message) {
        if (function_exists('audit_log')) {
            try {
                audit_log($adminId, $message);
            } catch (Throwable $e) {
                error_log("audit_log() failed: " . $e->getMessage());
            }
        } else {
            error_log("AUDIT admin={$adminId}: {$message}");
        }
    };

    if ($roleDocId > 0) {
        $sql = "UPDATE user_role_documents
                SET status = 'rejected',
                    admin_notes = ?,
                    reviewed_at = NOW(),
                    reviewed_by = ?
                WHERE user_role_document_id = ?
                LIMIT 1";
        $db->query($sql, [$reason, $adminId, $roleDocId]);

        $row = $db->fetch("SELECT status FROM user_role_documents WHERE user_role_document_id = ? LIMIT 1", [$roleDocId]);
        if (!$row || strtolower(trim((string)$row['status'])) !== 'rejected') {
            throw new Exception("Failed to update role-level document (id={$roleDocId}).");
        }

        $do_audit($adminId, "Rejected user_role_document {$roleDocId}: {$reason}");
        $_SESSION['manage_user_msg'] = 'Document rejected.';
        header('Location: ' . $redirect);
        exit;
    }

    if ($identityId > 0) {
        // Try richer update
        try {
            $sql1 = "UPDATE identity_documents
                     SET status = 'rejected',
                         admin_notes = ?,
                         reviewed_at = NOW(),
                         reviewed_by = ?
                     WHERE identity_id = ?
                     LIMIT 1";
            $db->query($sql1, [$reason, $adminId, $identityId]);

            $r1 = $db->fetch("SELECT status FROM identity_documents WHERE identity_id = ? LIMIT 1", [$identityId]);
            if ($r1 && strtolower(trim((string)$r1['status'])) === 'rejected') {
                $do_audit($adminId, "Rejected identity_document {$identityId}: {$reason}");
                $_SESSION['manage_user_msg'] = 'Document rejected.';
                header('Location: ' . $redirect);
                exit;
            }
            // else fall through
        } catch (Throwable $e) {
            error_log("reject_role_document: identity_documents rich update failed: " . $e->getMessage());
        }

        // Minimal fallback
        $sql2 = "UPDATE identity_documents
                 SET status = 'rejected',
                     admin_notes = ?
                 WHERE identity_id = ?
                 LIMIT 1";
        $db->query($sql2, [$reason, $identityId]);

        $r2 = $db->fetch("SELECT status FROM identity_documents WHERE identity_id = ? LIMIT 1", [$identityId]);
        if (!$r2 || strtolower(trim((string)$r2['status'])) !== 'rejected') {
            throw new Exception("Failed to update identity document (id={$identityId}).");
        }

        $do_audit($adminId, "Rejected identity_document {$identityId} (fallback): {$reason}");
        $_SESSION['manage_user_msg'] = 'Document rejected.';
        header('Location: ' . $redirect);
        exit;
    }
} catch (Throwable $e) {
    error_log("reject_role_document error: " . $e->getMessage());
    $_SESSION['manage_user_error'] = 'An error occurred processing the request.';
    header('Location: ' . $redirect);
    exit;
}