<?php
// approve_role_document.php
// Approves a document (user_role_documents or identity_documents) and auto-activates the
// corresponding user_roles row when role requirements are met.
//
// Notes:
// - Expects $db wrapper with query/fetch/fetchAll used by the app.
// - Expects an admin session user id in $_SESSION['user_id'].
// - Accepts POST: user_role_document_id (int), identity_id (int), user_role_id (optional int).
// - After approval, will try to auto-activate the role according to ROLE_DOC_RULES,
//   using the "either id or permit" rule for inspector/accountant.

require_once 'config.php';
require_once 'includes/csrf.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
requireAdmin();

$redirect = $_SERVER['HTTP_REFERER'] ?? '/admin_pending_requests.php';

// Grab CSRF token (common names), support csrf_validate signatures
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

$roleDocId  = isset($_POST['user_role_document_id']) ? (int)$_POST['user_role_document_id'] : 0;
$identityId = isset($_POST['identity_id']) ? (int)$_POST['identity_id'] : 0;
$userRoleIdPosted = isset($_POST['user_role_id']) ? (int)$_POST['user_role_id'] : 0;
$adminId = $_SESSION['user_id'] ?? null;

if ($roleDocId <= 0 && $identityId <= 0) {
    $_SESSION['manage_user_error'] = 'No document id provided.';
    header('Location: ' . $redirect);
    exit;
}

// Normalize doc types across tables
function normalize_doc_type(string $raw): string {
    $t = strtolower(trim($raw));
    if ($t === '') return $t;
    $map = [
        'government_id'   => 'id',
        'gov_id'          => 'id',
        'government id'   => 'id',
        'id'              => 'id',
        'permit'          => 'permit',
        'business_permit' => 'permit',
        'business permit' => 'permit',
        'mayor_permit'    => 'permit',
        'business-permit' => 'permit',
        'other'           => 'other',
    ];
    return $map[$t] ?? $t;
}

// Role doc rules (keep in sync with UI)
$ROLE_DOC_RULES = [
    'super_admin'    => ['required'=>[],               'optional'=>[]],
    'market_manager' => ['required'=>['permit'],       'optional'=>['id']],
    'vendor'         => ['required'=>['permit','id'],  'optional'=>[]],
    // NOTE: inspector/accountant follow "either id OR permit" requirement per request
    'inspector'      => ['required'=>['id'],           'optional'=>['permit']],
    'accountant'     => ['required'=>['id'],           'optional'=>['permit']],
];

// Helper to record an audit but don't fail if audit_log() missing
function safe_audit($adminId, $message) {
    if (function_exists('audit_log')) {
        try { audit_log($adminId, $message); } catch (Throwable $e) { error_log("audit_log failed: ".$e->getMessage()); }
    } else {
        error_log("AUDIT admin={$adminId}: ".$message);
    }
}

/**
 * Determine whether the role's document requirements are satisfied and, if so, set user_roles.status = 'active'.
 * Special rule: for inspector/accountant, either approved 'id' or approved 'permit' is sufficient.
 *
 * @param object $db DB wrapper
 * @param int $user_role_id
 * @param int $adminId
 * @return bool true if role was activated, false otherwise
 */
function tryActivateRoleIfDocsComplete($db, int $user_role_id, ?int $adminId): bool {
    global $ROLE_DOC_RULES;

    // Fetch role info and user id
    $roleRow = $db->fetch(
        "SELECT ur.user_role_id, ur.user_id, r.name AS role_name, ur.status AS role_status
         FROM user_roles ur
         JOIN roles r ON ur.role_id = r.role_id
         WHERE ur.user_role_id = ? LIMIT 1",
        [$user_role_id]
    );
    if (!$roleRow) return false;

    $userId = (int)$roleRow['user_id'];
    $roleKey = strtolower(trim((string)$roleRow['role_name'] ?? ''));

    // If already active, nothing to do
    if (strtolower(trim((string)$roleRow['role_status'] ?? '')) === 'active') return true;

    // Build effective required set
    $docRule = $ROLE_DOC_RULES[$roleKey] ?? ['required'=>[], 'optional'=>[]];
    $required = array_map('strtolower', array_map('normalize_doc_type', (array)$docRule['required']));

    // Special-case inspector/accountant: requirement is "either id or permit" (if either approved -> active)
    if (in_array($roleKey, ['inspector','accountant'], true)) {
        // Check role-level documents for approved id/permit
        $rows = $db->fetchAll(
            "SELECT doc_type, status FROM user_role_documents WHERE user_role_id = ?",
            [$user_role_id]
        ) ?: [];
        foreach ($rows as $r) {
            $k = strtolower(normalize_doc_type((string)($r['doc_type'] ?? '')));
            $s = strtolower(trim((string)($r['status'] ?? 'pending')));
            if (($k === 'id' || $k === 'permit') && $s === 'approved') {
                $db->query("UPDATE user_roles SET status = 'active' WHERE user_role_id = ?", [$user_role_id]);
                safe_audit($adminId, "Auto-activated role {$user_role_id} (found approved {$k} in user_role_documents)");
                return true;
            }
        }
        // Check identity_documents fallback (user-level)
        $idrows = $db->fetchAll(
            "SELECT doc_type, status FROM identity_documents WHERE user_id = ?",
            [$userId]
        ) ?: [];
        foreach ($idrows as $ir) {
            $k = strtolower(normalize_doc_type((string)($ir['doc_type'] ?? '')));
            $s = strtolower(trim((string)($ir['status'] ?? 'pending')));
            if (($k === 'id' || $k === 'permit') && $s === 'approved') {
                $db->query("UPDATE user_roles SET status = 'active' WHERE user_role_id = ?", [$user_role_id]);
                safe_audit($adminId, "Auto-activated role {$user_role_id} (found approved {$k} in identity_documents)");
                return true;
            }
        }
        return false;
    }

    // For other roles: require all required types to be approved (consider role-level first, then identity fallback)
    $docMap = [];

    // role-level docs
    $rows = $db->fetchAll("SELECT doc_type, status FROM user_role_documents WHERE user_role_id = ?", [$user_role_id]) ?: [];
    foreach ($rows as $r) {
        $k = strtolower(normalize_doc_type((string)($r['doc_type'] ?? '')));
        $s = strtolower(trim((string)($r['status'] ?? 'pending')));
        if ($k !== '') $docMap[$k] = $s;
    }

    // identity_documents fallback for the user
    $idrows = $db->fetchAll("SELECT doc_type, status FROM identity_documents WHERE user_id = ? ORDER BY uploaded_at DESC", [$userId]) ?: [];
    foreach ($idrows as $ir) {
        $k = strtolower(normalize_doc_type((string)($ir['doc_type'] ?? '')));
        if ($k === '') continue;
        if (!isset($docMap[$k])) {
            $docMap[$k] = strtolower(trim((string)($ir['status'] ?? 'pending')));
        }
    }

    // Check required types
    foreach ($required as $req) {
        if (!isset($docMap[$req]) || strtolower($docMap[$req]) !== 'approved') {
            return false; // still missing or not approved
        }
    }

    // All required satisfied -> activate
    $db->query("UPDATE user_roles SET status = 'active' WHERE user_role_id = ?", [$user_role_id]);
    safe_audit($adminId, "Auto-activated role {$user_role_id} because all required documents are approved");
    return true;
}

// Start approval flow
try {
    // Approve role-level doc if provided
    if ($roleDocId > 0) {
        $db->query(
            "UPDATE user_role_documents
             SET status = 'approved',
                 reviewed_at = NOW(),
                 reviewed_by = ?
             WHERE user_role_document_id = ?
             LIMIT 1",
            [$adminId, $roleDocId]
        );

        // verify
        $row = $db->fetch("SELECT user_role_id, status FROM user_role_documents WHERE user_role_document_id = ? LIMIT 1", [$roleDocId]);
        if (!$row || strtolower(trim((string)$row['status'])) !== 'approved') {
            throw new Exception("Failed to update user_role_documents id={$roleDocId}");
        }

        safe_audit($adminId, "Approved user_role_document {$roleDocId}");
        // Determine role id to check for activation
        $user_role_id_to_check = $userRoleIdPosted ?: (int)($row['user_role_id'] ?? 0);
        if ($user_role_id_to_check > 0) {
            tryActivateRoleIfDocsComplete($db, $user_role_id_to_check, $adminId);
        }

        $_SESSION['manage_user_msg'] = 'Document approved.';
        header('Location: ' . $redirect);
        exit;
    }

    // Approve identity_documents row if provided (fallback)
    if ($identityId > 0) {
        // Try to update extras if present
        try {
            $db->query(
                "UPDATE identity_documents
                 SET status = 'approved',
                     reviewed_at = NOW(),
                     reviewed_by = ?
                 WHERE identity_id = ?
                 LIMIT 1",
                [$adminId, $identityId]
            );
        } catch (Throwable $e) {
            // If reviewed_at/reviewed_by don't exist, ignore and do minimal update
            error_log("approve_role_document: identity_documents rich update failed: " . $e->getMessage());
        }

        // minimal update
        $db->query("UPDATE identity_documents SET status = 'approved' WHERE identity_id = ? LIMIT 1", [$identityId]);

        // verify
        $r = $db->fetch("SELECT user_id, doc_type, status FROM identity_documents WHERE identity_id = ? LIMIT 1", [$identityId]);
        if (!$r || strtolower(trim((string)$r['status'])) !== 'approved') {
            throw new Exception("Failed to update identity_documents id={$identityId}");
        }

        safe_audit($adminId, "Approved identity_document {$identityId}");

        // If UI provided user_role_id, use that. Otherwise attempt to find any pending role for this user that should be checked.
        $user_role_id_to_check = $userRoleIdPosted ?: 0;
        if ($user_role_id_to_check <= 0) {
            // Attempt to find a user_roles row for the user that is not active (pending/under_review)
            $possible = $db->fetch("SELECT user_role_id FROM user_roles WHERE user_id = ? AND status != 'active' ORDER BY user_role_id DESC LIMIT 1", [(int)$r['user_id']]);
            if ($possible && !empty($possible['user_role_id'])) $user_role_id_to_check = (int)$possible['user_role_id'];
        }

        if ($user_role_id_to_check > 0) {
            tryActivateRoleIfDocsComplete($db, $user_role_id_to_check, $adminId);
        }

        $_SESSION['manage_user_msg'] = 'Document approved.';
        header('Location: ' . $redirect);
        exit;
    }

} catch (Throwable $e) {
    error_log("approve_role_document error: " . $e->getMessage());
    $_SESSION['manage_user_error'] = 'An error occurred processing the request.';
    header('Location: ' . $redirect);
    exit;
}