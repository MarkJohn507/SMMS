<?php
/**
 * approve_role.php (document-level + provisional logic + minimal required docs)
 *
 * Document rule:
 *   - For super_admin / market_manager: required = ['permit'], optional = ['id']
 *   - For vendor: required = ['id'], optional = []
 *
 * Status resolution considering ONLY required docs:
 *   ANY required rejected -> 'rejected'
 *   ALL required approved -> 'active'
 *   SOME required approved (none rejected) -> 'provisional_active'
 *   ELSE (all required still pending) -> 'under_review'
 */

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/csrf.php';
require_once 'includes/audit.php';
require_once 'includes/helpers.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
requireAdmin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    redirect('admin_pending_requests.php');
}
if (!csrf_validate_request()) {
    redirect('admin_pending_requests.php?error=csrf');
}

$user_role_id = (int)($_POST['user_role_id'] ?? 0);
if ($user_role_id <= 0) {
    redirect('admin_pending_requests.php?error=invalid');
}

$ROLE_DOC_RULES = [
    'super_admin'    => ['required'=>['permit'],'optional'=>['id']],
    'market_manager' => ['required'=>['permit'],'optional'=>['id']],
    'vendor'         => ['required'=>['id'],    'optional'=>[]],
];

try {
    $ur = $db->fetch(
        "SELECT ur.user_role_id, ur.user_id, ur.role_id, ur.status, ur.admin_notes,
                u.email, u.full_name, u.role AS legacy_role, u.status AS account_status,
                r.name AS role_name
         FROM user_roles ur
         JOIN users u ON ur.user_id = u.user_id
         JOIN roles r ON ur.role_id = r.role_id
         WHERE ur.user_role_id = ? LIMIT 1",
        [$user_role_id]
    );
    if (!$ur) throw new RuntimeException("Role request not found");

    $currentStatus = strtolower(trim((string)$ur['status']));
    $allowedStatuses = ['pending','under_review','provisional_active','rejected'];
    if (!in_array($currentStatus, $allowedStatuses, true)) {
        throw new RuntimeException("Cannot approve from status '$currentStatus'");
    }

    $userId   = (int)$ur['user_id'];
    $roleNameKey = strtolower(trim((string)$ur['role_name']));
    $docRule = $ROLE_DOC_RULES[$roleNameKey] ?? ['required'=>['id','permit'],'optional'=>[]];
    $requiredDocs = $docRule['required'];

    // Load document statuses
    $docRows = $db->fetchAll(
        "SELECT doc_type, status FROM user_role_documents WHERE user_role_id = ?",
        [$user_role_id]
    ) ?: [];

    // Build map for required docs only
    $docMap = [];
    foreach ($docRows as $d) {
        $docMap[strtolower($d['doc_type'])] = strtolower($d['status']);
    }

    $anyRejectedRequired = false;
    $allRequiredApproved = true;
    $anyRequiredApproved = false;

    foreach ($requiredDocs as $req) {
        $st = $docMap[$req] ?? null;
        if ($st === 'rejected') $anyRejectedRequired = true;
        if ($st !== 'approved') $allRequiredApproved = false;
        if ($st === 'approved') $anyRequiredApproved = true;
    }

    if ($anyRejectedRequired) {
        $newStatus = 'rejected';
    } elseif ($allRequiredApproved) {
        $newStatus = 'active';
    } elseif ($anyRequiredApproved) {
        $newStatus = 'provisional_active';
    } else {
        $newStatus = 'under_review';
    }

    // Optional: force active override
    if (isset($_POST['force_active']) && $_POST['force_active'] === '1' && !$anyRejectedRequired) {
        $newStatus = 'active';
    }

    // Legacy mapping to users.role
    $legacy_map = [
        'vendor'          => 'vendor',
        'super_admin'     => 'admin',
        'municipal_admin' => 'admin',
        'issuer_admin'    => 'admin',
        'market_manager'  => 'admin',
        'accountant'      => 'admin',
        'inspector'       => 'admin',
        'admin'           => 'admin',
    ];
    $legacyRole = $legacy_map[$roleNameKey] ?? ($roleNameKey === 'vendor' ? 'vendor' : 'admin');

    $pdo = $db->pdo();
    $pdo->beginTransaction();

    $db->query(
        "UPDATE user_roles
         SET status = ?,
             admin_notes = CONCAT(COALESCE(admin_notes,''), ?),
             approved_by = ?,
             approved_at = NOW()
         WHERE user_role_id = ?",
        [
            $newStatus,
            "\n[Approval review ".date('Y-m-d H:i:s')." -> ".$newStatus."]",
            $_SESSION['user_id'],
            $user_role_id
        ]
    );

    if (in_array($newStatus, ['active','provisional_active'], true)) {
        $db->query(
            "UPDATE users SET status='active', role=?, updated_at=NOW()
             WHERE user_id=?",
            [$legacyRole, $userId]
        );
    }

    $elevated = ['super_admin','municipal_admin','issuer_admin','market_manager','accountant','inspector','admin'];
    if (in_array($roleNameKey,$elevated,true) && $newStatus === 'active') {
        try {
            $db->query(
               "UPDATE user_roles ur
                JOIN roles r ON ur.role_id = r.role_id
                SET ur.status='inactive'
                WHERE ur.user_id=? AND r.name='vendor' AND ur.status='active'",
               [$userId]
            );
        } catch (Throwable $e) {
            error_log("approve_role: vendor deactivate fail: ".$e->getMessage());
        }
    }

    // Invalidate sessions
    try { $db->query("DELETE FROM sessions WHERE user_id=?", [$userId]); } catch (Throwable $e) {}
    try {
        $col = $db->fetch("SHOW COLUMNS FROM users LIKE 'session_version'");
        if ($col) $db->query("UPDATE users SET session_version = session_version + 1 WHERE user_id=?", [$userId]);
    } catch (Throwable $e) {}

    logAudit($db, $_SESSION['user_id'], 'Approved Role Request', 'user_roles', $user_role_id, $currentStatus, $newStatus);

    // Notification
    try {
        $notifMsg = "Your role request for '" . ($ur['role_name'] ?? 'role') . "' was reviewed. Status: ".$newStatus.".";
        if ($newStatus === 'provisional_active') {
            $notifMsg .= " Provisional access granted — remaining documents must be approved.";
        } elseif ($newStatus === 'under_review') {
            $notifMsg .= " Required documents are still pending approval.";
        } elseif ($newStatus === 'rejected') {
            $notifMsg .= " Required document(s) were rejected — please resubmit.";
        } elseif ($newStatus === 'active') {
            $notifMsg .= " Full access granted.";
        }
        $db->query(
            "INSERT INTO notifications (user_id, title, message, type, category, created_at)
             VALUES (?, 'Role Approval Update', ?, 'info', 'role_request', NOW())",
            [$userId, $notifMsg]
        );
    } catch (Throwable $e) { error_log("approve_role notification fail: ".$e->getMessage()); }

    // Email
    if (!empty($ur['email']) && function_exists('sendMail')) {
        try {
            $subject = APP_NAME." — Role approval update";
            $html  = "<p>Hi ".htmlspecialchars($ur['full_name'] ?? '').",</p>";
            $html .= "<p>Your request for the <strong>".htmlspecialchars($ur['role_name'] ?? '')."</strong> role is now <strong>".htmlspecialchars($newStatus)."</strong>.</p>";
            sendMail($ur['email'], $subject, $html);
        } catch (Throwable $e) { error_log("approve_role email fail: ".$e->getMessage()); }
    }

    $pdo->commit();
    redirect('admin_pending_requests.php?msg=approved');
} catch (Throwable $e) {
    try { if (isset($pdo) && $pdo->inTransaction()) $pdo->rollBack(); } catch (Throwable $_) {}
    error_log("approve_role error: ".$e->getMessage());
    redirect('admin_pending_requests.php?error=1');
}