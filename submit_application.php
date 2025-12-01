<?php
// submit_application.php
// Vendor submits a stall application, sets flash messages, and redirects back to browse_stalls.php
// so toaster messages display there (not in my_applications.php).

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/csrf.php';

if (file_exists(__DIR__ . '/includes/notifications.php')) {
    require_once __DIR__ . '/includes/notifications.php';
}

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

if (!isLoggedIn()) redirect('login.php?timeout=1');
requireVendor();

$user_id = (int)($_SESSION['user_id'] ?? 0);

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    redirect('browse_stalls.php');
}

// CSRF validation
if (!csrf_validate_request()) {
    $_SESSION['error_message'] = 'Invalid CSRF token.';
    redirect('browse_stalls.php');
}

// Required fields
$stall_id = (int)($_POST['stall_id'] ?? 0);
$business_name = sanitize($_POST['business_name'] ?? '');
$business_type = sanitize($_POST['business_type'] ?? '');
// optional preferred start date
$preferred_start_date_raw = trim($_POST['preferred_start_date'] ?? '');
$preferred_start_date = null;
if ($preferred_start_date_raw !== '') {
    $d = DateTime::createFromFormat('Y-m-d', $preferred_start_date_raw);
    if (!$d || $d->format('Y-m-d') !== $preferred_start_date_raw) {
        $_SESSION['error_message'] = 'Preferred start date is invalid. Use YYYY-MM-DD.';
        redirect('browse_stalls.php');
    }
    $today = new DateTime('today');
    if ($d < $today) {
        $_SESSION['error_message'] = 'Preferred start date cannot be in the past.';
        redirect('browse_stalls.php');
    }
    $preferred_start_date = $d->format('Y-m-d');
}

if ($stall_id <= 0 || empty($business_name) || empty($business_type)) {
    $_SESSION['error_message'] = 'Please provide all required fields.';
    redirect('browse_stalls.php');
}

// Ensure stall exists and is available
$stall = $db->fetch("SELECT * FROM stalls WHERE stall_id = ? LIMIT 1", [$stall_id]);
if (!$stall) {
    $_SESSION['error_message'] = 'Stall not found.';
    redirect('browse_stalls.php');
}
if (strtolower((string)$stall['status']) !== 'available') {
    $_SESSION['error_message'] = 'That stall is no longer available.';
    redirect('browse_stalls.php');
}

// Active lease guard
try {
    $existsLease = $db->fetch("SELECT lease_id FROM leases WHERE stall_id=? AND status='active' LIMIT 1", [$stall_id]);
    if ($existsLease) {
        $_SESSION['error_message'] = 'This stall already has an active lease.';
        redirect('browse_stalls.php');
    }
} catch (Throwable $e) {
    error_log("submit_application: active lease check failed: " . $e->getMessage());
}

// Duplicate application guard
try {
    $dup = $db->fetch("SELECT application_id, status FROM applications WHERE vendor_id=? AND stall_id=? AND status NOT IN ('cancelled','rejected') LIMIT 1", [$user_id, $stall_id]);
    if ($dup) {
        $_SESSION['error_message'] = 'You have already submitted an application for this stall.';
        redirect('browse_stalls.php');
    }
} catch (Throwable $e) {
    error_log("submit_application: duplicate application check failed: " . $e->getMessage());
}

// Block re-apply after terminated lease (optional cooldown)
try {
    $leaseColExists = function(string $col) use ($db): bool {
        try {
            return (bool)$db->fetch("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'leases' AND column_name = ? LIMIT 1", [$col]);
        } catch (Throwable $e) { return false; }
    };

    $hasTerminatedAt = $leaseColExists('terminated_at');
    $hasUpdatedAt    = $leaseColExists('updated_at');
    $hasEndDate      = $leaseColExists('lease_end_date');

    $cooldown = defined('REAPPLY_AFTER_TERMINATION_DAYS') ? max(0,(int)REAPPLY_AFTER_TERMINATION_DAYS) : 0;

    $parts = [];
    if ($hasTerminatedAt) $parts[] = "NULLIF(l.terminated_at,'0000-00-00')";
    if ($hasUpdatedAt)    $parts[] = "NULLIF(l.updated_at,'0000-00-00 00:00:00')";
    if ($hasEndDate)      $parts[] = "NULLIF(l.lease_end_date,'0000-00-00')";
    $termExpr = $parts ? ("DATE(COALESCE(" . implode(',', $parts) . "))") : "NULL";

    $orderBy = [];
    if ($hasUpdatedAt) $orderBy[] = "l.updated_at DESC";
    if ($hasEndDate)   $orderBy[] = "l.lease_end_date DESC";
    if (!$orderBy)     $orderBy[] = "l.lease_id DESC";
    $orderSql = implode(', ', $orderBy);

    $termRow = $db->fetch("
        SELECT {$termExpr} AS term_date
        FROM leases l
        WHERE l.vendor_id = ? AND l.stall_id = ? AND LOWER(TRIM(l.status)) = 'terminated'
        ORDER BY {$orderSql}
        LIMIT 1
    ", [$user_id, $stall_id]);

    if ($termRow) {
        if ($cooldown === 0) {
            http_response_code(403);
            $_SESSION['error_message'] = 'You cannot re-apply to this stall after your lease was terminated.';
            redirect('browse_stalls.php');
        } else {
            $term = $termRow['term_date'] ?? null;
            if (empty($term) || $term === '0000-00-00') {
                http_response_code(403);
                $_SESSION['error_message'] = 'You cannot re-apply to this stall yet (cooldown in effect).';
                redirect('browse_stalls.php');
            }
            $allowTs = strtotime($term . " +{$cooldown} days");
            if (time() < $allowTs) {
                http_response_code(403);
                $_SESSION['error_message'] = 'You cannot re-apply to this stall yet (cooldown in effect).';
                redirect('browse_stalls.php');
            }
        }
    }
} catch (Throwable $e) {
    error_log("submit_application: terminated lease re-apply enforcement failed: " . $e->getMessage());
}

// Vendor document verification
$has_verified_permit = false;
$has_verified_id = false;
try {
    $rows = $db->fetchAll("
       SELECT d.doc_type,d.status
       FROM user_role_documents d
       JOIN user_roles ur ON d.user_role_id=ur.user_role_id
       JOIN roles r ON ur.role_id=r.role_id
       WHERE ur.user_id=? AND r.name='vendor'
    ", [$user_id]) ?: [];
    foreach ($rows as $r) {
        $t = strtolower($r['doc_type'] ?? '');
        $s = strtolower($r['status'] ?? '');
        if (in_array($t, ['permit','business_permit'], true) && $s === 'approved') $has_verified_permit = true;
        if (in_array($t, ['id','government_id','gov_id'], true) && $s === 'approved') $has_verified_id = true;
    }
} catch (Throwable $e) {
    error_log("submit_application: vendor doc check failed: " . $e->getMessage());
}
if (!$has_verified_permit || !$has_verified_id) {
    $_SESSION['error_message'] = 'You must have an approved Permit and ID before applying.';
    redirect('browse_stalls.php');
}

// Prepare upload directories
$uploadDirBase = __DIR__ . '/uploads/applications';
if (!is_dir($uploadDirBase)) {
    if (!mkdir($uploadDirBase, 0755, true)) {
        error_log("submit_application: failed to create upload directory {$uploadDirBase}");
    }
}

// Allowed mime types & max size (5MB)
$allowed_mimes = [
    'application/pdf' => 'pdf',
    'image/jpeg' => 'jpg',
    'image/png' => 'png',
    'application/msword' => 'doc',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => 'docx'
];
$maxBytes = 5 * 1024 * 1024;

// Start DB transaction if available
$usingTx = false;
try {
    if (method_exists($db, 'beginTransaction')) {
        $db->beginTransaction();
        $usingTx = true;
    }
} catch (Throwable $e) {
    $usingTx = false;
}

// Insert application row (include preferred_start_date if column exists)
$app_id = null;
try {
    $colCheck = $db->fetch("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'applications' AND column_name = 'preferred_start_date' LIMIT 1");
    if ($colCheck) {
        $db->query("INSERT INTO applications (stall_id, vendor_id, business_name, business_type, business_permit, preferred_start_date, status, application_date) VALUES (?, ?, ?, ?, ?, ?, 'pending', NOW())", [
            $stall_id, $user_id, $business_name, $business_type, null, $preferred_start_date
        ]);
    } else {
        $db->query("INSERT INTO applications (stall_id, vendor_id, business_name, business_type, business_permit, status, application_date) VALUES (?, ?, ?, ?, ?, 'pending', NOW())", [
            $stall_id, $user_id, $business_name, $business_type, null
        ]);
    }
    $app_id = (int)$db->lastInsertId();
} catch (Throwable $e) {
    if ($usingTx && method_exists($db, 'rollBack')) $db->rollBack();
    error_log("submit_application: failed to insert application: " . $e->getMessage());
    $_SESSION['error_message'] = 'Failed to submit application. Please try again later.';
    redirect('browse_stalls.php');
}

// Create application upload dir
$appUploadDir = $uploadDirBase . "/app_{$app_id}";
if (!is_dir($appUploadDir)) {
    if (!mkdir($appUploadDir, 0755, true)) {
        error_log("submit_application: failed to create app upload dir {$appUploadDir}");
    }
}

// Utility to generate safe filename
function make_safe_filename($prefix, $ext) {
    $time = time();
    $rand = bin2hex(random_bytes(6));
    $ext = ltrim(strtolower($ext), '.');
    return "{$prefix}_{$time}_{$rand}." . preg_replace('/[^a-z0-9]+/i', '', $ext);
}

// Handle single business permit upload
$business_permit_path = null;
if (!empty($_FILES['business_permit']) && is_array($_FILES['business_permit']) && ($_FILES['business_permit']['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_OK) {
    $f = $_FILES['business_permit'];
    if ($f['size'] <= $maxBytes) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = finfo_file($finfo, $f['tmp_name']);
        finfo_close($finfo);
        if (isset($allowed_mimes[$mime])) {
            $ext = $allowed_mimes[$mime];
            $safeName = make_safe_filename('business_permit', $ext);
            $dest = $appUploadDir . '/' . $safeName;
            if (move_uploaded_file($f['tmp_name'], $dest)) {
                $business_permit_path = 'uploads/applications/app_' . $app_id . '/' . $safeName;
                try {
                    $db->query("UPDATE applications SET business_permit = ? WHERE application_id = ?", [$business_permit_path, $app_id]);
                } catch (Throwable $e) {
                    error_log("submit_application: failed to update business_permit path: " . $e->getMessage());
                }
            } else {
                error_log("submit_application: move_uploaded_file failed for business_permit");
            }
        } else {
            error_log("submit_application: business_permit unsupported mime: {$mime}");
        }
    } else {
        error_log("submit_application: business_permit too large ({$f['size']})");
    }
}

// Handle multiple additional documents (input name: additional_documents[])
$docFiles = $_FILES['additional_documents'] ?? null;
$docTypes = $_POST['document_types'] ?? [];
$docNames = $_POST['document_names'] ?? [];

if ($docFiles && is_array($docFiles['name'])) {
    $count = count($docFiles['name']);
    for ($i = 0; $i < $count; $i++) {
        if (($docFiles['error'][$i] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) continue;
        $tmp = $docFiles['tmp_name'][$i] ?? '';
        $orig = $docFiles['name'][$i] ?? '';
        if (!is_file($tmp)) continue;
        if (@filesize($tmp) > $maxBytes) continue;

        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $docMime = finfo_file($finfo, $tmp);
        finfo_close($finfo);
        if (!isset($allowed_mimes[$docMime])) continue;

        $ext = $allowed_mimes[$docMime];
        $safe = make_safe_filename('doc', $ext);
        $dest = $appUploadDir . '/' . $safe;

        if (move_uploaded_file($tmp, $dest)) {
            $file_path = 'uploads/applications/app_' . $app_id . '/' . $safe;
            $doc_type = sanitize($docTypes[$i] ?? '');
            $doc_name = sanitize($docNames[$i] ?? pathinfo($orig, PATHINFO_FILENAME));
            // Insert into application_documents if table exists
            try {
                $tableCheck = $db->fetch("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'application_documents' LIMIT 1");
                if ($tableCheck) {
                    $db->query("INSERT INTO application_documents (application_id, document_name, document_type, file_path, uploaded_at) VALUES (?, ?, ?, ?, NOW())", [
                        $app_id, $doc_name, $doc_type, $file_path
                    ]);
                } else {
                    error_log("submit_application: application_documents table missing, skipping insert");
                }
            } catch (Throwable $e) {
                error_log("submit_application: failed inserting application_documents: " . $e->getMessage());
            }
        }
    }
}

// Commit transaction if using one
try {
    if ($usingTx && method_exists($db, 'commit')) $db->commit();
} catch (Throwable $e) {
    error_log("submit_application: commit failed: " . $e->getMessage());
}

/*
 * NOTIFICATION: notify market managers only (for the stall's market).
 * Avoid broadcasting to super_admins.
 */
try {
    $market_id = isset($stall['market_id']) ? (int)$stall['market_id'] : null;
    $recipients = [];

    if ($market_id) {
        // Primary: market_managers table
        $recipients = $db->fetchAll("SELECT user_id FROM market_managers WHERE market_id = ? AND status = 'active'", [$market_id]) ?: [];

        // Secondary: user_roles mapping for market_manager role scoped to the market
        if (empty($recipients)) {
            $recipients = $db->fetchAll("
                SELECT ur.user_id
                FROM user_roles ur
                JOIN roles r ON ur.role_id = r.role_id
                JOIN users u ON ur.user_id = u.user_id
                WHERE r.name = 'market_manager'
                  AND ur.market_id = ?
                  AND ur.status = 'active'
                  AND u.status = 'active'
            ", [$market_id]) ?: [];
        }
    }

    // Final fallback: notify issuer/admin-like roles (excluding super_admin)
    if (empty($recipients)) {
        $recipients = $db->fetchAll("
            SELECT u.user_id
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.role_id
            JOIN users u ON ur.user_id = u.user_id
            WHERE r.name IN ('issuer_admin','admin','municipal_admin','agency_admin')
              AND ur.status = 'active'
              AND u.status = 'active'
        ") ?: [];
    }

    $stallLabel = $stall['stall_number'] ?? 'Unknown';
    $msg = "New application (#{$app_id}) by " . ($_SESSION['full_name'] ?? 'Vendor') . " for stall {$stallLabel}. Business: {$business_name}";
    if ($preferred_start_date) {
        $msg .= " — preferred start: {$preferred_start_date}";
    }

    foreach ($recipients as $r) {
        $to = (int)($r['user_id'] ?? 0);
        if ($to <= 0) continue;
        if (function_exists('createNotification')) {
            createNotification($db, $to, 'New Stall Application', $msg, 'info', 'application', $app_id, 'applications');
        } else {
            error_log("submit_application: createNotification not available; admin_id={$to}, msg={$msg}");
        }
    }
} catch (Throwable $e) {
    error_log("submit_application: notify market managers failed: " . $e->getMessage());
}

logAudit($db, $user_id, 'Submit Application', 'applications', $app_id, null, null);
$_SESSION['success_message'] = 'Application submitted successfully.';
redirect('browse_stalls.php');