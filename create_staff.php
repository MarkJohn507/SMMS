<?php
/**
 * create_staff.php (robust + optional ID upload)
 *
 * Changes:
 * - ID document is now optional for market managers. If an ID file is provided we validate and store it;
 *   otherwise we continue creating the user/role without a document.
 * - Record uploaded document into user_role_documents OR identity_documents using a schema-safe approach:
 *     * Detect which storage column exists (storage_url, storage_path, file_path, path, url) and use it.
 *     * Detect primary key column names if needed.
 * - Better logging and cleanup on failure.
 *
 * All other behavior preserved.
 */

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/csrf.php';
require_once 'includes/audit.php';
require_once 'includes/notifications.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

$uid = $_SESSION['user_id'] ?? null;
if (!$uid) {
    http_response_code(403);
    echo "Forbidden";
    exit;
}

/* ------------------ Safe return page helper & whitelist ------------------ */
function resolve_return_page(string $candidate): string {
    $allowed = [
        'manage_staff.php',
        'admin_dashboard.php',
        'admin_pending_requests.php',
        'manage_users.php'
    ];
    $base = basename(parse_url($candidate, PHP_URL_PATH) ?: $candidate);
    if (in_array($base, $allowed, true)) return $base;
    return 'manage_staff.php';
}

/* ------------------ Permission: only market_manager ------------------ */
$is_market_manager = false;
try {
    if (function_exists('userIsInRole')) {
        $is_market_manager = userIsInRole($db, $uid, 'market_manager');
    } else {
        $row = $db->fetch("
            SELECT 1
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.role_id
            WHERE ur.user_id = ? AND r.name = 'market_manager' AND LOWER(TRIM(ur.status)) = 'active'
            LIMIT 1
        ", [$uid]);
        $is_market_manager = (bool)$row;
    }
} catch (Throwable $e) {
    error_log("create_staff: role check failed: ".$e->getMessage());
    $is_market_manager = false;
}

/* Resolve incoming from_page early and safely */
$from_page_input = $_POST['from_page'] ?? $_GET['from_page'] ?? 'manage_staff.php';
$from_page = resolve_return_page((string)$from_page_input);

if (!$is_market_manager) {
    $_SESSION['staff_error'] = 'You do not have permission to create staff accounts.';
    header('Location: admin_dashboard.php');
    exit;
}

/* ------------------ Request validation ------------------ */
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !csrf_validate_request()) {
    $_SESSION['staff_error'] = 'Invalid request.';
    header('Location: '.$from_page);
    exit;
}

/* ------------------ Helpers ------------------ */
function getManagedMarketIds($db, int $userId): array {
    $ids = [];
    try {
        $rows = $db->fetchAll("SELECT market_id FROM market_managers WHERE user_id = ?", [$userId]) ?: [];
        foreach ($rows as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id'];
    } catch (Throwable $e) {}
    if (empty($ids)) {
        try {
            $rows = $db->fetchAll("SELECT market_id FROM markets WHERE created_by = ?", [$userId]) ?: [];
            foreach ($rows as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id'];
        } catch (Throwable $e) {}
    }
    return array_values(array_unique($ids));
}

function normalize_phone_e164_local($raw, $default_country = '+63') {
    $s = trim((string)$raw);
    if ($s === '') return null;
    $digits = preg_replace('/[^\d+]/', '', $s);
    if ($digits === '') return null;
    if (strpos($digits, '+') === 0) {
        return '+' . preg_replace('/[^\d]/', '', substr($digits, 1));
    }
    if (strpos($digits, '00') === 0) {
        return '+' . ltrim($digits, '0');
    }
    if (strpos($digits, '0') === 0) {
        $n = ltrim($digits, '0');
        $cc = preg_replace('/[^\d]/', '', $default_country);
        return '+' . $cc . $n;
    }
    $cc = preg_replace('/[^\d]/', '', $default_country);
    return '+' . $cc . preg_replace('/[^\d]/', '', $digits);
}

/* Schema helpers */
function table_columns($db, string $table): array {
    try {
        $cols = $db->fetchAll("SHOW COLUMNS FROM `{$table}`") ?: [];
        $names = [];
        foreach ($cols as $c) {
            if (is_array($c) && isset($c['Field'])) $names[] = $c['Field'];
            elseif (is_array($c) && isset($c['field'])) $names[] = $c['field'];
        }
        return $names;
    } catch (Throwable $e) {
        return [];
    }
}
function find_storage_column(array $cols): ?string {
    $candidates = ['storage_url','storage_path','file_path','path','url','storage'];
    foreach ($candidates as $cand) {
        if (in_array($cand, $cols, true)) return $cand;
    }
    return null;
}
function find_id_column(array $cols): ?string {
    $candidates = ['id','identity_document_id','document_id','identity_id'];
    foreach ($candidates as $cand) {
        if (in_array($cand, $cols, true)) return $cand;
    }
    return null;
}

/* ------------------ Inputs ------------------ */
$username        = trim((string)($_POST['username'] ?? ''));
$password        = $_POST['password'] ?? '';
$full_name       = trim((string)($_POST['full_name'] ?? ''));
$email           = trim((string)($_POST['email'] ?? ''));
$contact_number  = trim((string)($_POST['contact_number'] ?? ''));
$role_raw        = trim((string)($_POST['role'] ?? ''));
$market_id       = (int)($_POST['market_id'] ?? 0);

/* ------------------ Normalize & validate role ------------------ */
$role = strtolower($role_raw);
$allowed_roles = ['inspector', 'accountant'];
if ($role === '' || !in_array($role, $allowed_roles, true)) {
    $_SESSION['staff_error'] = 'Role not allowed.';
    header('Location: '.$from_page);
    exit;
}

/* ------------------ Basic validation ------------------ */
if ($username === '' || $password === '' || $full_name === '' || $market_id <= 0) {
    $_SESSION['staff_error'] = 'Please provide username, password, full name and market.';
    header('Location: '.$from_page);
    exit;
}

/* ------------------ Market scoping ------------------ */
$managed = getManagedMarketIds($db, $uid);
if (empty($managed) || !in_array($market_id, $managed, true)) {
    $_SESSION['staff_error'] = 'You can only assign accounts to markets you manage.';
    header('Location: '.$from_page);
    exit;
}

/* ------------------ Uniqueness checks ------------------ */
try {
    $exists = $db->fetch("SELECT user_id FROM users WHERE username = ? LIMIT 1", [$username]);
    if ($exists) {
        $_SESSION['staff_error'] = 'Username already exists.';
        header('Location: '.$from_page);
        exit;
    }
} catch (Throwable $e) {
    error_log("create_staff: username check failed: ".$e->getMessage());
    $_SESSION['staff_error'] = 'Server error validating username.';
    header('Location: '.$from_page);
    exit;
}
if ($email !== '') {
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['staff_error'] = 'Invalid email address.';
        header('Location: '.$from_page);
        exit;
    }
    try {
        $existsEmail = $db->fetch("SELECT user_id FROM users WHERE email = ? LIMIT 1", [$email]);
        if ($existsEmail) {
            $_SESSION['staff_error'] = 'Email already in use.';
            header('Location: '.$from_page);
            exit;
        }
    } catch (Throwable $e) {
        error_log("create_staff: email uniqueness check failed: ".$e->getMessage());
    }
}

/* ------------------ Password policy ------------------ */
$minLen = defined('PASSWORD_MIN_LENGTH') ? (int)PASSWORD_MIN_LENGTH : 8;
if (strlen((string)$password) < $minLen) {
    $_SESSION['staff_error'] = "Password must be at least {$minLen} characters.";
    header('Location: '.$from_page);
    exit;
}

/* ------------------ Normalize contact ------------------ */
$normalized_contact = $contact_number ? normalize_phone_e164_local($contact_number) : null;

/* ------------------ Prepare upload dir for ID doc ------------------ */
$uploadBase = __DIR__ . '/uploads/staff_ids';
if (!is_dir($uploadBase)) @mkdir($uploadBase, 0755, true);

/* ------------------ Start transaction ------------------ */
$usingTx = false;
try {
    if (method_exists($db, 'beginTransaction')) { $db->beginTransaction(); $usingTx = true; }
} catch (Throwable $e) { $usingTx = false; }

/* Keep track of created ids for cleanup */
$new_user_id = null;
$new_user_role_id = null;
$uploaded_doc_path = null;

/* ------------------ Create user (status = 'active') ------------------ */
try {
    $hashed = password_hash($password, PASSWORD_DEFAULT);
    $user_status = 'active';

    $db->query("
        INSERT INTO users (username, password, full_name, email, contact_number, role, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
    ", [
        $username,
        $hashed,
        $full_name,
        $email ?: null,
        $normalized_contact ?: null,
        $role,
        $user_status
    ]);
    $new_user_id = (int)$db->lastInsertId();

    // Defensive ensure role persisted
    try {
        $db->query("UPDATE users SET role = ? WHERE user_id = ? LIMIT 1", [$role, $new_user_id]);
    } catch (Throwable $_e) {
        error_log("create_staff: post-insert users.role update failed for user {$new_user_id}: " . $_e->getMessage());
    }
} catch (Throwable $e) {
    if ($usingTx && method_exists($db,'rollBack')) $db->rollBack();
    error_log("create_staff: user insert failed: ".$e->getMessage());
    $_SESSION['staff_error'] = 'Failed to create user.';
    header('Location: '.$from_page);
    exit;
}

/* ------------------ Insert user_role (status = 'pending') ------------------ */
try {
    $roleRow = $db->fetch("SELECT role_id FROM roles WHERE name = ? LIMIT 1", [$role]);
    if ($roleRow && !empty($roleRow['role_id'])) {
        $db->query("
            INSERT INTO user_roles (user_id, role_id, market_id, issuer_id, status, assigned_by, assigned_at)
            VALUES (?, ?, ?, NULL, 'pending', ?, NOW())
        ", [$new_user_id, (int)$roleRow['role_id'], $market_id, $uid]);
        $new_user_role_id = (int)$db->lastInsertId();
    } else {
        error_log("create_staff: role row not found for {$role}");
        if ($usingTx && method_exists($db,'rollBack')) $db->rollBack();
        try { $db->query("DELETE FROM users WHERE user_id = ?", [$new_user_id]); } catch (Throwable $_e) {}
        $_SESSION['staff_error'] = 'Role configuration problem. Contact an administrator.';
        header('Location: '.$from_page);
        exit;
    }
} catch (Throwable $e) {
    if ($usingTx && method_exists($db,'rollBack')) $db->rollBack();
    error_log("create_staff: user_roles insert failed: ".$e->getMessage());
    try { $db->query("DELETE FROM users WHERE user_id = ?", [$new_user_id]); } catch (Throwable $_e) {}
    $_SESSION['staff_error'] = 'Failed to assign role.';
    header('Location: '.$from_page);
    exit;
}

/* ------------------ Optional ID upload handling ------------------ */
/*
 * Market manager may optionally supply an ID document.
 * If provided, validate and attempt to store it in user_role_documents,
 * falling back to identity_documents. This code detects actual storage column
 * names and uses those. Failure to record a document is logged but does not
 * abort the overall flow (per request).
 */
if (!empty($_FILES['id_document']) && ($_FILES['id_document']['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_OK) {
    // Validate & store upload
    $f = $_FILES['id_document'];
    $maxBytes = 5 * 1024 * 1024;
    $allowed_mimes = ['image/jpeg'=>'jpg','image/png'=>'png','application/pdf'=>'pdf'];

    if ($f['size'] > $maxBytes) {
        // cleanup and fail
        if ($usingTx && method_exists($db,'rollBack')) $db->rollBack();
        try { if ($new_user_role_id) $db->query("DELETE FROM user_roles WHERE user_role_id = ?", [$new_user_role_id]); } catch (Throwable $_e) {}
        try { $db->query("DELETE FROM users WHERE user_id = ?", [$new_user_id]); } catch (Throwable $_e) {}
        $_SESSION['staff_error'] = 'ID document too large (max 5MB).';
        header('Location: '.$from_page);
        exit;
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $f['tmp_name']);
    finfo_close($finfo);
    if (!isset($allowed_mimes[$mime])) {
        if ($usingTx && method_exists($db,'rollBack')) $db->rollBack();
        try { if ($new_user_role_id) $db->query("DELETE FROM user_roles WHERE user_role_id = ?", [$new_user_role_id]); } catch (Throwable $_e) {}
        try { $db->query("DELETE FROM users WHERE user_id = ?", [$new_user_id]); } catch (Throwable $_e) {}
        $_SESSION['staff_error'] = 'Unsupported ID document format.';
        header('Location: '.$from_page);
        exit;
    }

    $ext = $allowed_mimes[$mime];
    $userDir = $uploadBase . "/user_{$new_user_id}";
    if (!is_dir($userDir)) @mkdir($userDir, 0755, true);
    $safe = "id_" . time() . "_" . bin2hex(random_bytes(6)) . "." . $ext;
    $dest = $userDir . "/" . $safe;
    if (!move_uploaded_file($f['tmp_name'], $dest)) {
        if ($usingTx && method_exists($db,'rollBack')) $db->rollBack();
        try { if ($new_user_role_id) $db->query("DELETE FROM user_roles WHERE user_role_id = ?", [$new_user_role_id]); } catch (Throwable $_e) {}
        try { $db->query("DELETE FROM users WHERE user_id = ?", [$new_user_id]); } catch (Throwable $_e) {}
        $_SESSION['staff_error'] = 'Failed to save uploaded ID document.';
        header('Location: '.$from_page);
        exit;
    }
    $uploaded_doc_path = 'uploads/staff_ids/user_' . $new_user_id . '/' . $safe;

    // Attempt to insert into user_role_documents (preferred) with schema-safe column name
    try {
        $urdCols = table_columns($db, 'user_role_documents');
        $urdStorageCol = find_storage_column($urdCols);

        if (!empty($urdCols) && $new_user_role_id) {
            // Build dynamic INSERT using found storage column (or fallback to a generic column name)
            if ($urdStorageCol) {
                $sql = "INSERT INTO user_role_documents (user_role_id, doc_type, `{$urdStorageCol}`, status, uploaded_at) VALUES (?, 'id', ?, 'submitted', NOW())";
                $db->query($sql, [$new_user_role_id, $uploaded_doc_path]);
            } else {
                // If no known storage column, try common column names directly and let DB error be caught
                $db->query("INSERT INTO user_role_documents (user_role_id, doc_type, storage_path, status, uploaded_at) VALUES (?, 'id', ?, 'submitted', NOW())", [$new_user_role_id, $uploaded_doc_path]);
            }
        } else {
            // Fallback to identity_documents if available
            $idCols = table_columns($db, 'identity_documents');
            if (!empty($idCols)) {
                $idStorageCol = find_storage_column($idCols) ?? 'storage_url';
                if (in_array($idStorageCol, $idCols, true)) {
                    $sql = "INSERT INTO identity_documents (user_id, doc_type, `{$idStorageCol}`, status, uploaded_at) VALUES (?, 'id', ?, 'submitted', NOW())";
                    $db->query($sql, [$new_user_id, $uploaded_doc_path]);
                } else {
                    // try a fallback column name that some schemas use
                    $db->query("INSERT INTO identity_documents (user_id, doc_type, storage_url, status, uploaded_at) VALUES (?, 'id', ?, 'submitted', NOW())", [$new_user_id, $uploaded_doc_path]);
                }
            } else {
                // No document table exists — log and continue
                error_log("create_staff: no document table available to record uploaded id for user {$new_user_id}");
            }
        }
    } catch (Throwable $e) {
        // Log failure but do NOT abort overall flow; market manager chose to upload and we tried our best.
        error_log("create_staff: failed to record uploaded id doc for user {$new_user_id}: " . $e->getMessage());
        // (We intentionally do not rollback the whole user creation for optional document uploads.)
    }
}

/* ------------------ Commit and notify super_admins ------------------ */
try {
    if ($usingTx && method_exists($db,'commit')) $db->commit();
} catch (Throwable $e) {
    error_log("create_staff: commit failed: ".$e->getMessage());
}

/* Audit entry */
logAudit($db, $uid, 'Created staff account (user active, role pending)', 'users', $new_user_id, null, json_encode(['role'=>$role,'market_id'=>$market_id]));

/* Notify super_admins to review/approve the pending role */
try {
    $superAdmins = $db->fetchAll("
        SELECT u.user_id
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.role_id
        JOIN users u ON ur.user_id = u.user_id
        WHERE r.name = 'super_admin' AND ur.status = 'active' AND u.status = 'active'
    ") ?: [];

    if (empty($superAdmins)) {
        $superAdmins = $db->fetchAll("
            SELECT u.user_id
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.role_id
            JOIN users u ON ur.user_id = u.user_id
            WHERE r.name IN ('admin','issuer_admin','municipal_admin','agency_admin') AND ur.status = 'active' AND u.status = 'active'
        ") ?: [];
    }

    $marketName = '';
    try {
        $m = $db->fetch("SELECT market_name FROM markets WHERE market_id = ? LIMIT 1", [$market_id]);
        $marketName = $m['market_name'] ?? '';
    } catch (Throwable $e) {}

    $msg = "Staff account pending verification: {$full_name} (role: {$role})";
    if ($marketName) $msg .= " — market: {$marketName}";
    if ($uploaded_doc_path) $msg .= " — ID submitted";

    foreach ($superAdmins as $a) {
        $to = (int)($a['user_id'] ?? 0);
        if ($to <= 0) continue;
        if (function_exists('createNotification')) {
            createNotification($db, $to, 'Staff Account Pending Verification', $msg, 'info', 'staff_verification', $new_user_id, 'users');
        }
    }
} catch (Throwable $e) {
    error_log("create_staff: notify super_admins failed: ".$e->getMessage());
}

/* ------------------ Success for market manager ------------------ */
$_SESSION['staff_success'] = "Staff account created and role submitted for verification: {$full_name} (role: {$role}).";
header('Location: ' . $from_page);
exit;