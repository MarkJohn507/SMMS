<?php
// Secure download proxy for user documents.
// Usage: download_user_document.php?id=123
// Only the document owner or authorized admins may download.

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/helpers.php';
require_once 'includes/audit.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

if (!isset($_GET['id'])) {
    http_response_code(400);
    echo "Missing document id";
    exit;
}
$docId = (int)$_GET['id'];
if ($docId <= 0) {
    http_response_code(400);
    echo "Invalid document id";
    exit;
}

// fetch document record
try {
    $doc = $db->fetch("SELECT d.*, u.user_id AS owner_id, u.email AS owner_email FROM user_documents d JOIN users u ON d.user_id = u.user_id WHERE d.id = ? LIMIT 1", [$docId]);
    if (!$doc) {
        http_response_code(404);
        echo "Document not found";
        exit;
    }
} catch (Throwable $e) {
    error_log("download_user_document: DB fetch failed: " . $e->getMessage());
    http_response_code(500);
    echo "Server error";
    exit;
}

// permission check: owner or admin roles (restrict to admin roles you consider allowed)
$sessionUserId = (int)($_SESSION['user_id'] ?? 0);
$allowedAdminRoles = ['super_admin','municipal_admin','issuer_admin','market_manager','admin','inspector','accountant'];

// owner allowed
$allowed = ($sessionUserId === (int)$doc['owner_id']);

// otherwise check roles from session or DB
if (!$allowed) {
    $roles = $_SESSION['roles'] ?? [];
    // normalize lower-case
    $norm = array_map('strtolower', $roles);
    foreach ($allowedAdminRoles as $r) {
        if (in_array($r, $norm, true)) { $allowed = true; break; }
    }
    // final fallback: check active user_roles mapping in DB for current user (e.g., they are market_manager for that market)
    if (!$allowed && $sessionUserId > 0) {
        try {
            $check = $db->fetch("SELECT 1 FROM user_roles ur JOIN roles r ON ur.role_id = r.role_id WHERE ur.user_id = ? AND ur.status = 'active' AND LOWER(r.name) IN ('municipal_admin','super_admin','issuer_admin','market_manager') LIMIT 1", [$sessionUserId]);
            if (!empty($check)) $allowed = true;
        } catch (Throwable $e) {
            // ignore
        }
    }
}

if (!$allowed) {
    http_response_code(403);
    echo "Forbidden";
    exit;
}

// compute safe path
$rel = $doc['file_path']; // stored relative path like 'uploads/user_documents/123/file.jpg'
$base = realpath(__DIR__); // app root
$path = realpath($base . DIRECTORY_SEPARATOR . ltrim($rel, '/\\'));
if ($path === false || strpos($path, $base) !== 0) {
    http_response_code(400);
    echo "Invalid file path";
    exit;
}
if (!is_file($path) || !is_readable($path)) {
    http_response_code(404);
    echo "File not available";
    exit;
}

// log download action
try {
    logAudit($db, $sessionUserId > 0 ? $sessionUserId : null, 'Downloaded user document', 'user_documents', $docId, null, null);
} catch (Throwable $e) {
    error_log("download_user_document: audit failed: " . $e->getMessage());
}

// Serve file (use X-Sendfile/X-Accel if configured)
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime = $finfo->file($path) ?: ($doc['mime_type'] ?? 'application/octet-stream');
$basename = basename($doc['file_name'] ?? $path);

// Try X-Sendfile header (Apache mod_xsendfile)
if (function_exists('apache_get_modules') && in_array('mod_xsendfile', apache_get_modules())) {
    header('Content-Type: ' . $mime);
    header('Content-Disposition: inline; filename="' . $basename . '"');
    header('X-Sendfile: ' . $path);
    exit;
}

// Try Nginx X-Accel-Redirect via a configurable internal location
if (defined('X_ACCEL_INTERNAL') && X_ACCEL_INTERNAL) {
    // X_ACCEL_BASE should be the internal path prefix pointing to the uploads folder (config)
    if (!defined('X_ACCEL_BASE')) define('X_ACCEL_BASE', '/protected_uploads/');
    header('Content-Type: ' . $mime);
    header('Content-Disposition: inline; filename="' . $basename . '"');
    header('X-Accel-Redirect: ' . X_ACCEL_BASE . str_replace(realpath(__DIR__), '', $path));
    exit;
}

// Fallback to PHP readfile
header('Content-Type: ' . $mime);
header('Content-Disposition: inline; filename="' . $basename . '"');
header('Content-Length: ' . filesize($path));
header('Cache-Control: private, max-age=0, must-revalidate');
readfile($path);
exit;