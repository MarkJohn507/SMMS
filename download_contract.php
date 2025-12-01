<?php
require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/csrf.php';

$type = $_GET['type'] ?? '';
if ($type === 'application') {
    $doc_id = isset($_GET['doc_id']) ? (int)$_GET['doc_id'] : 0;
    if ($doc_id <= 0) { http_response_code(400); echo "Invalid"; exit; }
    $doc = $db->fetch("SELECT * FROM application_documents WHERE document_id = ? LIMIT 1", [$doc_id]);
    if (!$doc) { http_response_code(404); echo "Not found"; exit; }
    $path = $doc['file_path'];
    $app = $db->fetch("SELECT vendor_id FROM applications WHERE application_id = ? LIMIT 1", [$doc['application_id']]);
    $allowed = isAdmin() || (!empty($_SESSION['user_id']) && $app && $_SESSION['user_id'] == $app['vendor_id']);
} elseif ($type === 'lease') {
    $lease_id = isset($_GET['lease_id']) ? (int)$_GET['lease_id'] : 0;
    if ($lease_id <= 0) { http_response_code(400); echo "Invalid"; exit; }
    $lease = $db->fetch("SELECT contract_document, vendor_id FROM leases WHERE lease_id = ? LIMIT 1", [$lease_id]);
    if (!$lease || empty($lease['contract_document'])) { http_response_code(404); echo "Not found"; exit; }
    $path = $lease['contract_document'];
    $allowed = isAdmin() || (!empty($_SESSION['user_id']) && $_SESSION['user_id'] == $lease['vendor_id']);
} else {
    http_response_code(400);
    echo "Invalid type";
    exit;
}

if (!$allowed) { http_response_code(403); echo "Forbidden"; exit; }

$root = realpath(__DIR__);
$full = $path;
if (!file_exists($full)) $full = $root . DIRECTORY_SEPARATOR . $path;
$real = realpath($full);
if ($real === false || !is_file($real)) { http_response_code(404); echo "File not found"; exit; }

$uploadsDir = realpath(__DIR__ . '/uploads');
if ($uploadsDir && strpos($real, $uploadsDir) !== 0) {
    http_response_code(403); echo "Forbidden"; exit;
}

$mime = mime_content_type($real) ?: 'application/octet-stream';
header('Content-Type: ' . $mime);
header('Content-Disposition: attachment; filename="' . basename($real) . '"');
header('Content-Length: ' . filesize($real));
readfile($real);
exit;