<?php
// API/upload_inspection_photo.php
// Accepts multipart/form-data file uploads (field name 'photo').
// Returns JSON { ok: true, url: '/uploads/inspections/...' } on success.

require_once __DIR__ . '/../config.php';
header('Content-Type: application/json; charset=utf-8');

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
$uid = $_SESSION['user_id'] ?? null;
if (!$uid) {
    http_response_code(401);
    echo json_encode(['error' => 'unauthenticated']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'method_not_allowed']);
    exit;
}

if (empty($_FILES['photo']) || $_FILES['photo']['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    echo json_encode(['error' => 'no_file']);
    exit;
}

$file = $_FILES['photo'];
$allowedMime = ['image/jpeg','image/png','image/webp'];
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $file['tmp_name']);
finfo_close($finfo);
if (!in_array($mime, $allowedMime, true)) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid_file_type']);
    exit;
}

// create uploads/inspections directory if missing
$uploadsBase = __DIR__ . '/../uploads/inspections';
if (!is_dir($uploadsBase)) {
    @mkdir($uploadsBase, 0755, true);
}

// unique filename
$ext = pathinfo($file['name'], PATHINFO_EXTENSION) ?: ($mime === 'image/png' ? 'png' : 'jpg');
$fname = time() . '-' . bin2hex(random_bytes(6)) . '.' . preg_replace('/[^a-z0-9]/i','', $ext);
$dst = $uploadsBase . '/' . $fname;

if (!move_uploaded_file($file['tmp_name'], $dst)) {
    http_response_code(500);
    echo json_encode(['error' => 'upload_failed']);
    exit;
}

// Build a URL for returned file (prefer APP_URL if available)
$publicPath = '/uploads/inspections/' . $fname;
$base = defined('APP_URL') ? rtrim(APP_URL, '/') : '';
$url = $base . $publicPath;

http_response_code(201);
echo json_encode(['ok' => true, 'url' => $url, 'path' => $publicPath]);
exit;