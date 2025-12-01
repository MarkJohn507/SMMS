<?php
require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/csrf.php';

$payment_id = isset($_GET['payment_id']) ? (int)$_GET['payment_id'] : 0;
$filename = isset($_GET['file']) ? basename($_GET['file']) : null;

if ($payment_id <= 0 && !$filename) {
    http_response_code(400);
    echo "Invalid request.";
    exit;
}

if ($payment_id > 0) {
    $p = $db->fetch("SELECT * FROM payments WHERE payment_id = ? LIMIT 1", [$payment_id]);
    if (!$p || empty($p['receipt_number'])) {
        http_response_code(404);
        echo "Receipt not found.";
        exit;
    }
    $filename = $p['receipt_number'];
}

$base = realpath(__DIR__ . '/uploads/payments');
$filepath = $base . DIRECTORY_SEPARATOR . $filename;
$real = realpath($filepath);
if ($real === false || strpos($real, $base) !== 0 || !is_file($real)) {
    http_response_code(404);
    echo "File not found.";
    exit;
}

$allowed = false;
if (isAdmin()) $allowed = true;
if (!empty($_SESSION['user_id'])) {
    if ($payment_id > 0) {
        if ($_SESSION['user_id'] == $p['vendor_id']) $allowed = true;
    } else {
        $allowed = false;
    }
}
if (!$allowed) {
    http_response_code(403);
    echo "Forbidden";
    exit;
}

$mime = mime_content_type($real) ?: 'application/octet-stream';
header('Content-Type: ' . $mime);
header('Content-Disposition: attachment; filename="' . basename($real) . '"');
header('Content-Length: ' . filesize($real));
readfile($real);
exit;