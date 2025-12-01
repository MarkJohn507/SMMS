<?php
require_once 'config.php';
require_once 'includes/notifications.php';
require_once 'includes/auth_roles.php';
require_once 'includes/csrf.php';

header('Content-Type: application/json');

if (!isLoggedIn()) {
    http_response_code(403);
    echo json_encode(['ok'=>false,'error'=>'unauthenticated']);
    exit;
}

// Validate CSRF for POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !csrf_validate_request()) {
    http_response_code(400);
    echo json_encode(['ok'=>false,'error'=>'invalid_csrf']);
    exit;
}

$notification_id = isset($_POST['notification_id']) ? (int)$_POST['notification_id'] : 0;
if ($notification_id <= 0) {
    http_response_code(400);
    echo json_encode(['ok'=>false,'error'=>'invalid_id']);
    exit;
}

$n = $db->fetch("SELECT user_id FROM notifications WHERE notification_id = ? LIMIT 1", [$notification_id]);
if (!$n) {
    http_response_code(404);
    echo json_encode(['ok'=>false,'error'=>'not_found']);
    exit;
}
if ($n['user_id'] != $_SESSION['user_id'] && !isAdmin()) {
    http_response_code(403);
    echo json_encode(['ok'=>false,'error'=>'forbidden']);
    exit;
}

try {
    markAsRead($db, $notification_id);
    echo json_encode(['ok'=>true]);
} catch (Throwable $e) {
    error_log("mark_notification_read failed: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['ok'=>false,'error'=>'server_error']);
}