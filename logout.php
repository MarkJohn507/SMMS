<?php
// logout.php - safe logout handling
require_once 'config.php';
require_once 'includes/audit.php';

// Log the logout if user_id present
$user_id = $_SESSION['user_id'] ?? null;
if ($user_id) {
    try { logAudit($db, $user_id, 'Logout', 'users', $user_id, null, null); } catch (Throwable $e) {}
}

// Clear session data
$_SESSION = [];

// Remove session cookie
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params['path'] ?? '/', $params['domain'] ?? '', $params['secure'] ?? false, $params['httponly'] ?? true
    );
}

// Destroy session and regenerate a fresh one
session_destroy();
session_start();
session_regenerate_id(true);

// Redirect to login with explicit logout flag
redirect('login.php?logout=1');