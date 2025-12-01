<?php
// includes/csrf.php
// Central CSRF helpers. Use csrf_field() in forms and csrf_validate_request() in POST handlers.

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

if (!function_exists('csrf_get_token')) {
    function csrf_get_token() {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $_SESSION['csrf_token_created_at'] = time();
        }
        return $_SESSION['csrf_token'];
    }
}

if (!function_exists('csrf_field')) {
    // Returns HTML hidden input for embedding in forms
    function csrf_field() {
        $t = htmlspecialchars(csrf_get_token(), ENT_QUOTES, 'UTF-8');
        return '<input type="hidden" name="csrf_token" value="' . $t . '">';
    }
}

if (!function_exists('csrf_validate')) {
    // Validate a token value
    function csrf_validate($token) {
        if (empty($token) || empty($_SESSION['csrf_token'])) return false;
        return hash_equals($_SESSION['csrf_token'], $token);
    }
}

if (!function_exists('csrf_validate_request')) {
    // Validate POST request and optionally regenerate token on success
    function csrf_validate_request() {
        if (!isset($_POST['csrf_token'])) return false;
        $ok = csrf_validate($_POST['csrf_token']);
        // Optionally rotate token on success for improved security
        if ($ok) {
            // rotate token to prevent replay
            unset($_SESSION['csrf_token']);
            csrf_get_token();
        }
        return $ok;
    }
}