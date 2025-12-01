<?php
// check_availability.php
// Simple JSON endpoint used by register.php to check availability of username, email, contact_number.
//
// Place this file in the same webroot as register.php (e.g. C:\xampp\htdocs\NEW\check_availability.php).
// Returns JSON: { ok: true, field: "username", value: "...", available: true }
// or { ok: false, error: "message" }

header('Content-Type: application/json; charset=utf-8');

// very small whitelist of allowed fields
$allowed = ['username', 'email', 'contact_number'];

$field = isset($_GET['field']) ? strtolower(trim((string)$_GET['field'])) : '';
$value = isset($_GET['value']) ? trim((string)$_GET['value']) : '';

if ($field === '' || $value === '') {
    echo json_encode(['ok' => false, 'error' => 'Missing field or value']);
    exit;
}
if (!in_array($field, $allowed, true)) {
    echo json_encode(['ok' => false, 'error' => 'Unsupported field']);
    exit;
}

// load your app config which should expose $db (same as other pages)
$cfg = __DIR__ . '/config.php';
if (!file_exists($cfg)) {
    echo json_encode(['ok' => false, 'error' => 'Server misconfiguration: config missing']);
    exit;
}
require_once $cfg;

try {
    if ($field === 'username') {
        // simple exact match
        $row = $db->fetch("SELECT 1 FROM users WHERE username = ? LIMIT 1", [$value]);
        $available = $row ? false : true;

    } elseif ($field === 'email') {
        $email = filter_var($value, FILTER_SANITIZE_EMAIL);
        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            echo json_encode(['ok' => false, 'error' => 'Invalid email format']);
            exit;
        }
        $row = $db->fetch("SELECT 1 FROM users WHERE email = ? LIMIT 1", [$email]);
        $available = $row ? false : true;

    } else { // contact_number
        // normalize digits-only (strip non-digits)
        $digits = preg_replace('/\D+/', '', $value);
        if ($digits === '') {
            echo json_encode(['ok' => false, 'error' => 'Invalid contact number']);
            exit;
        }
        // Compare normalized digits with stored contact_number normalized on-the-fly.
        // This will match numbers stored as "+63 912-345-6789", "09123456789", etc.
        $row = $db->fetch("
            SELECT 1 FROM users
            WHERE REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(contact_number, ' ', ''), '+', ''), '-', ''), '(', ''), ')', '') = ?
            LIMIT 1
        ", [$digits]);
        $available = $row ? false : true;
    }

    echo json_encode([
        'ok' => true,
        'field' => $field,
        'value' => $value,
        'available' => (bool)$available
    ]);
    exit;

} catch (Throwable $e) {
    error_log("check_availability error: " . $e->getMessage());
    echo json_encode(['ok' => false, 'error' => 'Server error']);
    exit;
}