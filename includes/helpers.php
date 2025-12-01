<?php
// includes/helpers.php - shared helper utilities (hardened)
// Replaces redirect() with a robust implementation to avoid redirect loops
// and adds small CSRF helper aliases used across the app.

// Start session if not already (safe to call multiple times)
if (session_status() !== PHP_SESSION_ACTIVE) {
    if (php_sapi_name() !== 'cli') { if (session_status() === PHP_SESSION_NONE) session_start(); }
}

// sanitize input (simple)
if (!function_exists('sanitize')) {
    function sanitize($v) {
        if (is_array($v)) return array_map('sanitize', $v);
        return trim(htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'));
    }
}

// app_base() - returns application base path (eg '/NEW' or '')
if (!function_exists('app_base')) {
    function app_base() {
        if (defined('APP_BASE') && APP_BASE !== '') {
            return rtrim(APP_BASE, '/');
        }
        // Derive from SCRIPT_NAME: take first segment (e.g. /NEW/index.php => /NEW)
        $script = $_SERVER['SCRIPT_NAME'] ?? '/';
        $parts = explode('/', trim($script, '/'));
        if (!empty($parts[0])) {
            return '/' . $parts[0];
        }
        return '';
    }
}

// robust redirect helper
if (!function_exists('redirect')) {
    function redirect($url) {
        // If $url is relative filename (no leading slash and not absolute http), make it absolute under app base
        if (strpos($url, '/') !== 0 && stripos($url, 'http') !== 0) {
            $base = app_base();
            $url = ($base === '') ? '/' . ltrim($url, '/') : rtrim($base, '/') . '/' . ltrim($url, '/');
        }

        // Normalize target for comparison (strip query and trailing slashes)
        $normTarget = preg_replace('/\?.*$/', '', $url);
        $normTarget = rtrim($normTarget, '/');

        // Current request URI (strip query)
        $current = $_SERVER['REQUEST_URI'] ?? '/';
        $normCurrent = preg_replace('/\?.*$/', '', $current);
        $normCurrent = rtrim($normCurrent, '/');

        // If redirect target equals current, avoid redirect to prevent loops
        // Also handle the case where target is an absolute URL pointing to same path
        $targetPath = $normTarget;
        if (stripos($targetPath, 'http') === 0) {
            // Try to extract path portion
            $parsed = parse_url($targetPath);
            $targetPath = $parsed['path'] ?? $targetPath;
            $targetPath = rtrim($targetPath, '/');
        }

        if ($targetPath === $normCurrent) {
            // Do not issue a redirect to the same URL
            return;
        }

        // Send a proper Location header and exit
        header('Location: ' . $url, true, 302);
        exit;
    }
}

// format currency
if (!function_exists('formatCurrency')) {
    function formatCurrency($amount) {
        return '₱' . number_format((float)$amount, 2);
    }
}

// format date
function formatDate($value, $withTime = false) {
    if (empty($value)) return '';
    try {
        if ($value instanceof DateTime) {
            $dt = $value;
        } else {
            // handle timestamps too
            if (is_numeric($value)) {
                $dt = (new DateTime())->setTimestamp((int)$value);
            } else {
                $dt = new DateTime($value);
            }
        }
        return $withTime ? $dt->format('M j, Y g:i A') : $dt->format('M j, Y');
    } catch (Throwable $e) {
        // Fallback: original string (or empty)
        error_log("formatDate: failed to format value='{$value}': " . $e->getMessage());
        return is_string($value) ? $value : '';
    }
}

if (!function_exists('autoUpdateOverduePayments')) {
    function autoUpdateOverduePayments($db) {
        try {
            $db->query("
                UPDATE payments
                SET status='overdue', updated_at=NOW()
                WHERE status IN ('pending','partial')
                  AND due_date < CURDATE()
            ");
        } catch (Throwable $e) {
            error_log('autoUpdateOverduePayments fail: '.$e->getMessage());
        }
    }
}

// Small helper to render status badges used across admin/vendor pages
if (!function_exists('getStatusBadge')) {
    function getStatusBadge($status) {
        $s = strtolower((string)$status);
        switch ($s) {
            case 'pending':
                return '<span class="px-2 py-1 text-xs bg-yellow-100 text-yellow-800 rounded">Pending</span>';
            case 'active':
                return '<span class="px-2 py-1 text-xs bg-green-100 text-green-800 rounded">Active</span>';
            case 'approved':
                return '<span class="px-2 py-1 text-xs bg-green-100 text-green-800 rounded">Approved</span>';
            case 'available':
                return '<span class="px-2 py-1 text-xs bg-green-100 text-green-800 rounded">Available</span>';
            case 'occupied':
                return '<span class="px-2 py-1 text-xs bg-blue-100 text-blue-800 rounded">Occupied</span>';
            case 'expired':
                return '<span class="px-2 py-1 text-xs bg-gray-100 text-gray-800 rounded">Expired</span>';
            case 'terminated':
                return '<span class="px-2 py-1 text-xs bg-red-100 text-red-800 rounded">Terminated</span>';
            case 'rejected':
                return '<span class="px-2 py-1 text-xs bg-red-100 text-red-800 rounded">Rejected</span>';
            case 'reserved':
                return '<span class="px-2 py-1 text-xs bg-yellow-100 text-yellow-800 rounded">Reserved</span>';
            case 'maintenance':
                return '<span class="px-2 py-1 text-xs bg-red-100 text-red-800 rounded">Maintenance</span>';
            case 'paid':
                return '<span class="px-2 py-1 text-xs bg-green-100 text-green-800 rounded">Paid</span>';
            case 'overdue':
                return '<span class="px-2 py-1 text-xs bg-red-100 text-red-800 rounded">Overdue</span>';
            default:
                return '<span class="px-2 py-1 text-xs bg-gray-100 text-gray-800 rounded">' . htmlspecialchars($status) . '</span>';
        }
    }
}

// simple CSRF token helpers
if (!function_exists('csrf_get_token')) {
    function csrf_get_token() {
        if (empty($_SESSION['csrf_token'])) {
            try {
                $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
            } catch (Throwable $e) {
                // fallback
                $_SESSION['csrf_token'] = md5(uniqid('', true));
            }
        }
        return $_SESSION['csrf_token'];
    }
}
if (!function_exists('csrf_validate')) {
    function csrf_validate($token) {
        return !empty($token) && !empty($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
    }
}
// Backwards-compatible helpers used in other files
if (!function_exists('csrf_field')) {
    function csrf_field() {
        $t = htmlspecialchars(csrf_get_token());
        return '<input type="hidden" name="csrf_token" value="' . $t . '">';
    }
}
if (!function_exists('csrf_validate_request')) {
    function csrf_validate_request() {
        $token = $_POST['csrf_token'] ?? $_REQUEST['csrf_token'] ?? null;
        return csrf_validate($token);
    }
}

// is POST
if (!function_exists('isPost')) {
    function isPost() { return $_SERVER['REQUEST_METHOD'] === 'POST'; }
}