<?php
/**
 * stall_photos_endpoint.php
 *
 * Purpose:
 *   Return JSON list of photos for a given stall (used by manage_stalls edit modal).
 *
 * Fixes:
 *   - Adds fallback implementation for csrf_validate_query() if it does not exist.
 *   - Avoids fatal error: "Call to undefined function csrf_validate_query()".
 *   - Adds basic authorization: user must be allowed to manage the stall's market.
 *   - Gracefully handles missing helpers (sanitize).
 *
 * Behavior:
 *   Request: GET /stall_photos_endpoint.php?stall_id=123&csrf_token=XXXX
 *   Response JSON:
 *     { "ok": true, "photos": [ { "stall_photo_id": 5, "file_path": "uploads/stalls/123/img.png" }, ... ] }
 *     or { "ok": false, "error": "reason" }
 *
 * Security Notes:
 *   - CSRF token check is optional fallback. If your project already has csrf_validate_query()
 *     in includes/csrf.php, that version will be used.
 *   - Authorization ensures only users with permission (admin roles or market_manager of that market)
 *     can view stall photos.
 */

declare(strict_types=1);

header('Content-Type: application/json');

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/auth_roles.php';
require_once __DIR__ . '/includes/audit.php';
require_once __DIR__ . '/includes/csrf.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

/* ---------------- Fallback Helpers ---------------- */

if (!function_exists('sanitize')) {
    function sanitize($v) {
        if (is_string($v)) {
            return trim($v);
        }
        return $v;
    }
}

/**
 * Fallback CSRF query validator if your csrf.php does not define one.
 * Looks for common token names in GET and matches session.
 */
if (!function_exists('csrf_validate_query')) {
    function csrf_validate_query(): bool {
        $candidates = ['csrf_token','csrf','token','_csrf'];
        foreach ($candidates as $key) {
            if (isset($_GET[$key]) && isset($_SESSION[$key]) && hash_equals((string)$_SESSION[$key], (string)$_GET[$key])) {
                return true;
            }
        }
        // If no token present at all, treat as failure (tighten security).
        return false;
    }
}

/**
 * Check if current user can view/manage stall photos.
 * Similar logic to manage_stalls guard: admin roles OR market_manager of stall's market.
 */
function user_can_access_stall($db, int $stall_id): bool {
    $uid = $_SESSION['user_id'] ?? 0;
    if ($uid <= 0) return false;

    // Admin-like roles
    $adminRoles = ['super_admin','municipal_admin','issuer_admin','admin','agency_admin'];
    foreach ($adminRoles as $r) {
        if (function_exists('userIsInRole') && userIsInRole($db, $uid, $r)) {
            return true;
        }
    }

    // Stall -> market_id
    try {
        $stall = $db->fetch("SELECT market_id FROM stalls WHERE stall_id=? LIMIT 1", [$stall_id]);
    } catch (Throwable $e) {
        error_log("stall_photos_endpoint: stall fetch error: ".$e->getMessage());
        return false;
    }
    if (!$stall) return false;
    $market_id = (int)$stall['market_id'];

    // Market manager?
    if (function_exists('userIsInRole') && userIsInRole($db, $uid, 'market_manager')) {
        // Get managed market ids
        try {
            $rows = $db->fetchAll("SELECT market_id FROM market_managers WHERE user_id=?", [$uid]) ?: [];
            $ids = [];
            foreach ($rows as $r) {
                if (!empty($r['market_id'])) $ids[] = (int)$r['market_id'];
            }
            // Fallback to markets.created_by
            if (!$ids) {
                $fallback = $db->fetchAll("SELECT market_id FROM markets WHERE created_by=?", [$uid]) ?: [];
                foreach ($fallback as $f) {
                    if (!empty($f['market_id'])) $ids[] = (int)$f['market_id'];
                }
            }
            if (in_array($market_id, $ids, true)) return true;
        } catch (Throwable $e) {
            error_log("stall_photos_endpoint: market manager check failed: ".$e->getMessage());
        }
    }

    // Inspectors could optionally be allowed (add if desired):
    if (function_exists('userIsInRole') && userIsInRole($db,$uid,'inspector')) {
        // Allow inspectors to view photos
        return true;
    }

    return false;
}

/* ---------------- CSRF Validation ---------------- */

if (!csrf_validate_query()) {
    echo json_encode(['ok' => false, 'error' => 'csrf']);
    exit;
}

/* ---------------- Input Validation ---------------- */

$stall_id = (int)($_GET['stall_id'] ?? 0);
if ($stall_id <= 0) {
    echo json_encode(['ok' => false, 'error' => 'invalid_stall']);
    exit;
}

/* ---------------- Authorization ---------------- */

if (!user_can_access_stall($db, $stall_id)) {
    echo json_encode(['ok' => false, 'error' => 'forbidden']);
    exit;
}

/* ---------------- Fetch Photos ---------------- */

try {
    $photos = $db->fetchAll(
        "SELECT stall_photo_id, file_path
         FROM stall_photos
         WHERE stall_id=?
         ORDER BY uploaded_at DESC",
        [$stall_id]
    ) ?: [];
} catch (Throwable $e) {
    error_log("stall_photos_endpoint DB error: ".$e->getMessage());
    echo json_encode(['ok' => false, 'error' => 'db']);
    exit;
}

/* ---------------- Audit (optional) ---------------- */
try {
    logAudit($db, $_SESSION['user_id'] ?? null, 'View Stall Photos', 'stalls', $stall_id, null, null);
} catch (Throwable $e) {
    // Non-critical
}

/* ---------------- Response ---------------- */
echo json_encode(['ok' => true, 'photos' => $photos]);