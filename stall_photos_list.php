<?php
/**
 * stall_photos_list.php
 * Returns JSON list of ALL photos for a stall for lightbox slider.
 * Now permits 'vendor' role to view photos (read-only) in addition to previous roles.
 * Query params: stall_id & csrf token (?stall_id=###&csrf_token=...)
 * Response: { ok: true, photos: [ { stall_photo_id, file_path }, ... ] }
 */

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/csrf.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
header('Content-Type: application/json');

/* Fallback CSRF query validator */
if (!function_exists('csrf_validate_query')) {
    function csrf_validate_query(): bool {
        $keys = ['csrf_token','csrf','token','_csrf'];
        foreach ($keys as $k) {
            if (isset($_GET[$k], $_SESSION[$k]) &&
                is_string($_GET[$k]) && is_string($_SESSION[$k]) &&
                hash_equals($_SESSION[$k], $_GET[$k])) {
                return true;
            }
        }
        return false;
    }
}

if (!csrf_validate_query()) {
    echo json_encode(['ok'=>false,'error'=>'csrf']); exit;
}

$stall_id = (int)($_GET['stall_id'] ?? 0);
if ($stall_id <= 0) {
    echo json_encode(['ok'=>false,'error'=>'invalid_stall']); exit;
}

$uid = $_SESSION['user_id'] ?? 0;
if ($uid <= 0) {
    echo json_encode(['ok'=>false,'error'=>'auth']); exit;
}

/* Authorization:
   Allow: admin roles, market_manager of the stall's market, inspector, vendor (read-only).
*/
$allowed = false;
$adminRoles = ['super_admin','municipal_admin','issuer_admin','admin','agency_admin'];
foreach ($adminRoles as $r) {
    if (function_exists('userIsInRole') && userIsInRole($db,$uid,$r)) { $allowed = true; break; }
}

if (!$allowed && function_exists('userIsInRole') && userIsInRole($db,$uid,'market_manager')) {
    try {
        $mkt = $db->fetch("SELECT market_id FROM stalls WHERE stall_id=? LIMIT 1",[$stall_id]);
        if ($mkt) {
            $rows = $db->fetchAll("SELECT market_id FROM market_managers WHERE user_id=?",[$uid]) ?: [];
            $ids = [];
            foreach ($rows as $wr) if (!empty($wr['market_id'])) $ids[] = (int)$wr['market_id'];
            if (!$ids) {
                $fallback = $db->fetchAll("SELECT market_id FROM markets WHERE created_by=?",[$uid]) ?: [];
                foreach ($fallback as $f) if (!empty($f['market_id'])) $ids[] = (int)$f['market_id'];
            }
            if (in_array((int)$mkt['market_id'],$ids,true)) $allowed = true;
        }
    } catch (Throwable $e) { /* ignore */ }
}

if (!$allowed && function_exists('userIsInRole') && userIsInRole($db,$uid,'inspector')) {
    $allowed = true;
}

/* NEW: Allow vendor role read-only */
if (!$allowed && function_exists('userIsInRole') && userIsInRole($db,$uid,'vendor')) {
    $allowed = true;
}

if (!$allowed) {
    echo json_encode(['ok'=>false,'error'=>'forbidden']); exit;
}

try {
    $photos = $db->fetchAll("
        SELECT stall_photo_id, file_path
        FROM stall_photos
        WHERE stall_id=?
        ORDER BY uploaded_at ASC
    ",[$stall_id]) ?: [];
    echo json_encode(['ok'=>true,'photos'=>$photos]);
} catch (Throwable $e) {
    error_log("stall_photos_list: ".$e->getMessage());
    echo json_encode(['ok'=>false,'error'=>'db']);
}