<?php
/**
 * stall_photos_delete.php
 * GET: stall_photo_id, stall_id, csrf token in query.
 * Response: { ok:true } or { ok:false, error:"..." }
 */

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/csrf.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
header('Content-Type: application/json');

if (!function_exists('csrf_validate_query')) {
    function csrf_validate_query(): bool {
        $keys=['csrf_token','csrf','token','_csrf'];
        foreach($keys as $k){
            if(isset($_GET[$k],$_SESSION[$k]) && hash_equals((string)$_SESSION[$k],(string)$_GET[$k])) return true;
        }
        return false;
    }
}
if (!csrf_validate_query()) { echo json_encode(['ok'=>false,'error'=>'csrf']); exit; }

$stall_id      = (int)($_GET['stall_id'] ?? 0);
$stall_photo_id= (int)($_GET['stall_photo_id'] ?? 0);
if ($stall_id <= 0 || $stall_photo_id <= 0) {
    echo json_encode(['ok'=>false,'error'=>'invalid_params']); exit;
}

$uid = $_SESSION['user_id'] ?? 0;
if ($uid <= 0) { echo json_encode(['ok'=>false,'error'=>'auth']); exit; }

/* Auth similar to upload/list */
$can=false;
$adminRoles=['super_admin','municipal_admin','issuer_admin','admin','agency_admin'];
foreach($adminRoles as $r){ if(function_exists('userIsInRole') && userIsInRole($db,$uid,$r)){ $can=true; break; } }
if(!$can && function_exists('userIsInRole') && userIsInRole($db,$uid,'market_manager')){
    $mkt = $db->fetch("SELECT market_id FROM stalls WHERE stall_id=? LIMIT 1",[$stall_id]);
    if($mkt){
        $rows=$db->fetchAll("SELECT market_id FROM market_managers WHERE user_id=?",[$uid]) ?: [];
        $ids=[];
        foreach($rows as $rr){ if(!empty($rr['market_id'])) $ids[]=(int)$rr['market_id']; }
        if(!$ids){
            $fb=$db->fetchAll("SELECT market_id FROM markets WHERE created_by=?",[$uid]) ?: [];
            foreach($fb as $f){ if(!empty($f['market_id'])) $ids[]=(int)$f['market_id']; }
        }
        if(in_array((int)$mkt['market_id'],$ids,true)) $can=true;
    }
}
if(!$can && function_exists('userIsInRole') && userIsInRole($db,$uid,'inspector')) $can=true;
if(!$can){ echo json_encode(['ok'=>false,'error'=>'forbidden']); exit; }

try {
    $photo = $db->fetch("SELECT file_path FROM stall_photos WHERE stall_photo_id=? AND stall_id=? LIMIT 1",
        [$stall_photo_id,$stall_id]);
    if (!$photo) {
        echo json_encode(['ok'=>false,'error'=>'not_found']); exit;
    }
    $full = __DIR__.'/'.$photo['file_path'];
    if (is_file($full)) @unlink($full);
    $db->query("DELETE FROM stall_photos WHERE stall_photo_id=?",[$stall_photo_id]);
    echo json_encode(['ok'=>true]);
} catch(Throwable $e){
    error_log("stall_photos_delete DB error: ".$e->getMessage());
    echo json_encode(['ok'=>false,'error'=>'db']);
}