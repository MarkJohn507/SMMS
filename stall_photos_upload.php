<?php
/**
 * stall_photos_upload.php
 * POST: stall_id, photos[] (JPEG/PNG <=5MB)
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
        foreach ($keys as $k) {
            if (isset($_GET[$k], $_SESSION[$k]) && hash_equals((string)$_SESSION[$k], (string)$_GET[$k])) return true;
        }
        return false;
    }
}
if (!csrf_validate_query()) { echo json_encode(['ok'=>false,'error'=>'csrf']); exit; }

$stall_id = (int)($_POST['stall_id'] ?? 0);
if ($stall_id <= 0) { echo json_encode(['ok'=>false,'error'=>'invalid_stall']); exit; }

$uid = $_SESSION['user_id'] ?? 0;
if ($uid <= 0) { echo json_encode(['ok'=>false,'error'=>'auth']); exit; }

/* Authorization (same logic as list) */
$can=false;
$adminRoles=['super_admin','municipal_admin','issuer_admin','admin','agency_admin'];
foreach($adminRoles as $r){ if(function_exists('userIsInRole') && userIsInRole($db,$uid,$r)){ $can=true; break; } }
if(!$can && function_exists('userIsInRole') && userIsInRole($db,$uid,'market_manager')){
    $mkt = $db->fetch("SELECT market_id FROM stalls WHERE stall_id=? LIMIT 1",[$stall_id]);
    if($mkt){
        $rows=$db->fetchAll("SELECT market_id FROM market_managers WHERE user_id=?",[$uid]) ?: [];
        $ids=[];
        foreach($rows as $r){ if(!empty($r['market_id'])) $ids[]=(int)$r['market_id']; }
        if(!$ids){
            $fb=$db->fetchAll("SELECT market_id FROM markets WHERE created_by=?",[$uid]) ?: [];
            foreach($fb as $f){ if(!empty($f['market_id'])) $ids[]=(int)$f['market_id']; }
        }
        if(in_array((int)$mkt['market_id'],$ids,true)) $can=true;
    }
}
if(!$can && function_exists('userIsInRole') && userIsInRole($db,$uid,'inspector')) $can=true;
if(!$can){ echo json_encode(['ok'=>false,'error'=>'forbidden']); exit; }

/* Existing photos count */
try {
    $existing = $db->fetchAll("SELECT stall_photo_id FROM stall_photos WHERE stall_id=?",[$stall_id]) ?: [];
    $currentCount = count($existing);
} catch(Throwable $e){
    echo json_encode(['ok'=>false,'error'=>'db_existing']); exit;
}

if ($currentCount >= 3) {
    echo json_encode(['ok'=>false,'error'=>'max_photos']); exit;
}

if (empty($_FILES['photos'])) {
    echo json_encode(['ok'=>false,'error'=>'no_files']); exit;
}

$allowed = ['image/jpeg'=>'jpg','image/png'=>'png'];
$errors  = [];
$processed = 0;

foreach ($_FILES['photos']['name'] as $i=>$nm) {
    if ($nm === '') continue;
    if ($currentCount + $processed >= 3) break; // limit
    $err = $_FILES['photos']['error'][$i] ?? UPLOAD_ERR_NO_FILE;
    if ($err !== UPLOAD_ERR_OK) { $errors[]="Photo ".($i+1)." error."; continue; }
    $tmp  = $_FILES['photos']['tmp_name'][$i];
    $size = $_FILES['photos']['size'][$i];
    if ($size > 5*1024*1024) { $errors[]="Photo ".($i+1)." >5MB."; continue; }
    $mime = null;
    try { $finfo=new finfo(FILEINFO_MIME_TYPE); $mime=$finfo->file($tmp); } catch(Throwable $e){}
    if (!$mime || !isset($allowed[$mime])) { $errors[]="Photo ".($i+1)." invalid type."; continue; }
    $ext = $allowed[$mime];

    $dir = __DIR__."/uploads/stalls/{$stall_id}/";
    if (!is_dir($dir)) @mkdir($dir,0755,true);
    $fname = time().'_'.bin2hex(random_bytes(6)).'.'.$ext;
    $dest  = $dir.$fname;
    $rel   = "uploads/stalls/{$stall_id}/".$fname;

    if (!(@move_uploaded_file($tmp,$dest) || @rename($tmp,$dest) || @copy($tmp,$dest))) {
        $errors[]="Photo ".($i+1)." save failed."; continue;
    }
    try {
        $db->query("INSERT INTO stall_photos (stall_id,file_path,original_name) VALUES (?,?,?)",
            [$stall_id,$rel,$nm]);
        $processed++;
    } catch(Throwable $e){
        $errors[]="Photo ".($i+1)." DB insert failed.";
    }
}

if ($processed === 0 && $errors) {
    echo json_encode(['ok'=>false,'error'=>implode('; ',$errors)]); exit;
}

echo json_encode([
    'ok'=>true,
    'uploaded'=>$processed,
    'errors'=>$errors
]);