<?php
require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/csrf.php';
require_once 'includes/inspector_utils.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

/* -------------------- CSRF Helper Fallbacks -------------------- */
if (!function_exists('csrf_query_param')) {
    function csrf_query_param(): string {
        $keys = ['csrf_token','csrf','token','_csrf'];
        foreach ($keys as $k) {
            if (!empty($_SESSION[$k])) return $k.'='.urlencode($_SESSION[$k]);
        }
        if (function_exists('csrf_token')) {
            $t = csrf_token();
            if ($t) { $_SESSION['csrf_token'] = $t; return 'csrf_token='.urlencode($t); }
        }
        $t = bin2hex(random_bytes(16));
        $_SESSION['csrf_token'] = $t;
        return 'csrf_token='.urlencode($t);
    }
}
if (!function_exists('csrf_validate_query')) {
    function csrf_validate_query(): bool {
        $keys = ['csrf_token','csrf','token','_csrf'];
        foreach ($keys as $k) {
            if (isset($_GET[$k], $_SESSION[$k]) && hash_equals((string)$_SESSION[$k], (string)$_GET[$k])) {
                return true;
            }
        }
        return false;
    }
}
if (!function_exists('formatCurrency')) {
    function formatCurrency($amount): string { return '₱'.number_format((float)$amount,2); }
}
if (!function_exists('getStatusBadge')) {
    function getStatusBadge(string $status): string {
        $status = strtolower($status);
        $map = [
            'available'          => 'bg-green-100 text-green-700',
            'occupied'           => 'bg-blue-100 text-blue-700',
            'reserved'           => 'bg-yellow-100 text-yellow-700',
            'maintenance'        => 'bg-red-100 text-red-700',
            'follow_up_required' => 'bg-amber-100 text-amber-700'
        ];
        $cls = $map[$status] ?? 'bg-gray-100 text-gray-700';
        return "<span class='px-2 py-1 rounded text-xs font-semibold {$cls}'>".htmlspecialchars(ucwords(str_replace('_',' ',$status)))."</span>";
    }
}

/* -------------------- Page Inputs -------------------- */
$page_title   = 'Manage Stalls';
$error        = '';
$success      = '';
$market_filter= isset($_GET['market_id']) ? (int)$_GET['market_id'] : 0;
$status_filter= isset($_GET['status']) ? sanitize($_GET['status']) : 'all';
$floor_filter = isset($_GET['floor']) ? (int)$_GET['floor'] : 0;
$search       = isset($_GET['search']) ? sanitize($_GET['search']) : '';

/* -------------------- Utility Functions -------------------- */
function getManagedMarketIds($db, int $userId): array {
    $ids = [];
    try {
        $rows = $db->fetchAll("SELECT market_id FROM market_managers WHERE user_id=?", [$userId]) ?: [];
        foreach ($rows as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id'];
    } catch (Throwable $e) { error_log("getManagedMarketIds primary: ".$e->getMessage()); }
    if (!$ids) {
        try {
            $rows = $db->fetchAll("SELECT market_id FROM markets WHERE created_by=?", [$userId]) ?: [];
            foreach ($rows as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id'];
        } catch (Throwable $e) { error_log("getManagedMarketIds fallback: ".$e->getMessage()); }
    }
    return array_values(array_unique($ids));
}
function userHasApprovedPermit($db, int $userId): bool {
    try {
        $row = $db->fetch("
            SELECT 1
            FROM user_role_documents d
            JOIN user_roles ur ON d.user_role_id=ur.user_role_id
            JOIN roles r ON ur.role_id=r.role_id
            WHERE ur.user_id=? AND d.doc_type='permit' AND LOWER(d.status)='approved'
            LIMIT 1
        ",[$userId]);
        return (bool)$row;
    } catch(Throwable $e){ error_log("userHasApprovedPermit: ".$e->getMessage()); return false; }
}
function ensure_can_manage_market($db, $market_id=null){
    $uid = $_SESSION['user_id'] ?? null;
    if (!$uid) redirect('login.php');
    $adminRoles = ['super_admin','municipal_admin','issuer_admin','admin','agency_admin'];
    foreach ($adminRoles as $r) if (function_exists('userIsInRole') && userIsInRole($db,$uid,$r)) return;
    if (function_exists('userHasPermission')) {
        try { if (userHasPermission($db,$uid,'manage_markets')) return; } catch(Throwable $e){}
    }
    if (function_exists('userIsInRole') && userIsInRole($db,$uid,'market_manager')) {
        if ($market_id === null) return;
        $managed = getManagedMarketIds($db,$uid);
        if (in_array((int)$market_id,$managed,true)) return;
        http_response_code(403); echo "Forbidden: you do not have permissions for this market."; exit;
    }
    http_response_code(403); echo "Forbidden: insufficient permissions."; exit;
}

/* -------------------- Guard -------------------- */
ensure_can_manage_market($db, $market_filter > 0 ? $market_filter : null);

/* -------------------- Role Flags -------------------- */
$uid              = $_SESSION['user_id'] ?? null;
$isMarketManager  = $uid && function_exists('userIsInRole') && userIsInRole($db,$uid,'market_manager');
$isInspector      = isInspector($db,$uid);
$hasVerifiedPermit= $uid ? userHasApprovedPermit($db,$uid) : false;

$adminRoles = ['super_admin','municipal_admin','issuer_admin','admin','agency_admin'];
$canAddStall = false;
foreach ($adminRoles as $r) if (function_exists('userIsInRole') && userIsInRole($db,$uid,$r)) { $canAddStall=true; break; }
if (!$canAddStall && $isMarketManager) $canAddStall = $hasVerifiedPermit;

/* -------------------- Ensure stall_photos table -------------------- */
try {
    $exists = $db->fetch("SHOW TABLES LIKE 'stall_photos'");
    if (!$exists) {
        $db->query("
            CREATE TABLE stall_photos (
              stall_photo_id INT AUTO_INCREMENT PRIMARY KEY,
              stall_id INT NOT NULL,
              file_path VARCHAR(255) NOT NULL,
              original_name VARCHAR(255),
              uploaded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
              INDEX(stall_id),
              FOREIGN KEY (stall_id) REFERENCES stalls(stall_id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");
    }
} catch(Throwable $e){ error_log("ensure stall_photos: ".$e->getMessage()); }

/* -------------------- ADD Stall -------------------- */
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['add_stall'])) {
    if (!csrf_validate_request()) {
        $error='Invalid CSRF token.';
    } else {
        if (!$canAddStall) {
            $error = $isMarketManager && !$hasVerifiedPermit ? 'Cannot add stall until permit verified.' : 'Insufficient permissions.';
        } else {
            $market_id = (int)$_POST['market_id'];
            ensure_can_manage_market($db,$market_id);
            $stall_number  = sanitize($_POST['stall_number'] ?? '');
            $floor_number  = max(1,(int)($_POST['floor_number'] ?? 1));
            $stall_size    = sanitize($_POST['stall_size'] ?? '');
            $monthly_rent  = $_POST['monthly_rent'] !== '' ? (float)$_POST['monthly_rent'] : 0.0;
            $dimensions    = sanitize($_POST['dimensions'] ?? '');
            $description   = sanitize($_POST['description'] ?? '');

            if (!$error) {
                $dup = $db->fetch("SELECT 1 FROM stalls WHERE market_id=? AND stall_number=? LIMIT 1", [$market_id,$stall_number]);
                if ($dup) $error='Stall number already exists in this market.';
            }

            if (!$error) {
                $ok = $db->query("
                  INSERT INTO stalls
                    (market_id,stall_number,floor_number,stall_size,monthly_rent,dimensions,description,status,created_by)
                  VALUES (?,?,?,?,?,?,?, 'available',?)",
                  [$market_id,$stall_number,$floor_number,$stall_size,$monthly_rent,$dimensions,$description,$uid]
                );
                if ($ok) {
                    $stall_id = (int)$db->lastInsertId();
                    logAudit($db,$uid,'Stall Added','stalls',$stall_id,null,null);
                    if ($isMarketManager) {
                        try { $db->query("INSERT IGNORE INTO market_managers (market_id,user_id) VALUES (?,?)", [$market_id,$uid]); } catch(Throwable $e){}
                    }
                    $success='Stall added successfully!';
                } else {
                    $error='Failed to add stall.';
                }
            }
        }
    }
}

/* -------------------- UPDATE Stall -------------------- */
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['update_stall'])) {
    if (!csrf_validate_request()) {
        $error='Invalid CSRF token.';
    } else {
        $stall_id = (int)($_POST['stall_id'] ?? 0);
        $stall = $db->fetch("SELECT * FROM stalls WHERE stall_id=? LIMIT 1",[$stall_id]);
        if (!$stall) {
            $error='Stall not found.';
        } else {
            ensure_can_manage_market($db,(int)$stall['market_id']);
            $stall_number    = sanitize($_POST['stall_number'] ?? '');
            $floor_number    = max(1,(int)($_POST['floor_number'] ?? 1));
            $stall_size      = sanitize($_POST['stall_size'] ?? '');
            $monthly_rent    = $_POST['monthly_rent'] !== '' ? (float)$_POST['monthly_rent'] : 0.0;
            $status          = sanitize($_POST['status'] ?? 'available');
            $dimensions      = sanitize($_POST['dimensions'] ?? '');
            $description     = sanitize($_POST['description'] ?? '');

            // PREVENT setting status to 'available' if there is an active lease on this stall
            try {
                $activeLeaseCnt = (int)($db->fetch("SELECT COUNT(*) c FROM leases WHERE stall_id=? AND LOWER(TRIM(status))='active'",[$stall_id])['c'] ?? 0);
            } catch (Throwable $e) {
                $activeLeaseCnt = 0;
                error_log("manage_stalls: active lease check failed: ".$e->getMessage());
            }
            if (strtolower($status) === 'available' && $activeLeaseCnt > 0) {
                $error = 'Cannot set status to Available while there is an active lease on this stall.';
            }

            if (!$error) {
                $ok = $db->query("
                  UPDATE stalls
                     SET stall_number=?, floor_number=?, stall_size=?, monthly_rent=?,
                         status=?, dimensions=?, description=?
                   WHERE stall_id=?",
                   [$stall_number,$floor_number,$stall_size,$monthly_rent,$status,$dimensions,$description,$stall_id]
                );
                if ($ok) {
                    logAudit($db,$uid,'Stall Updated','stalls',$stall_id,null,null);
                    $success='Stall updated successfully!';

                    // Inspector auto inspection
                    if ($isInspector) {
                        $triggerStatuses = ['maintenance','follow_up_required','reserved'];
                        if (in_array($status,$triggerStatuses,true)) {
                            $inspection_notes = sanitize($_POST['inspection_notes'] ?? '');
                            $inspectionData = [
                                'stall_id'    => $stall_id,
                                'market_id'   => (int)$stall['market_id'],
                                'inspector_id'=> $uid,
                                'outcome'     => ($status==='maintenance' ? 'major_issue' : 'follow_up_required'),
                                'status'      => 'completed',
                                'notes'       => $inspection_notes ?: ('Status changed to '.$status),
                                'items'       => [],
                                'photos'      => []
                            ];
                            $insId = recordInspection($db,$inspectionData);
                            if ($insId) {
                                logAudit($db,$uid,'Inspection Recorded','inspections',$insId,null,'Auto stall update');
                                $success.=' Inspection recorded.';
                            }
                        }
                    }
                } else {
                    $error='Failed to update stall.';
                }
            }
        }
    }
}

/* -------------------- DELETE Stall -------------------- */
if (isset($_GET['delete']) && $_GET['delete'] !== '') {
    $stall_id = (int)$_GET['delete'];
    $stall    = $db->fetch("SELECT * FROM stalls WHERE stall_id=? LIMIT 1",[$stall_id]);
    if (!$stall) {
        $error='Stall not found.';
    } else {
        ensure_can_manage_market($db,(int)$stall['market_id']);
        $leaseCount = (int)($db->fetch("SELECT COUNT(*) c FROM leases WHERE stall_id=? AND LOWER(TRIM(status))='active'",[$stall_id])['c'] ?? 0);
        if ($leaseCount > 0) {
            // Keep server-side protection (for everyone) to be safe
            $error='Cannot delete stall with active leases.';
        } else {
            if ($db->query("DELETE FROM stalls WHERE stall_id=?",[$stall_id])) {
                $photosDir = __DIR__."/uploads/stalls/{$stall_id}/";
                if (is_dir($photosDir)) {
                    foreach (glob($photosDir.'/*') as $f) if (is_file($f)) @unlink($f);
                    @rmdir($photosDir);
                }
                logAudit($db,$uid,'Stall Deleted','stalls',$stall_id,null,null);
                $success='Stall deleted successfully!';
            } else {
                $error='Failed to delete stall.';
            }
        }
    }
}

/* -------------------- Listing Query -------------------- */
$sql = "SELECT s.*, m.market_name, m.location
        FROM stalls s
        JOIN markets m ON s.market_id=m.market_id
        WHERE 1=1";
$params=[];
if ($isMarketManager) {
    $managed = getManagedMarketIds($db,$uid);
    if (!$managed) {
        $stalls=[];
    } else {
        if ($market_filter>0 && !in_array($market_filter,$managed,true)) {
            $stalls=[];
        } else {
            if ($market_filter>0) {
                $sql.=" AND s.market_id=?"; $params[]=$market_filter;
            } else {
                $ph=implode(',',array_fill(0,count($managed),'?'));
                $sql.=" AND s.market_id IN ($ph)";
                $params=array_merge($params,$managed);
            }
            if ($status_filter!=='all'){ $sql.=" AND s.status=?"; $params[]=$status_filter; }
            if ($floor_filter>0){ $sql.=" AND s.floor_number=?"; $params[]=$floor_filter; }
            if ($search!==''){ $sql.=" AND (s.stall_number LIKE ? OR m.market_name LIKE ?)"; $sp="%{$search}%"; $params[]=$sp; $params[]=$sp; }
            $sql.=" ORDER BY m.market_name, s.floor_number, s.stall_number";
            try { $stalls=$db->fetchAll($sql,$params) ?: []; } catch(Throwable $e){ $stalls=[]; }
        }
    }
} else {
    if ($market_filter>0){ $sql.=" AND s.market_id=?"; $params[]=$market_filter; }
    if ($status_filter!=='all'){ $sql.=" AND s.status=?"; $params[]=$status_filter; }
    if ($floor_filter>0){ $sql.=" AND s.floor_number=?"; $params[]=$floor_filter; }
    if ($search!==''){ $sql.=" AND (s.stall_number LIKE ? OR m.market_name LIKE ?)"; $sp="%{$search}%"; $params[]=$sp; $params[]=$sp; }
    $sql.=" ORDER BY m.market_name, s.floor_number, s.stall_number";
    try { $stalls=$db->fetchAll($sql,$params) ?: []; } catch(Throwable $e){ $stalls=[]; }
}

/* -------------------- Preload active lease counts for stalls on page -------------------- */
$activeLeaseByStall = [];
if (!empty($stalls)) {
    $ids = array_values(array_unique(array_map(fn($s)=>(int)$s['stall_id'], $stalls)));
    if ($ids) {
        $ph = implode(',', array_fill(0, count($ids), '?'));
        try {
            $rows = $db->fetchAll("SELECT stall_id, COUNT(*) AS c FROM leases WHERE stall_id IN ($ph) AND LOWER(TRIM(status))='active' GROUP BY stall_id", $ids) ?: [];
            foreach ($rows as $r) {
                $sid = (int)($r['stall_id'] ?? 0);
                $c   = (int)($r['c'] ?? 0);
                if ($sid) $activeLeaseByStall[$sid] = $c;
            }
        } catch (Throwable $e) {
            error_log("manage_stalls: preload active leases failed: ".$e->getMessage());
        }
    }
}

/* -------------------- Markets Dropdown -------------------- */
try {
    if ($isMarketManager) {
        $managed = getManagedMarketIds($db,$uid);
        if (!$managed) $markets=[];
        else {
            $ph=implode(',',array_fill(0,count($managed),'?'));
            $markets=$db->fetchAll("SELECT * FROM markets WHERE market_id IN ($ph) AND status='active' ORDER BY market_name",$managed) ?: [];
        }
    } else {
        $markets=$db->fetchAll("SELECT * FROM markets WHERE status='active' ORDER BY market_name") ?: [];
    }
} catch(Throwable $e){ $markets=[]; }

/* -------------------- Stats -------------------- */
try {
    if ($isMarketManager) {
        $managed = getManagedMarketIds($db,$uid);
        if (!$managed) {
            $stats=['total'=>0,'available'=>0,'occupied'=>0,'reserved'=>0,'maintenance'=>0];
        } else {
            $params_stats=[];
            if ($market_filter>0 && !in_array($market_filter,$managed,true)) {
                $stats=['total'=>0,'available'=>0,'occupied'=>0,'reserved'=>0,'maintenance'=>0];
            } else {
                if ($market_filter>0){ $where="WHERE market_id=?"; $params_stats[]=$market_filter; }
                else { $ph=implode(',',array_fill(0,count($managed),'?')); $where="WHERE market_id IN ($ph)"; $params_stats=$managed; }
                $stats=$db->fetch("
                    SELECT COUNT(*) total,
                           SUM(CASE WHEN status='available' THEN 1 ELSE 0 END) available,
                           SUM(CASE WHEN status='occupied' THEN 1 ELSE 0 END) occupied,
                           SUM(CASE WHEN status='reserved' THEN 1 ELSE 0 END) reserved,
                           SUM(CASE WHEN status='maintenance' THEN 1 ELSE 0 END) maintenance
                    FROM stalls $where
                ",$params_stats) ?: ['total'=>0,'available'=>0,'occupied'=>0,'reserved'=>0,'maintenance'=>0];
            }
        }
    } else {
        if ($market_filter>0){
            $stats=$db->fetch("
                SELECT COUNT(*) total,
                       SUM(CASE WHEN status='available' THEN 1 ELSE 0 END) available,
                       SUM(CASE WHEN status='occupied' THEN 1 ELSE 0 END) occupied,
                       SUM(CASE WHEN status='reserved' THEN 1 ELSE 0 END) reserved,
                       SUM(CASE WHEN status='maintenance' THEN 1 ELSE 0 END) maintenance
                FROM stalls WHERE market_id=?",[$market_filter]) ?: ['total'=>0,'available'=>0,'occupied'=>0,'reserved'=>0,'maintenance'=>0];
        } else {
            $stats=$db->fetch("
                SELECT COUNT(*) total,
                       SUM(CASE WHEN status='available' THEN 1 ELSE 0 END) available,
                       SUM(CASE WHEN status='occupied' THEN 1 ELSE 0 END) occupied,
                       SUM(CASE WHEN status='reserved' THEN 1 ELSE 0 END) reserved,
                       SUM(CASE WHEN status='maintenance' THEN 1 ELSE 0 END) maintenance
                FROM stalls") ?: ['total'=>0,'available'=>0,'occupied'=>0,'reserved'=>0,'maintenance'=>0];
        }
    }
} catch(Throwable $e){ $stats=['total'=>0,'available'=>0,'occupied'=>0,'reserved'=>0,'maintenance'=>0]; }

require_once 'includes/header.php';
require_once 'includes/admin_sidebar.php';
?>

<section class="max-w-7xl mx-auto p-6">
  <!-- Header -->
  <div class="mb-6 flex flex-col xl:flex-row xl:items-center xl:justify-between gap-4">
    <div>
      <p class="text-gray-600">
        Add, edit, and manage market stalls.
        <?php if ($isMarketManager && !$hasVerifiedPermit): ?>
          <span class="text-red-600 font-medium">Permit not verified. You cannot add stalls.</span>
        <?php endif; ?>
      </p>
    </div>
    <div class="flex gap-2">
      <?php if ($canAddStall): ?>
        <button type="button" class="btn-add-stall bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition flex items-center">
          <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
          Add New Stall
        </button>
      <?php endif; ?>
      <?php if ($isInspector): ?>
        <button type="button" class="btn-inspect-quick bg-yellow-600 text-white px-6 py-3 rounded-lg hover:bg-yellow-700 transition">
          Inspect (Quick)
        </button>
      <?php endif; ?>
    </div>
  </div>

  <!-- Messages -->
  <?php if ($error): ?>
    <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-6"><?php echo htmlspecialchars($error); ?></div>
  <?php endif; ?>
  <?php if ($success): ?>
    <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-6"><?php echo htmlspecialchars($success); ?></div>
  <?php endif; ?>

  <!-- Stats -->
  <div class="grid grid-cols-1 md:grid-cols-5 gap-6 mb-6">
    <div class="bg-white rounded-lg shadow-md p-6"><p class="text-gray-500 text-sm">Total</p><h3 class="text-3xl font-bold"><?php echo (int)$stats['total']; ?></h3></div>
    <div class="bg-white rounded-lg shadow-md p-6"><p class="text-gray-500 text-sm">Available</p><h3 class="text-3xl font-bold text-green-600"><?php echo (int)$stats['available']; ?></h3></div>
    <div class="bg-white rounded-lg shadow-md p-6"><p class="text-gray-500 text-sm">Occupied</p><h3 class="text-3xl font-bold text-blue-600"><?php echo (int)$stats['occupied']; ?></h3></div>
    <div class="bg-white rounded-lg shadow-md p-6"><p class="text-gray-500 text-sm">Reserved</p><h3 class="text-3xl font-bold text-yellow-600"><?php echo (int)$stats['reserved']; ?></h3></div>
    <div class="bg-white rounded-lg shadow-md p-6"><p class="text-gray-500 text-sm">Maintenance</p><h3 class="text-3xl font-bold text-red-600"><?php echo (int)$stats['maintenance']; ?></h3></div>
  </div>

  <!-- Filters -->
  <div class="bg-white rounded-lg shadow-md p-6 mb-6">
    <form method="GET" class="grid grid-cols-1 md:grid-cols-5 gap-4">
      <div>
        <label class="block text-sm font-medium mb-2">Market</label>
        <select name="market_id" class="w-full px-4 py-2 border rounded">
          <option value="0">All Markets</option>
          <?php foreach ($markets as $m): ?>
            <option value="<?php echo (int)$m['market_id']; ?>" <?php echo $market_filter==$m['market_id']?'selected':''; ?>>
              <?php echo htmlspecialchars($m['market_name']); ?>
            </option>
          <?php endforeach; ?>
        </select>
      </div>
      <div>
        <label class="block text-sm font-medium mb-2">Status</label>
        <select name="status" class="w-full px-4 py-2 border rounded">
          <option value="all">All Status</option>
          <option value="available"          <?php echo $status_filter==='available'?'selected':''; ?>>Available</option>
          <option value="occupied"           <?php echo $status_filter==='occupied'?'selected':''; ?>>Occupied</option>
          <option value="reserved"           <?php echo $status_filter==='reserved'?'selected':''; ?>>Reserved</option>
          <option value="maintenance"        <?php echo $status_filter==='maintenance'?'selected':''; ?>>Maintenance</option>
        </select>
      </div>
      <div>
        <label class="block text-sm font-medium mb-2">Floor</label>
        <select name="floor" class="w-full px-4 py-2 border rounded">
          <option value="0">All Floors</option>
          <?php for($i=1;$i<=10;$i++): ?>
            <option value="<?php echo $i; ?>" <?php echo $floor_filter==$i?'selected':''; ?>>Floor <?php echo $i; ?></option>
          <?php endfor; ?>
        </select>
      </div>
      <div>
        <label class="block text-sm font-medium mb-2">Search</label>
        <input type="text" name="search" value="<?php echo htmlspecialchars($search); ?>" class="w-full px-4 py-2 border rounded" placeholder="Stall # / Market">
      </div>
      <div class="flex items-end gap-2">
        <button type="submit" class="px-6 py-2 bg-blue-600 text-white rounded">Filter</button>
        <a href="manage_stalls.php" class="px-6 py-2 bg-gray-300 rounded text-gray-700">Reset</a>
      </div>
    </form>
  </div>

  <!-- Stalls Table -->
  <div class="bg-white rounded-lg shadow-md overflow-hidden">
    <?php if ($stalls): ?>
      <div class="overflow-x-auto">
        <table class="w-full">
          <thead class="bg-gray-50">
            <tr>
              <th class="py-4 px-6 text-left">Stall</th>
              <th class="py-4 px-6 text-left">Market</th>
              <th class="py-4 px-6 text-left">Floor</th>
              <th class="py-4 px-6 text-left">Size</th>
              <th class="py-4 px-6 text-left">Monthly Rent</th>
              <th class="py-4 px-6 text-left">Status</th>
              <th class="py-4 px-6 text-left">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-200">
          <?php foreach ($stalls as $stall): ?>
            <?php
              $thumbs = $db->fetchAll("SELECT file_path FROM stall_photos WHERE stall_id=? ORDER BY uploaded_at DESC LIMIT 3",[(int)$stall['stall_id']]) ?: [];
              $activeCnt = (int)($activeLeaseByStall[(int)$stall['stall_id']] ?? 0);
              // augment stall data for the edit modal
              $stallForModal = $stall;
              $stallForModal['active_lease_count'] = $activeCnt;
            ?>
            <tr class="hover:bg-gray-50">
              <td class="py-4 px-6">
                <p class="font-semibold"><?php echo htmlspecialchars($stall['stall_number']); ?></p>
                <?php if (!empty($stall['dimensions'])): ?>
                  <p class="text-xs text-gray-500"><?php echo htmlspecialchars($stall['dimensions']); ?></p>
                <?php endif; ?>
                <?php if ($thumbs): ?>
                  <div class="flex mt-2 gap-1">
                    <?php foreach ($thumbs as $th): ?>
                      <a href="<?php echo htmlspecialchars($th['file_path']); ?>" target="_blank">
                        <img src="<?php echo htmlspecialchars($th['file_path']); ?>" class="h-10 w-10 object-cover rounded border" alt="">
                      </a>
                    <?php endforeach; ?>
                  </div>
                <?php endif; ?>
              </td>
              <td class="py-4 px-6">
                <p class="font-medium"><?php echo htmlspecialchars($stall['market_name']); ?></p>
                <p class="text-xs text-gray-500"><?php echo htmlspecialchars($stall['location']); ?></p>
              </td>
              <td class="py-4 px-6"><?php echo (int)$stall['floor_number']; ?></td>
              <td class="py-4 px-6">
                <span class="px-2 py-1 rounded text-xs bg-gray-100"><?php echo htmlspecialchars($stall['stall_size']); ?></span>
                <div class="text-xs text-gray-600 mt-1"><?php echo formatCurrency($stall['monthly_rent']); ?></div>
              </td>
              <td class="py-4 px-6"><?php echo getStatusBadge($stall['status']); ?></td>
              <td class="py-4 px-6">
                <div class="flex flex-wrap gap-3 text-sm items-center">
                  <button type="button"
                          class="stall-edit-btn text-blue-600 hover:text-blue-800"
                          data-stall='<?php echo json_encode($stallForModal, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP); ?>'>
                    Edit
                  </button>

                  <?php
                    // Hide Delete if stall is occupied OR (market manager with an active lease on this stall)
                    $canShowDelete = ($stall['status'] !== 'occupied') && !($isMarketManager && $activeCnt > 0);
                  ?>
                  <?php if ($canShowDelete): ?>
                    <button type="button"
                            class="stall-delete-btn text-red-600 hover:text-red-800"
                            data-stall-id="<?php echo (int)$stall['stall_id']; ?>"
                            data-stall-number="<?php echo htmlspecialchars($stall['stall_number']); ?>">
                      Delete
                    </button>
                  <?php endif; ?>

                  <?php if ($isInspector): ?>
                    <button type="button"
                            class="stall-inspect-btn text-yellow-700 hover:text-yellow-900"
                            data-stall='<?php echo json_encode($stall, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP); ?>'>
                      Inspect
                    </button>
                  <?php endif; ?>

                  <?php if ($activeCnt > 0): ?>
                    <span class="text-xs px-2 py-1 rounded bg-blue-100 text-blue-700">Active Lease</span>
                  <?php endif; ?>
                </div>
              </td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    <?php else: ?>
      <div class="text-center py-16">
        <h3 class="text-xl font-semibold text-gray-700 mb-2">No stalls found</h3>
        <p class="text-gray-500 mb-6">
          <?php if ($isMarketManager && !$hasVerifiedPermit): ?>
            Verify your permit to add stalls.
          <?php else: ?>
            Add stalls to get started.
          <?php endif; ?>
        </p>
        <?php if ($canAddStall): ?>
          <button type="button" class="btn-add-stall bg-blue-600 text-white px-6 py-3 rounded hover:bg-blue-700 transition">
            Add New Stall
          </button>
        <?php endif; ?>
      </div>
    <?php endif; ?>
  </div>

  <!-- Add Stall Modal -->
  <div id="addModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
    <div class="bg-white rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto">
      <div class="p-6">
        <div class="flex items-center justify-between mb-6">
          <h3 class="text-2xl font-bold">Add New Stall</h3>
          <button type="button" class="modal-close text-gray-500" data-target="addModal">✕</button>
        </div>
        <?php if (!$canAddStall): ?>
          <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-4 text-sm">
            You cannot add stalls. <?php echo ($isMarketManager && !$hasVerifiedPermit)?'Permit not verified.':'Insufficient permissions.'; ?>
          </div>
        <?php else: ?>
          <form method="POST">
            <?php echo csrf_field(); ?>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label class="block text-sm mb-2">Market *</label>
                <select name="market_id" required class="w-full px-4 py-2 border rounded">
                  <option value="">Select Market</option>
                  <?php foreach ($markets as $m): ?>
                    <option value="<?php echo (int)$m['market_id']; ?>"><?php echo htmlspecialchars($m['market_name']); ?></option>
                  <?php endforeach; ?>
                </select>
              </div>
              <div>
                <label class="block text-sm mb-2">Stall Number *</label>
                <input type="text" name="stall_number" required class="w-full px-4 py-2 border rounded">
              </div>
              <div>
                <label class="block text-sm mb-2">Floor Number *</label>
                <input type="number" name="floor_number" min="1" value="1" required class="w-full px-4 py-2 border rounded">
              </div>
              <div>
                <label class="block text-sm mb-2">Stall Size *</label>
                <select name="stall_size" required class="w-full px-4 py-2 border rounded">
                  <option value="Small">Small</option>
                  <option value="Medium">Medium</option>
                  <option value="Large">Large</option>
                </select>
              </div>
              <div>
                <label class="block text-sm mb-2">Monthly Rent *</label>
                <input type="number" name="monthly_rent" step="0.01" min="0" required class="w-full px-4 py-2 border rounded">
                <p class="text-xs text-gray-500 mt-1">The monthly rent will be applied at the end of the month since the lease duration is monthly.</p>
              </div>
              <div>
                <label class="block text-sm mb-2">Dimensions</label>
                <input type="text" name="dimensions" class="w-full px-4 py-2 border rounded">
              </div>
              <div class="md:col-span-2">
                <label class="block text-sm mb-2">Description</label>
                <textarea name="description" rows="3" class="w-full px-4 py-2 border rounded"></textarea>
              </div>
            </div>
            <div class="flex gap-4 pt-6">
              <button type="submit" name="add_stall" class="flex-1 bg-blue-600 text-white py-3 rounded">Add Stall</button>
              <button type="button" class="modal-close flex-1 bg-gray-300 py-3 rounded" data-target="addModal">Cancel</button>
            </div>
          </form>
        <?php endif; ?>
      </div>
    </div>
  </div>

  <!-- Edit Stall Modal -->
  <div id="editModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
    <div class="bg-white rounded-lg max-w-3xl w-full max-h-[92vh] overflow-y-auto">
      <div class="p-6">
        <div class="flex items-center justify-between mb-6">
          <h3 class="text-2xl font-bold">Edit Stall</h3>
          <button type="button" class="modal-close text-gray-500" data-target="editModal">✕</button>
        </div>
        <form method="POST">
          <?php echo csrf_field(); ?>
          <input type="hidden" name="stall_id" id="edit_stall_id">
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label class="block text-sm mb-2">Stall Number *</label>
              <input type="text" name="stall_number" id="edit_stall_number" required class="w-full px-4 py-2 border rounded">
            </div>
            <div>
              <label class="block text-sm mb-2">Floor Number *</label>
              <input type="number" name="floor_number" id="edit_floor_number" min="1" required class="w-full px-4 py-2 border rounded">
            </div>
            <div>
              <label class="block text-sm mb-2">Stall Size *</label>
              <select name="stall_size" id="edit_stall_size" required class="w-full px-4 py-2 border rounded">
                <option value="Small">Small</option><option value="Medium">Medium</option><option value="Large">Large</option>
              </select>
            </div>
            <div>
              <label class="block text-sm mb-2">Monthly Rent *</label>
              <input type="number" name="monthly_rent" id="edit_monthly_rent" step="0.01" min="0" required class="w-full px-4 py-2 border rounded">
              <p class="text-xs text-gray-500 mt-1">The monthly rent will be applied at the end of the month since the lease duration is monthly.</p>
            </div>
            <div>
              <label class="block text-sm mb-2">Status *</label>
              <select name="status" id="edit_status" class="w-full px-4 py-2 border rounded">
                <option value="available">Available</option><option value="occupied">Occupied</option><option value="maintenance">Maintenance</option>
              </select>
              <p id="edit_status_hint" class="text-xs text-blue-700 mt-1 hidden">Active lease detected. "Available" is disabled.</p>
            </div>
            <div>
              <label class="block text-sm mb-2">Dimensions</label>
              <input type="text" name="dimensions" id="edit_dimensions" class="w-full px-4 py-2 border rounded">
            </div>
            <div class="md:col-span-2">
              <label class="block text-sm mb-2">Description</label>
              <textarea name="description" id="edit_description" rows="3" class="w-full px-4 py-2 border rounded"></textarea>
            </div>
            <?php if ($isInspector): ?>
              <div class="md:col-span-2">
                <label class="block text-sm mb-2">Inspection Notes (optional)</label>
                <textarea name="inspection_notes" id="edit_inspection_notes" rows="3" class="w-full px-4 py-2 border rounded"></textarea>
                <p class="text-xs text-gray-500 mt-1">Maintenance / Reserved / Follow-up auto creates inspection.</p>
              </div>
            <?php endif; ?>
          </div>
          <div class="flex gap-4 pt-6">
            <button type="submit" name="update_stall" class="flex-1 bg-blue-600 text-white py-3 rounded">Save Changes</button>
            <button type="button" class="modal-close flex-1 bg-gray-300 py-3 rounded" data-target="editModal">Cancel</button>
          </div>
        </form>

        <!-- AJAX Photo Management -->
        <div class="mt-8 border-t pt-6">
          <h4 class="text-lg font-semibold mb-2">Photos</h4>
          <p class="text-sm text-gray-600 mb-4">You can upload or delete photos without closing this modal. Max 3 photos total.</p>
          <div id="photoSlotsInfo" class="text-xs text-gray-500 mb-3"></div>
          <div id="edit_photo_gallery" class="mb-4"></div>
          <div class="flex items-center gap-3 mb-4">
            <input type="file" id="photoInput" accept="image/jpeg,image/png" multiple class="border rounded px-3 py-2 text-sm">
            <button type="button" id="btnUploadPhotos" class="bg-blue-600 text-white px-4 py-2 rounded text-sm disabled:opacity-50">
              Upload Selected
            </button>
            <button type="button" id="btnRefreshPhotos" class="bg-gray-200 px-4 py-2 rounded text-sm">
              Refresh
            </button>
          </div>
          <div id="photoStatus" class="text-xs text-gray-600"></div>
        </div>

      </div>
    </div>
  </div>

  <!-- Inspect Modal -->
  <div id="inspectModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
    <div class="bg-white rounded-lg max-w-3xl w-full max-h-[90vh] overflow-y-auto">
      <div class="p-6">
        <div class="flex items-center justify-between mb-4">
          <h3 class="text-2xl font-bold">Create Inspection</h3>
          <button type="button" class="modal-close text-gray-500" data-target="inspectModal">✕</button>
        </div>
        <form id="inspectForm">
          <?php echo csrf_field(); ?>
          <input type="hidden" id="inspect_stall_id" name="stall_id">
          <input type="hidden" id="inspect_market_id" name="market_id">
          <div class="space-y-4">
            <div>
              <label class="block text-sm mb-2">Outcome</label>
              <select id="inspect_outcome" name="outcome" class="w-full px-4 py-2 border rounded">
                <option value="ok">OK</option><option value="minor_issue">Minor Issue</option><option value="major_issue">Major Issue</option>
              </select>
            </div>
            <div>
              <label class="block text-sm mb-2">Notes</label>
              <textarea id="inspect_notes" name="notes" rows="4" class="w-full px-4 py-2 border rounded"></textarea>
            </div>
            <div>
              <label class="block text-sm mb-2">Photos (optional)</label>
              <input type="file" id="inspect_photos" multiple accept="image/*" class="w-full">
              <p class="text-xs text-gray-500 mt-1">Attach photos for documentation.</p>
            </div>
            <div class="flex gap-2">
              <button type="button" class="btn-submit-inspection bg-yellow-600 text-white px-4 py-2 rounded">Create Inspection</button>
              <button type="button" class="modal-close bg-gray-300 px-4 py-2 rounded" data-target="inspectModal">Cancel</button>
            </div>
          </div>
        </form>
        <div id="inspectStatus" class="mt-4 text-sm"></div>
      </div>
    </div>
  </div>
</section>

<script>
(function(){
  const csrfQuery = '<?php echo csrf_query_param(); ?>';

  function qs(id){ return document.getElementById(id); }
  function showModal(id){ const el=qs(id); if(el) el.classList.remove('hidden'); }
  function hideModal(id){ const el=qs(id); if(el) el.classList.add('hidden'); }
  function parseJSONSafe(str){ try { return JSON.parse(str); } catch(e){ return null; } }

  /* ---------------- Photo Management ---------------- */
  let currentStallId = null;

  async function loadPhotos(stallId){
    currentStallId = stallId;
    const gallery = qs('edit_photo_gallery');
    const info    = qs('photoSlotsInfo');
    const status  = qs('photoStatus');
    if (!gallery) return;
    gallery.innerHTML = '<p class="text-xs text-gray-500">Loading photos...</p>';
    info.textContent  = '';
    status.textContent= '';
    try {
      const resp = await fetch('stall_photos_list.php?stall_id='+encodeURIComponent(stallId)+'&'+csrfQuery, {credentials:'same-origin'});
      const data = await resp.json();
      if (!data.ok) {
        gallery.innerHTML = '<p class="text-xs text-red-600">Failed to load photos.</p>';
        return;
      }
      const photos = data.photos || [];
      const remaining = Math.max(0, 3 - photos.length);
      info.textContent = 'Photos: '+photos.length+'/3 • Remaining slots: '+remaining;
      if (!photos.length) {
        gallery.innerHTML = '<p class="text-xs text-gray-500">No photos uploaded yet.</p>';
        return;
      }
      const wrap = document.createElement('div');
      wrap.className='flex flex-wrap gap-3';
      photos.forEach(p=>{
        const item=document.createElement('div');
        item.className='relative group';
        item.innerHTML=`
          <img src="${p.file_path}" class="h-24 w-24 object-cover rounded border" alt="">
          <button type="button"
            class="absolute top-1 right-1 bg-red-600 text-white rounded-full h-6 w-6 flex items-center justify-center text-xs opacity-80 hover:opacity-100"
            data-photo-id="${p.stall_photo_id}"
            title="Delete photo">✕</button>
        `;
        wrap.appendChild(item);
      });
      gallery.innerHTML='';
      gallery.appendChild(wrap);
      qs('btnUploadPhotos').disabled = remaining <= 0;
      qs('photoInput').disabled      = remaining <= 0;
    } catch (e) {
      console.error(e);
      gallery.innerHTML = '<p class="text-xs text-red-600">Error loading photos.</p>';
    }
  }

  async function deletePhoto(photoId){
    if (!currentStallId) return;
    if (!confirm('Delete this photo?')) return;
    const status = qs('photoStatus');
    status.textContent='Deleting photo...';
    try {
      const resp = await fetch('stall_photos_delete.php?stall_photo_id='+encodeURIComponent(photoId)+'&stall_id='+encodeURIComponent(currentStallId)+'&'+csrfQuery, {credentials:'same-origin'});
      const data = await resp.json();
      if (!data.ok) {
        status.textContent='Delete failed: '+(data.error||'Unknown error');
      } else {
        status.textContent='Photo deleted.';
        await loadPhotos(currentStallId);
      }
    } catch(e){
      status.textContent='Delete failed (network).';
    }
  }

  async function uploadSelectedPhotos(){
    if (!currentStallId) return;
    const input = qs('photoInput');
    const status = qs('photoStatus');
    const btn    = qs('btnUploadPhotos');
    if (!input.files.length){
      status.textContent='Select at least one photo.';
      return;
    }
    status.textContent='Uploading '+input.files.length+' photo(s)...';
    btn.disabled=true;

    const form = new FormData();
    form.append('stall_id', currentStallId);
    for (let i=0;i<input.files.length;i++){
      form.append('photos[]', input.files[i]);
    }

    try {
      const resp = await fetch('stall_photos_upload.php?'+csrfQuery, {
        method:'POST',
        credentials:'same-origin',
        body: form
      });
      const data = await resp.json();
      if (!data.ok) {
        status.textContent='Upload failed: '+(data.error||'Unknown error');
      } else {
        status.textContent='Upload successful.';
        input.value='';
        await loadPhotos(currentStallId);
      }
    } catch(e){
      console.error(e);
      status.textContent='Upload failed (network).';
    } finally {
      btn.disabled=false;
    }
  }

  /* ---------------- Inspection Async ---------------- */
  async function submitInspection(){
    const stallId   = qs('inspect_stall_id').value;
    const marketId  = qs('inspect_market_id').value;
    const notes     = qs('inspect_notes').value;
    const outcome   = qs('inspect_outcome').value;
    const files     = qs('inspect_photos').files;
    const statusDiv = qs('inspectStatus');

    if(!stallId || !marketId){ alert('Missing stall or market info.'); return; }

    statusDiv.textContent='Uploading photos...';
    const photoUrls=[];

    for(let i=0;i<files.length;i++){
      const f=files[i];
      const form=new FormData();
      form.append('photo',f);
      try {
        const resp=await fetch('API/upload_inspection_photo.php',{method:'POST',credentials:'same-origin',body:form});
        const json=await resp.json().catch(()=>({ok:false,error:'json'}));
        if(!resp.ok || !json.ok){
          statusDiv.textContent='Photo upload failed: '+(json.error||resp.statusText);
          return;
        }
        photoUrls.push({url:json.url,caption:''});
      } catch(e){
        statusDiv.textContent='Photo upload failed.';
        return;
      }
    }

    statusDiv.textContent='Creating inspection...';
    const payload={stall_id:parseInt(stallId,10),market_id:parseInt(marketId,10),outcome,status:'completed',notes,photos:photoUrls};

    try {
      const r=await fetch('API/inspections.php',{
        method:'POST',
        credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify(payload)
      });
      const j=await r.json().catch(()=>({ok:false,error:'json'}));
      if(r.status===201 && j.ok){
        statusDiv.textContent='Inspection created (ID: '+j.inspection_id+').';
        setTimeout(()=>{ hideModal('inspectModal'); window.location.reload(); },900);
      } else {
        statusDiv.textContent='Failed: '+(j.error||r.statusText);
      }
    } catch(e){
      statusDiv.textContent='Failed (network).';
    }
  }

  /* ---------------- Edit Modal ---------------- */
  function openEditModal(stall){
    currentStallId = stall.stall_id;
    qs('edit_stall_id').value         = stall.stall_id || '';
    qs('edit_stall_number').value     = stall.stall_number || '';
    qs('edit_floor_number').value     = stall.floor_number || 1;
    qs('edit_stall_size').value       = stall.stall_size || 'Small';
    qs('edit_monthly_rent').value     = stall.monthly_rent || 0;
    qs('edit_status').value           = stall.status || 'available';
    qs('edit_dimensions').value       = stall.dimensions || '';
    qs('edit_description').value      = stall.description || '';
    if (qs('edit_inspection_notes')) qs('edit_inspection_notes').value='';

    // Disable "Available" option if active lease exists for this stall
    try {
      const select = qs('edit_status');
      const availableOpt = Array.from(select.options).find(opt => opt.value === 'available');
      const hint = qs('edit_status_hint');
      const activeCount = parseInt(stall.active_lease_count || 0, 10);
      if (availableOpt) {
        if (activeCount > 0) {
          availableOpt.disabled = true;
          availableOpt.textContent = 'Available (disabled: active lease)';
          if (hint) hint.classList.remove('hidden');
          if (select.value === 'available') {
            select.value = 'occupied';
          }
        } else {
          availableOpt.disabled = false;
          availableOpt.textContent = 'Available';
          if (hint) hint.classList.add('hidden');
        }
      }
    } catch(e){}

    showModal('editModal');
    loadPhotos(stall.stall_id);
  }

  function confirmDelete(stallId, stallNumber){
    if(confirm('Delete stall "'+stallNumber+'"? This cannot be undone.')){
      window.location.href='?delete='+stallId;
    }
  }

  /* ---------------- Event Delegation ---------------- */
  document.addEventListener('click', function(e){
    const t=e.target;

    if (t.classList.contains('btn-add-stall')) { showModal('addModal'); return; }

    if (t.classList.contains('btn-inspect-quick')) {
      const f=qs('inspectForm'); if(f) f.reset();
      const sd=qs('inspectStatus'); if(sd) sd.textContent='';
      showModal('inspectModal'); return;
    }

    if (t.classList.contains('stall-edit-btn')) {
      const raw=t.getAttribute('data-stall');
      const obj=parseJSONSafe(raw);
      if(!obj){ alert('Failed to parse stall data'); return; }
      openEditModal(obj); return;
    }

    if (t.classList.contains('stall-delete-btn')) {
      confirmDelete(t.getAttribute('data-stall-id'), t.getAttribute('data-stall-number')); return;
    }

    if (t.classList.contains('stall-inspect-btn')) {
      const raw=t.getAttribute('data-stall');
      const obj=parseJSONSafe(raw);
      if(!obj){ alert('Failed to parse stall data'); return; }
      qs('inspect_stall_id').value  = obj.stall_id || '';
      qs('inspect_market_id').value = obj.market_id || '';
      qs('inspect_notes').value     = '';
      qs('inspect_outcome').value   = 'ok';
      if (qs('inspect_photos')) qs('inspect_photos').value='';
      const statusDiv=qs('inspectStatus'); if(statusDiv) statusDiv.textContent='';
      showModal('inspectModal'); return;
    }

    if (t.classList.contains('modal-close')) {
      hideModal(t.getAttribute('data-target')); return;
    }

    if (t.classList.contains('btn-submit-inspection')) {
      submitInspection(); return;
    }

    if (t.matches('#edit_photo_gallery button[data-photo-id]')) {
      const pid = t.getAttribute('data-photo-id');
      deletePhoto(pid); return;
    }

    if (t.id === 'btnUploadPhotos') {
      uploadSelectedPhotos(); return;
    }

    if (t.id === 'btnRefreshPhotos') {
      if (currentStallId) loadPhotos(currentStallId);
      return;
    }
  });

})();
</script>

<?php include 'includes/footer.php'; ?>