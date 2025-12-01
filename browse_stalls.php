<?php
/**
 * browse_stalls.php
 *
 * Vendor-only page to browse stalls.
 * - Market managers are blocked and redirected (this page is for vendors only).
 * - Vendors can see ALL stalls (available, occupied, reserved, maintenance).
 * - TABS for Status: All | Available | Occupied | Reserved | Maintenance
 * - Filters: Search, Min/Max Rent, Floor, Has Photos, Sort, Per Page (Market dropdown removed).
 * - Apply enabled only when:
 *     • stall status is 'available'
 *     • vendor documents verified (Permit + ID approved)
 *     • the current vendor has not already applied for this stall (non-cancelled/non-rejected)
 *     • the current vendor did NOT have a terminated lease for this stall (optionally with cooldown).
 * - Side panel loads compact stall details showing "Current applications" (pending)
 *   NOTE: Do NOT display "Current applications" when the selected stall is occupied (hidden client-side).
 * - Re-apply cooldown note: shows per-stall "re-apply on <date> (in N days)" when vendor was terminated.
 * - Adds pagination and better card layout.
 *
 * Fix: Proper toaster notifications for error/success messages.
 * - Consumes and unsets $_SESSION['error_message'] and $_SESSION['success_message'].
 * - Displays toast at top-right, auto-hides, accessible, and can be dismissed.
 * - submit_application.php redirects back here so success/error toasts appear on this page.
 */

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/helpers.php';
require_once 'includes/audit.php';
require_once 'includes/csrf.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

/* Flash messages (consume once) */
$error_message = '';
$success_message = '';
if (!empty($_SESSION['error_message'])) {
    $error_message = (string)$_SESSION['error_message'];
    unset($_SESSION['error_message']);
}
if (!empty($_SESSION['success_message'])) {
    $success_message = (string)$_SESSION['success_message'];
    unset($_SESSION['success_message']);
}

/* Role flags */
$user_id   = isLoggedIn() ? (int)($_SESSION['user_id'] ?? 0) : 0;
$is_vendor = false;
$is_manager= false;

/* Robust role detection */
if (isLoggedIn()) {
    try {
        if (function_exists('userIsInRole')) {
            $is_vendor  = userIsInRole($db, $user_id, 'vendor');
            $is_manager = userIsInRole($db, $user_id, 'market_manager');
        } else {
            $roles = array_map('strtolower', (array)($_SESSION['roles'] ?? []));
            $is_vendor  = in_array('vendor', $roles, true);
            $is_manager = in_array('market_manager', $roles, true);
        }
    } catch (Throwable $e) {
        error_log("browse_stalls role check: ".$e->getMessage());
    }
}

/* Vendor-only guard: market managers must not access this page */
if ($is_manager) {
    header('Location: manage_stalls.php');
    exit;
}

/* Helpers */
if (!function_exists('formatCurrency')) {
    function formatCurrency($amount){ return '₱'.number_format((float)$amount,2); }
}
if (!function_exists('csrf_query_param')) {
    function csrf_query_param(): string {
        $keys=['csrf_token','csrf','token','_csrf'];
        foreach($keys as $k){
            if(!empty($_SESSION[$k])) return $k.'='.urlencode($_SESSION[$k]);
        }
        if(function_exists('csrf_token')){
            $t=csrf_token();
            if($t){ $_SESSION['csrf_token']=$t; return 'csrf_token='.urlencode($t); }
        }
        $t=bin2hex(random_bytes(16));
        $_SESSION['csrf_token']=$t;
        return 'csrf_token='.urlencode($t);
    }
}
if (!function_exists('reapply_cooldown_days')) {
    function reapply_cooldown_days(): int {
        return defined('REAPPLY_AFTER_TERMINATION_DAYS') ? max(0, (int)REAPPLY_AFTER_TERMINATION_DAYS) : 0;
    }
}

/* Verification: require both approved permit and ID (variants) */
$has_verified_permit=false; $has_verified_id=false;
if ($is_vendor) {
    try {
        $rows=$db->fetchAll("
           SELECT d.doc_type,d.status
           FROM user_role_documents d
           JOIN user_roles ur ON d.user_role_id=ur.user_role_id
           JOIN roles r ON ur.role_id=r.role_id
           WHERE ur.user_id=? AND r.name='vendor'
        ",[$user_id]) ?: [];
        foreach($rows as $r){
            $t=strtolower($r['doc_type'] ?? '');
            $s=strtolower($r['status'] ?? '');
            if (in_array($t,['permit','business_permit'], true) && $s==='approved') $has_verified_permit=true;
            if (in_array($t,['id','government_id','gov_id'], true) && $s==='approved') $has_verified_id=true;
        }
    }catch(Throwable $e){ error_log("browse_stalls verify: ".$e->getMessage()); }
}
$vendor_can_apply = $is_vendor && $has_verified_permit && $has_verified_id;

/* Tabs for status */
$allowedTabs = ['all','available','occupied','reserved','maintenance'];
$tab = isset($_GET['tab']) ? strtolower(trim(sanitize($_GET['tab']))) : 'all';
if (!in_array($tab, $allowedTabs, true)) $tab = 'all';

/* Filters (Market dropdown removed) */
$search      = isset($_GET['search']) ? sanitize($_GET['search']) : '';
$min_rent    = isset($_GET['min_rent']) && $_GET['min_rent'] !== '' ? (float)$_GET['min_rent'] : null;
$max_rent    = isset($_GET['max_rent']) && $_GET['max_rent'] !== '' ? (float)$_GET['max_rent'] : null;
$floor_num   = isset($_GET['floor']) ? trim(sanitize($_GET['floor'])) : ''; // '' = all
$has_photos  = isset($_GET['has_photos']) ? 1 : 0;
$sort        = isset($_GET['sort']) ? strtolower(trim(sanitize($_GET['sort']))) : 'market_asc';
$per_page    = isset($_GET['per_page']) ? max(6, min(60, (int)$_GET['per_page'])) : 12;
$page        = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;

/* Allowed sort options */
$allowedSort = [
    'market_asc'  => 'm.market_name ASC, s.floor_number ASC, s.stall_number ASC',
    'market_desc' => 'm.market_name DESC, s.floor_number ASC, s.stall_number ASC',
    'stall_asc'   => 's.stall_number ASC',
    'stall_desc'  => 's.stall_number DESC',
    'rent_asc'    => 's.monthly_rent ASC, m.market_name ASC, s.stall_number ASC',
    'rent_desc'   => 's.monthly_rent DESC, m.market_name ASC, s.stall_number ASC',
    'floor_asc'   => 's.floor_number ASC, m.market_name ASC, s.stall_number ASC',
    'floor_desc'  => 's.floor_number DESC, m.market_name ASC, s.stall_number ASC',
];
if (!isset($allowedSort[$sort])) $sort = 'market_asc';

/* Floors list (for filter) */
try {
    $floorRows = $db->fetchAll("SELECT DISTINCT s.floor_number AS f FROM stalls s WHERE s.floor_number IS NOT NULL ORDER BY s.floor_number") ?: [];
} catch (Throwable $e) { $floorRows = []; }

/* Build filtered counts per status (badges), applying filters */
$counts = array_fill_keys($allowedTabs, 0);
try {
    $countSql = "SELECT LOWER(s.status) AS st, COUNT(*) AS c
                 FROM stalls s
                 JOIN markets m ON s.market_id = m.market_id
                 WHERE 1=1";
    $countParams = [];
    if ($search !== '') {
        $like = "%{$search}%";
        $countSql .= " AND (s.stall_number LIKE ? OR m.market_name LIKE ? OR COALESCE(s.description,'') LIKE ?)";
        array_push($countParams, $like, $like, $like);
    }
    if ($min_rent !== null) {
        $countSql .= " AND s.monthly_rent >= ?";
        $countParams[] = $min_rent;
    }
    if ($max_rent !== null) {
        $countSql .= " AND s.monthly_rent <= ?";
        $countParams[] = $max_rent;
    }
    if ($floor_num !== '' && strcasecmp($floor_num, 'all') !== 0) {
        $countSql .= " AND s.floor_number = ?";
        $countParams[] = $floor_num;
    }
    if ($has_photos) {
        $countSql .= " AND EXISTS (SELECT 1 FROM stall_photos sp WHERE sp.stall_id = s.stall_id)";
    }
    $countSql .= " GROUP BY LOWER(s.status)";
    $rows = $db->fetchAll($countSql, $countParams) ?: [];
    $totalAll = 0;
    foreach ($rows as $r) {
        $st = strtolower((string)($r['st'] ?? ''));
        $c  = (int)($r['c'] ?? 0);
        if (isset($counts[$st])) $counts[$st] = $c;
        $totalAll += $c;
    }
    $counts['all'] = $totalAll;
} catch (Throwable $e) {
    error_log("browse_stalls counts: ".$e->getMessage());
}

/* Pagination calc helper */
function paginate($total, $perPage, $currentPage) {
    $totalPages = max(1, (int)ceil($total / max(1, (int)$perPage)));
    $currentPage = max(1, min($currentPage, $totalPages));
    $offset = ($currentPage - 1) * $perPage;
    return ['totalPages'=>$totalPages, 'currentPage'=>$currentPage, 'offset'=>$offset, 'limit'=>$perPage];
}

/* Build WHERE for main list and total count */
$where = " WHERE 1=1";
$params = [];

if ($tab !== 'all') {
    $where .= " AND s.status = ?";
    $params[] = $tab;
}
if ($search !== '') {
    $like = "%{$search}%";
    $where .= " AND (s.stall_number LIKE ? OR m.market_name LIKE ? OR COALESCE(s.description,'') LIKE ?)";
    array_push($params, $like, $like, $like);
}
if ($min_rent !== null) {
    $where .= " AND s.monthly_rent >= ?";
    $params[] = $min_rent;
}
if ($max_rent !== null) {
    $where .= " AND s.monthly_rent <= ?";
    $params[] = $max_rent;
}
if ($floor_num !== '' && strcasecmp($floor_num, 'all') !== 0) {
    $where .= " AND s.floor_number = ?";
    $params[] = $floor_num;
}
if ($has_photos) {
    $where .= " AND EXISTS (SELECT 1 FROM stall_photos sp WHERE sp.stall_id = s.stall_id)";
}

/* Total for pagination */
try {
    $totalRow = $db->fetch("SELECT COUNT(*) AS cnt
                            FROM stalls s
                            JOIN markets m ON s.market_id = m.market_id
                            $where", $params) ?: ['cnt'=>0];
} catch (Throwable $e) {
    error_log("browse_stalls total count: ".$e->getMessage());
    $totalRow = ['cnt'=>0];
}
$total = (int)($totalRow['cnt'] ?? 0);
$pager = paginate($total, $per_page, $page);

/* Main list query */
$orderBy = $allowedSort[$sort];
$listSql="SELECT s.*, m.market_name
          FROM stalls s
          JOIN markets m ON s.market_id=m.market_id
          $where
          ORDER BY $orderBy
          LIMIT ? OFFSET ?";
$listParams = array_merge($params, [(int)$pager['limit'], (int)$pager['offset']]);
try { $stalls=$db->fetchAll($listSql,$listParams) ?: []; } catch(Throwable $e){ error_log("browse_stalls query: ".$e->getMessage()); $stalls=[]; }

/* Preload up to 3 photos per stall in the page */
$photosByStall=[];
if($stalls){
    $ids=array_values(array_filter(array_map(fn($s)=>(int)$s['stall_id'],$stalls), fn($x)=>$x>0));
    if ($ids) {
        $ph=implode(',',array_fill(0,count($ids),'?'));
        try{
            $photoRows=$db->fetchAll("
                SELECT stall_id,file_path
                FROM stall_photos
                WHERE stall_id IN ($ph)
                ORDER BY uploaded_at ASC
            ",$ids) ?: [];
            foreach($photoRows as $p){
                $sid=(int)$p['stall_id'];
                if(!isset($photosByStall[$sid])) $photosByStall[$sid]=[];
                if(count($photosByStall[$sid])<3 && !empty($p['file_path'])) $photosByStall[$sid][]=$p['file_path'];
            }
        }catch(Throwable $e){ error_log("photo preload: ".$e->getMessage()); }
    }
}

/* Duplicate guard list: ONLY current vendor's non-cancelled/non-rejected applications */
$vendorAppliedStalls = [];
if ($is_vendor && $user_id) {
    try {
        $apps = $db->fetchAll("
            SELECT stall_id
            FROM applications
            WHERE vendor_id = ?
              AND LOWER(TRIM(status)) NOT IN ('cancelled','rejected')
        ", [$user_id]) ?: [];
        foreach ($apps as $a) {
            if (!empty($a['stall_id'])) $vendorAppliedStalls[(int)$a['stall_id']] = true;
        }
    } catch (Throwable $e) {
        error_log("browse_stalls preload vendor applications: ".$e->getMessage());
    }
}

/* Block re-apply after terminated lease (optional cooldown via REAPPLY_AFTER_TERMINATION_DAYS) */
$blockedReapplyStalls = [];
$reapplyInfoByStall   = []; // sid => ['allowed_on' => 'YYYY-MM-DD', 'days_left' => int]
if ($is_vendor && $user_id) {
    $cooldown = reapply_cooldown_days();
    $hasTerminatedAt = false;
    $hasUpdatedAt    = false;
    $hasEndDate      = false;
    try {
        $cols = $db->fetchAll("SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'leases'") ?: [];
        $colNames = array_map(fn($c)=>strtolower($c['column_name'] ?? ''), $cols);
        $hasTerminatedAt = in_array('terminated_at', $colNames, true);
        $hasUpdatedAt    = in_array('updated_at', $colNames, true);
        $hasEndDate      = in_array('lease_end_date', $colNames, true);
    } catch (Throwable $e) {
        error_log("browse_stalls: leases column detection failed: ".$e->getMessage());
    }
    $termParts = [];
    if ($hasTerminatedAt) $termParts[] = "NULLIF(l.terminated_at,'0000-00-00')";
    if ($hasUpdatedAt)    $termParts[] = "NULLIF(l.updated_at,'0000-00-00 00:00:00')";
    if ($hasEndDate)      $termParts[] = "NULLIF(l.lease_end_date,'0000-00-00')";
    $termExpr = $termParts ? ("DATE(COALESCE(" . implode(',', $termParts) . "))") : "NULL";

    try {
        $rows = $db->fetchAll("
            SELECT 
              l.stall_id,
              {$termExpr} AS term_date
            FROM leases l
            WHERE l.vendor_id = ?
              AND LOWER(TRIM(l.status)) = 'terminated'
              AND l.stall_id IS NOT NULL
        ", [$user_id]) ?: [];

        $todayTs = strtotime(date('Y-m-d'));

        foreach ($rows as $r) {
            $sid = (int)($r['stall_id'] ?? 0);
            if ($sid <= 0) continue;

            if ($cooldown === 0) {
                $blockedReapplyStalls[$sid] = true;
                $reapplyInfoByStall[$sid] = ['allowed_on' => null, 'days_left' => null];
                continue;
            }

            $term = !empty($r['term_date']) ? $r['term_date'] : null;
            if (!$term) {
                $blockedReapplyStalls[$sid] = true;
                $reapplyInfoByStall[$sid] = ['allowed_on' => null, 'days_left' => null];
                continue;
            }

            $allowTs = strtotime($term . " +{$cooldown} days");
            $daysLeft = (int)ceil(($allowTs - $todayTs) / 86400);

            if ($daysLeft > 0) {
                $blockedReapplyStalls[$sid] = true;
                $reapplyInfoByStall[$sid] = [
                    'allowed_on' => date('Y-m-d', $allowTs),
                    'days_left' => $daysLeft
                ];
            }
        }
    } catch (Throwable $e) {
        error_log("browse_stalls terminated leases check failed: " . $e->getMessage());
    }
}

require_once 'includes/header.php';
require_once 'includes/vendor_sidebar.php';
$csrfQuery = csrf_query_param();

/* Build tab URLs preserving filters */
$preserve = [
    'search'    => ($search !== '') ? $search : null,
    'min_rent'  => ($min_rent !== null) ? $min_rent : null,
    'max_rent'  => ($max_rent !== null) ? $max_rent : null,
    'floor'     => ($floor_num !== '' ? $floor_num : null),
    'has_photos'=> $has_photos ? 1 : null,
    'sort'      => $sort,
    'per_page'  => $per_page
];
$preserve = array_filter($preserve, fn($v)=>$v!==null && $v!=='');
function tab_url(array $preserve, string $tab): string {
    return 'browse_stalls.php?' . http_build_query(array_merge($preserve, ['tab'=>$tab]));
}
?>
<style>
/* Compact filter controls */
.filter-label { font-size: 12px; line-height: 1; margin-bottom: 4px; color: #374151; }
.filter-control { padding: 6px 8px; font-size: 13px; height: 34px; border: 1px solid #d1d5db; border-radius: 6px; width: 100%; }
.filter-checkbox { width: 16px; height: 16px; }
.small-btn { padding: 8px 12px; font-size: 13px; border-radius: 6px; }

/* Toast container & toasts */
#toastContainer {
  position: fixed;
  top: 16px;
  right: 16px;
  z-index: 100;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.toast {
  min-width: 260px;
  max-width: 420px;
  background: #ffffff;
  border-radius: 10px;
  box-shadow: 0 8px 20px rgba(0,0,0,.15);
  border: 1px solid #e5e7eb;
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 10px 12px;
  font-size: 14px;
}
.toast-success { border-color: #bbf7d0; background: #ecfdf5; color: #065f46; }
.toast-error   { border-color: #fecaca; background: #fef2f2; color: #7f1d1d; }
.toast .icon {
  width: 20px; height: 20px; border-radius: 50%; display:flex; align-items:center; justify-content:center; flex-shrink:0;
  font-size: 12px; color:#fff;
}
.toast-success .icon { background:#16a34a; }
.toast-error   .icon { background:#ef4444; }
.toast .close {
  margin-left: auto;
  background: transparent;
  border: none;
  color: inherit;
  cursor: pointer;
  font-size: 16px;
  line-height: 1;
}
.toast .msg { margin-top: 2px; }

/* Side Details Panel */
#stallSidePanel {
  position: fixed; top: 0; right: 0; height: 100vh; width: 420px; max-width: 100%;
  background: #ffffff; box-shadow: -2px 0 12px rgba(0,0,0,.15);
  transform: translateX(100%); transition: transform .35s ease; z-index: 60; display: flex; flex-direction: column;
}
#stallSidePanel.open { transform: translateX(0); }
#stallSidePanelHeader {
  padding: 12px 16px; border-bottom: 1px solid #e5e7eb;
  display: flex; justify-content: space-between; align-items: center;
}
#stallSidePanelContent { padding: 12px 16px 24px; overflow-y: auto; flex: 1; }
#stallSidePanel .close-btn {
  background: #f3f4f6; border: none; padding: 8px 10px; border-radius: 8px; cursor: pointer; font-size: 13px;
  display:flex; align-items:center; gap:6px;
}
#stallSidePanel .close-btn:hover { background:#e5e7eb; }
.side-loading { animation: pulse 1.5s infinite; background:#f3f4f6; height:14px; border-radius:4px; }
@keyframes pulse { 0% { opacity:.6; } 50% { opacity:1; } 100% { opacity:.6; } }

/* Photo Lightbox */
#photoLightbox { display:none; }
#photoLightbox.open { display:flex; }
#photoLightbox .nav-btn {
  position:absolute; top:50%; transform:translateY(-50%);
  background:rgba(255,255,255,.9); color:#111827; padding:8px 10px; border-radius:8px; font-size:14px;
}
#photoLightbox .prev { left:16px; }
#photoLightbox .next { right:16px; }
#photoLightbox .counter {
  position:absolute; bottom:16px; left:50%; transform:translateX(-50%);
  background:rgba(255,255,255,.9); color:#111827; padding:4px 8px; border-radius:6px; font-size:12px;
}
</style>

<!-- Toast container (messages injected by JS below) -->
<div id="toastContainer" aria-live="polite" aria-atomic="true"></div>

<section class="max-w-7xl mx-auto p-6">
  <!-- Status Tabs -->
  <div class="mb-4 flex flex-wrap gap-2">
    <?php
      $tabLabels = [
        'all' => 'All',
        'available' => 'Available',
        'occupied' => 'Occupied',
        'reserved' => 'Reserved',
        'maintenance' => 'Maintenance',
      ];
      foreach ($tabLabels as $key=>$label):
        $active = ($tab === $key);
        $badgeCount = (int)($counts[$key] ?? 0);
        $url = htmlspecialchars(tab_url($preserve, $key));
    ?>
      <a href="<?php echo $url; ?>"
         class="px-4 py-2 rounded font-medium transition <?php echo $active?'bg-green-600 text-white':'bg-gray-100 text-gray-800 hover:bg-gray-200'; ?>">
        <?php echo htmlspecialchars($label); ?>
        <span class="ml-2 text-xs px-2 py-0.5 rounded-full <?php echo $active?'bg-white text-blue-700':'bg-gray-200 text-gray-800'; ?>">
          <?php echo $badgeCount; ?>
        </span>
      </a>
    <?php endforeach; ?>
  </div>

  <!-- Filters (compact) -->
  <div class="bg-white rounded shadow p-3 mb-6">
    <form method="GET" class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-2 items-end">
      <input type="hidden" name="tab" value="<?php echo htmlspecialchars($tab); ?>">

      <div class="lg:col-span-2">
        <label class="filter-label">Search</label>
        <input type="text" name="search" value="<?php echo htmlspecialchars($search); ?>"
               class="filter-control" placeholder="Stall #, market, description">
      </div>

      <div>
        <label class="filter-label">Min Rent (₱)</label>
        <input type="number" step="0.01" min="0" name="min_rent" value="<?php echo htmlspecialchars($min_rent ?? ''); ?>"
               class="filter-control">
      </div>
      <div>
        <label class="filter-label">Max Rent (₱)</label>
        <input type="number" step="0.01" min="0" name="max_rent" value="<?php echo htmlspecialchars($max_rent ?? ''); ?>"
               class="filter-control">
      </div>

      <div>
        <label class="filter-label">Floor</label>
        <select name="floor" class="filter-control">
          <option value="">All floors</option>
          <?php foreach ($floorRows as $fr): ?>
            <?php $f = $fr['f']; ?>
            <option value="<?php echo htmlspecialchars($f); ?>" <?php echo ($floor_num!=='' && (string)$floor_num===(string)$f)?'selected':''; ?>>
              <?php echo htmlspecialchars($f); ?>
            </option>
          <?php endforeach; ?>
        </select>
      </div>

      <div class="flex items-center gap-2">
        <input type="checkbox" id="has_photos" name="has_photos" value="1" class="filter-checkbox" <?php echo $has_photos ? 'checked' : ''; ?>>
        <label for="has_photos" class="text-sm">Has photos</label>
      </div>

      <div>
        <label class="filter-label">Sort</label>
        <select name="sort" class="filter-control">
          <option value="market_asc"  <?php echo $sort==='market_asc'?'selected':''; ?>>Market (A→Z)</option>
          <option value="market_desc" <?php echo $sort==='market_desc'?'selected':''; ?>>Market (Z→A)</option>
          <option value="stall_asc"   <?php echo $sort==='stall_asc'?'selected':''; ?>>Stall # (Asc)</option>
          <option value="stall_desc"  <?php echo $sort==='stall_desc'?'selected':''; ?>>Stall # (Desc)</option>
          <option value="rent_asc"    <?php echo $sort==='rent_asc'?'selected':''; ?>>Rent (Low→High)</option>
          <option value="rent_desc"   <?php echo $sort==='rent_desc'?'selected':''; ?>>Rent (High→Low)</option>
          <option value="floor_asc"   <?php echo $sort==='floor_asc'?'selected':''; ?>>Floor (Asc)</option>
          <option value="floor_desc"  <?php echo $sort==='floor_desc'?'selected':''; ?>>Floor (Desc)</option>
        </select>
      </div>

      <div>
        <label class="filter-label">Per Page</label>
        <select name="per_page" class="filter-control">
          <?php foreach ([6,12,18,24,36,48,60] as $pp): ?>
            <option value="<?php echo $pp; ?>" <?php echo $per_page===$pp?'selected':''; ?>><?php echo $pp; ?></option>
          <?php endforeach; ?>
        </select>
      </div>

      <div class="lg:col-span-2 flex gap-2 items-end">
        <button class="small-btn bg-green-600 text-white">Apply Filters</button>
        <a href="browse_stalls.php?tab=<?php echo htmlspecialchars($tab); ?>" class="small-btn bg-gray-200 text-gray-800">Reset</a>
      </div>
    </form>
  </div>

  <!-- Stall Grid -->
  <?php if($stalls): ?>
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      <?php foreach($stalls as $s): ?>
        <?php
          $sid=(int)$s['stall_id'];
          $status=strtolower((string)($s['status'] ?? ''));
          $thumbs=$photosByStall[$sid] ?? [];
          $alreadyAppliedByMe = !empty($vendorAppliedStalls[$sid]); // ONLY current vendor
          $blockedByTermination = !empty($blockedReapplyStalls[$sid]); // block if vendor had terminated lease here (within cooldown or forever)
          $applyEnabled = $vendor_can_apply && $status==='available' && !$alreadyAppliedByMe && !$blockedByTermination;

          $info = $reapplyInfoByStall[$sid] ?? null;

          $applyTooltipBase = !isLoggedIn() ? 'Login to apply'
                           : (!$vendor_can_apply ? 'Verify Permit & ID in Settings'
                           : ($status!=='available' ? 'Stall not available'
                           : ($alreadyAppliedByMe ? 'You already submitted an application for this stall'
                           : ($blockedByTermination
                              ? ('You cannot re-apply to this stall after a terminated lease'
                                 . ($info && $info['allowed_on']
                                    ? " • re-apply on {$info['allowed_on']} (in {$info['days_left']} day" . ($info['days_left']===1?'':'s') . ")"
                                    : (reapply_cooldown_days() > 0
                                        ? (function(){
                                            $cd = reapply_cooldown_days();
                                            return " • cooldown {$cd} day" . ($cd===1?'':'s');
                                          })()
                                        : ''
                                      )
                                   )
                                )
                              : 'Apply to this stall'))));
          $applyTooltip = $applyTooltipBase;

          $rent = isset($s['monthly_rent']) ? formatCurrency($s['monthly_rent']) : '—';
          $size = trim((string)($s['stall_size'] ?? ''));
          $dims = trim((string)($s['dimensions'] ?? ''));
          $desc = trim((string)($s['description'] ?? ''));
        ?>
        <div class="bg-white rounded shadow p-4 flex flex-col">
          <!-- Photos -->
          <?php if($thumbs): ?>
            <div class="mb-3 flex gap-2">
              <?php foreach($thumbs as $idx => $p): ?>
                <button type="button"
                        class="thumb-btn"
                        data-stall="<?php echo $sid; ?>"
                        data-index="<?php echo (int)$idx; ?>"
                        data-full="<?php echo htmlspecialchars($p); ?>"
                        aria-label="View photo"
                        title="View photo">
                  <img src="<?php echo htmlspecialchars($p); ?>"
                       loading="lazy"
                       class="h-16 w-16 object-cover rounded border"
                       alt="Stall Photo">
                </button>
              <?php endforeach; ?>
            </div>
          <?php else: ?>
            <div class="mb-3 h-16 flex items-center justify-center rounded bg-gray-50 text-xs text-gray-500 border">No photos</div>
          <?php endif; ?>

          <!-- Header -->
          <div class="flex items-start justify-between mb-2">
            <div>
              <h3 class="font-semibold text-gray-800">Stall <?php echo htmlspecialchars($s['stall_number']); ?></h3>
              <p class="text-xs text-gray-500">
                <?php echo htmlspecialchars($s['market_name']); ?>
                <?php if (!empty($s['floor_number'])): ?> • Floor <?php echo (int)$s['floor_number']; ?><?php endif; ?>
              </p>
            </div>
            <div class="text-right">
              <p class="text-sm font-semibold text-gray-700"><?php echo $rent; ?>/mo</p>
              <span class="inline-block mt-1 px-2 py-1 rounded text-xs
                <?php
                  echo match($status){
                      'available' => 'bg-green-100 text-green-700',
                      'occupied'  => 'bg-blue-100 text-blue-700',
                      'reserved'  => 'bg-yellow-100 text-yellow-700',
                      'maintenance' => 'bg-red-100 text-red-700',
                      default => 'bg-gray-100 text-gray-600',
                  };
                ?>">
                <?php echo ucfirst(str_replace('_',' ',$status)); ?>
              </span>
            </div>
          </div>

          <!-- Body -->
          <div class="text-sm text-gray-700 mb-3 space-y-1">
            <?php if ($size !== ''): ?>
              <div><span class="text-gray-500">Size:</span> <?php echo htmlspecialchars($size); ?></div>
            <?php endif; ?>
            <?php if ($dims !== ''): ?>
              <div><span class="text-gray-500">Dimensions:</span> <?php echo htmlspecialchars($dims); ?></div>
            <?php endif; ?>
            <?php if ($desc !== ''): ?>
              <div class="text-xs text-gray-500 leading-relaxed"><?php echo htmlspecialchars($desc); ?></div>
            <?php endif; ?>
          </div>

          <!-- Actions -->
          <div class="mt-auto flex flex-col gap-2">
            <div class="flex gap-2">
              <?php if($is_vendor): ?>
                <?php if($applyEnabled): ?>
                  <button type="button" title="<?php echo htmlspecialchars($applyTooltip); ?>" onclick="openApplyModal(<?php echo $sid; ?>,'<?php echo htmlspecialchars(addslashes($s['stall_number'])); ?>')" class="bg-green-600 text-white px-3 py-2 rounded text-sm">Apply</button>
                <?php else: ?>
                  <button type="button" disabled title="<?php echo htmlspecialchars($applyTooltip); ?>" class="bg-gray-300 text-gray-600 px-3 py-2 rounded text-sm cursor-not-allowed">Apply</button>
                <?php endif; ?>
              <?php else: ?>
                <a href="login.php" title="<?php echo htmlspecialchars($applyTooltip); ?>" class="bg-gray-300 text-gray-700 px-3 py-2 rounded text-sm">Login</a>
              <?php endif; ?>

              <button
                type="button"
                class="px-3 py-2 bg-gray-100 rounded text-sm hover:bg-gray-200"
                onclick="loadStallSidePanel(<?php echo $sid; ?>,'<?php echo htmlspecialchars(addslashes($s['stall_number'])); ?>','<?php echo htmlspecialchars($status, ENT_QUOTES); ?>')"
              >Details</button>
            </div>

            <?php if($is_vendor && !$vendor_can_apply): ?>
              <p class="text-[11px] text-amber-700">
                Verification required (Permit + ID) to apply. <a href="settings.php" class="underline">Verify now</a>.
              </p>
            <?php elseif($is_vendor && $alreadyAppliedByMe): ?>
              <p class="text-[11px] text-gray-600">
                You already submitted an application for this stall.
              </p>
            <?php elseif($is_vendor && $blockedByTermination): ?>
              <p class="text-[11px] text-red-700">
                You cannot re-apply to this stall after your lease was terminated
                <?php if (!empty($info['allowed_on'])): ?>
                  — re-apply on <?php echo htmlspecialchars($info['allowed_on']); ?>
                  (in <?php echo (int)$info['days_left']; ?> day<?php echo $info['days_left']===1?'':'s'; ?>).
                <?php else: ?>
                  <?php
                    $cd = reapply_cooldown_days();
                    if ($cd > 0) {
                      echo " — cooldown: {$cd} day" . ($cd===1 ? '' : 's') . ".";
                    } else {
                      echo ".";
                    }
                  ?>
                <?php endif; ?>
              </p>
            <?php endif; ?>
          </div>
        </div>
      <?php endforeach; ?>
    </div>

    <!-- Pagination -->
    <div class="mt-6 flex items-center justify-between">
      <div class="text-sm text-gray-600">
        Page <?php echo $pager['currentPage']; ?> of <?php echo $pager['totalPages']; ?> — <?php echo $total; ?> stalls
      </div>
      <div class="space-x-2">
        <?php
          // Preserve filters while paging
          $baseParams = [
            'tab'        => $tab,
            'search'     => $search !== '' ? $search : null,
            'min_rent'   => $min_rent !== null ? $min_rent : null,
            'max_rent'   => $max_rent !== null ? $max_rent : null,
            'floor'      => $floor_num !== '' ? $floor_num : null,
            'has_photos' => $has_photos ? 1 : null,
            'sort'       => $sort,
            'per_page'   => $per_page,
          ];
            $baseParams = array_filter($baseParams, fn($v)=>$v!==null && $v!=='');
            $base = 'browse_stalls.php?' . http_build_query($baseParams);
        ?>
        <?php if ($pager['currentPage'] > 1): ?>
          <a class="px-3 py-1 bg-gray-200 rounded" href="<?php echo $base . '&page=1'; ?>">First</a>
          <a class="px-3 py-1 bg-gray-200 rounded" href="<?php echo $base . '&page=' . ($pager['currentPage'] - 1); ?>">Prev</a>
        <?php endif; ?>
        <?php
          $startPg = max(1, $pager['currentPage'] - 2);
          $endPg   = min($pager['totalPages'], $pager['currentPage'] + 2);
          for ($pg = $startPg; $pg <= $endPg; $pg++):
        ?>
          <a class="px-3 py-1 <?php echo ($pg == $pager['currentPage']) ? 'bg-green-600 text-white rounded' : 'bg-gray-100 rounded'; ?>"
             href="<?php echo $base . '&page=' . $pg; ?>"><?php echo $pg; ?></a>
        <?php endfor; ?>
        <?php if ($pager['currentPage'] < $pager['totalPages']): ?>
          <a class="px-3 py-1 bg-gray-200 rounded" href="<?php echo $base . '&page=' . ($pager['currentPage'] + 1); ?>">Next</a>
          <a class="px-3 py-1 bg-gray-200 rounded" href="<?php echo $base . '&page=' . $pager['totalPages']; ?>">Last</a>
        <?php endif; ?>
      </div>
    </div>
  <?php else: ?>
    <div class="bg-white rounded shadow p-8 text-center text-gray-500">No stalls found.</div>
  <?php endif; ?>
</section>

<!-- Side Panel -->
<div id="stallSidePanel" aria-hidden="true" aria-label="Stall details panel">
  <div id="stallSidePanelHeader">
    <h2 id="stallSidePanelTitle" class="font-semibold text-gray-800 text-sm truncate">Stall Details</h2>
    <button class="close-btn" type="button" onclick="closeStallSidePanel()">
      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
      </svg>
      Close
    </button>
  </div>
  <div id="stallSidePanelContent">
    <div class="space-y-3">
      <div class="side-loading w-2/3"></div>
      <div class="side-loading w-1/2"></div>
      <div class="side-loading w-full h-24"></div>
    </div>
    <div id="stallSidePanelError" class="hidden text-sm text-red-600 mt-2"></div>
    <div id="stallSidePanelBody" class="hidden"></div>
  </div>
</div>

<!-- Photo Lightbox -->
<div id="photoLightbox" class="fixed inset-0 bg-black/80 z-50 items-center justify-center p-4">
  <button type="button" aria-label="Prev" title="Prev" class="nav-btn prev" onclick="lightboxPrev()">&larr;</button>
  <button type="button" aria-label="Next" title="Next" class="nav-btn next" onclick="lightboxNext()">&rarr;</button>
  <div class="counter" id="lightboxCounter">1 / 1</div>
  <button type="button" aria-label="Close" title="Close"
          onclick="closeLightbox()"
          class="absolute top-4 right-4 bg-white/90 hover:bg-white text-gray-800 px-3 py-1 rounded text-sm">Close</button>
  <a id="lightboxLink" href="#" target="_blank" rel="noopener" title="Open full size">
    <img id="lightboxImg" src="" alt="Stall Photo" class="max-h-[85vh] max-w-full rounded shadow-lg">
  </a>
</div>

<!-- Apply Modal -->
<div id="applyModal" class="hidden fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
  <div class="bg-white rounded max-w-lg w-full p-6">
    <div class="flex items-center justify-between mb-4">
      <h3 class="text-xl font-semibold">Apply for Stall</h3>
      <button type="button" onclick="closeApplyModal()" class="text-gray-500">✕</button>
    </div>
    <form method="POST" action="submit_application.php">
      <?php echo csrf_field(); ?>
      <input type="hidden" name="stall_id" id="apply_stall_id">
      <div class="mb-3">
        <label class="block text-sm">Business Name *</label>
        <input name="business_name" id="apply_business_name" required class="w-full border px-3 py-2">
      </div>
      <div class="mb-3">
        <label class="block text-sm">Business Type *</label>
        <input name="business_type" id="apply_business_type" required class="w-full border px-3 py-2">
      </div>
      <div class="mb-3">
        <label class="block text-sm">Preferred Start Date (optional)</label>
        <input type="date" name="preferred_start_date" id="apply_preferred_start_date" class="w-full px-3 py-2 border rounded">
        <p class="text-xs text-gray-500 mt-1">You may propose a preferred date; final lease start date set by admin.</p>
      </div>
      <div class="flex gap-2">
        <button class="bg-blue-600 text-white px-4 py-2 rounded">Submit Application</button>
        <button type="button" onclick="closeApplyModal()" class="bg-gray-300 px-4 py-2 rounded">Cancel</button>
      </div>
    </form>
  </div>
</div>

<script>
/* Simple toaster helper */
(function(){
  const container = document.getElementById('toastContainer');
  function showToast(message, type = 'success', timeoutMs = 5000){
    if (!container || !message) return;
    const toast = document.createElement('div');
    toast.className = 'toast ' + (type === 'error' ? 'toast-error' : 'toast-success');
    toast.setAttribute('role','status');
    toast.setAttribute('aria-live','polite');

    const icon = document.createElement('div');
    icon.className = 'icon';
    icon.textContent = type === 'error' ? '!' : '✓';

    const msg = document.createElement('div');
    msg.className = 'msg';
    msg.textContent = message;

    const close = document.createElement('button');
    close.className = 'close';
    close.setAttribute('aria-label','Dismiss');
    close.innerHTML = '&times;';
    close.addEventListener('click', () => {
      try { container.removeChild(toast); } catch(e){}
    });

    toast.appendChild(icon);
    toast.appendChild(msg);
    toast.appendChild(close);
    container.appendChild(toast);

    if (timeoutMs && timeoutMs > 0) {
      setTimeout(() => {
        try { container.removeChild(toast); } catch(e){}
      }, timeoutMs);
    }
  }

  // Inject server-side flash messages
  const flashError = <?php echo json_encode($error_message ?: null); ?>;
  const flashSuccess = <?php echo json_encode($success_message ?: null); ?>;

  if (flashError) showToast(flashError, 'error', 7000);
  if (flashSuccess) showToast(flashSuccess, 'success', 5000);

  // Expose for potential reuse
  window.SMMSShowToast = showToast;
})();

/* Apply Modal */
function openApplyModal(stallId, stallLabel){
  const canApply = <?php echo json_encode($vendor_can_apply); ?>;
  if(!canApply){
    window.SMMSShowToast && SMMSShowToast('You must verify Permit & ID before applying.', 'error');
    return;
  }
  document.getElementById('apply_stall_id').value = stallId;
  document.getElementById('apply_business_name').value = stallLabel + ' Business';
  document.getElementById('apply_business_type').value = '';
  try {
    const d=new Date(); d.setDate(d.getDate()+7);
    document.getElementById('apply_preferred_start_date').value = d.toISOString().split('T')[0];
  } catch(e){}
  document.getElementById('applyModal').classList.remove('hidden');
}
function closeApplyModal(){ document.getElementById('applyModal').classList.add('hidden'); }

/* Side Panel */
const sidePanel = document.getElementById('stallSidePanel');
const sidePanelTitle = document.getElementById('stallSidePanelTitle');
const sidePanelBody = document.getElementById('stallSidePanelBody');
const sidePanelError = document.getElementById('stallSidePanelError');
const sidePanelLoading = document.getElementById('stallSidePanelContent').firstElementChild;

async function loadStallSidePanel(stallId, stallNumber, stallStatus){
  sidePanelTitle.textContent = 'Stall ' + stallNumber + ' Details';
  sidePanel.classList.add('open');
  sidePanel.setAttribute('aria-hidden','false');
  sidePanelBody.classList.add('hidden');
  sidePanelError.classList.add('hidden');
  sidePanelLoading.classList.remove('hidden');

  try {
    const url = 'stall_details.php?compact=1&id=' + encodeURIComponent(stallId) + '&<?php echo $csrfQuery; ?>';
    const resp = await fetch(url, {credentials:'same-origin'});
    if (!resp.ok) throw new Error('HTTP '+resp.status);
    const html = await resp.text();
    if (!html.trim()) throw new Error('Empty response');

    sidePanelBody.innerHTML = html;

    // If the stall is occupied, hide the "Current applications" section from the compact details
    if ((stallStatus || '').toLowerCase() === 'occupied') {
      try {
        const headers = sidePanelBody.querySelectorAll('h4');
        for (const h of headers) {
          if (h.textContent && h.textContent.trim().toLowerCase() === 'current applications') {
            const section =
              h.closest('.rounded-lg.border.bg-white.p-4') ||
              h.closest('.bg-white') ||
              h.parentElement?.parentElement ||
              h.parentElement;
            if (section) section.remove();
            break;
          }
        }
      } catch (e) {}
    }

    sidePanelLoading.classList.add('hidden');
    sidePanelBody.classList.remove('hidden');
  } catch (e){
    sidePanelLoading.classList.add('hidden');
    sidePanelError.textContent = 'Failed to load stall details. Please try again.';
    sidePanelError.classList.remove('hidden');
    window.SMMSShowToast && SMMSShowToast('Failed to load stall details.', 'error');
  }
}
function closeStallSidePanel(){
  sidePanel.classList.remove('open');
  sidePanel.setAttribute('aria-hidden','true');
}

/* Photo Lightbox with fetch from stall_photos_list.php */
const lightbox = document.getElementById('photoLightbox');
const lightboxImg = document.getElementById('lightboxImg');
const lightboxLink = document.getElementById('lightboxLink');
const lightboxCounter = document.getElementById('lightboxCounter');

const photosCache = {}; // stallId => [url,...]
let currentStallId = null;
let currentIndex = 0;

function toAbsolute(url) {
  try { new URL(url); return url; }
  catch(e) { const a = document.createElement('a'); a.href = url; return a.href; }
}

function renderLightbox() {
  const arr = photosCache[currentStallId] || [];
  if (!arr.length) return closeLightbox();
  const url = arr[currentIndex];
  lightboxImg.src = url;
  lightboxLink.href = url;
  lightboxCounter.textContent = (currentIndex+1) + ' / ' + arr.length;
  lightbox.classList.add('open');
}

function lightboxPrev() {
  const arr = photosCache[currentStallId] || [];
  if (!arr.length) return;
  currentIndex = (currentIndex - 1 + arr.length) % arr.length;
  renderLightbox();
}
function lightboxNext() {
  const arr = photosCache[currentStallId] || [];
  if (!arr.length) return;
  currentIndex = (currentIndex + 1) % arr.length;
  renderLightbox();
}
function closeLightbox(){
  lightbox.classList.remove('open');
  setTimeout(()=>{ lightboxImg.src=''; }, 150);
}

async function openLightboxFor(stallId, startUrl, startIndexHint) {
  currentStallId = stallId;
  if (!photosCache[stallId]) {
    try {
      const resp = await fetch('stall_photos_list.php?stall_id=' + encodeURIComponent(stallId) + '&<?php echo $csrfQuery; ?>', { credentials: 'same-origin' });
      const data = await resp.json();
      if (!data || !data.ok) {
        photosCache[stallId] = startUrl ? [toAbsolute(startUrl)] : [];
      } else {
        const list = Array.isArray(data.photos) ? data.photos : [];
        const urls = list.map(p => toAbsolute(p.file_path || '')).filter(Boolean);
        if (!urls.length && startUrl) urls.push(toAbsolute(startUrl));
        photosCache[stallId] = urls;
      }
    } catch (e) {
      console.error('stall_photos_list fetch error', e);
      photosCache[stallId] = startUrl ? [toAbsolute(startUrl)] : [];
      window.SMMSShowToast && SMMSShowToast('Could not load photos.', 'error');
    }
  }
  const arr = photosCache[stallId];
  if (!arr.length) return;

  if (startIndexHint != null && !isNaN(startIndexHint)) {
    currentIndex = Math.max(0, Math.min(arr.length - 1, parseInt(startIndexHint, 10)));
  } else if (startUrl) {
    const idx = arr.indexOf(toAbsolute(startUrl));
    currentIndex = idx >= 0 ? idx : 0;
  } else {
    currentIndex = 0;
  }
  renderLightbox();
}

document.addEventListener('click', function(e){
  const btn = e.target.closest('.thumb-btn');
  if (btn) {
    const stallId = parseInt(btn.getAttribute('data-stall') || '0', 10);
    const full = btn.getAttribute('data-full') || '';
    const idx = btn.getAttribute('data-index');
    if (!stallId) return;
    openLightboxFor(stallId, full, idx != null ? parseInt(idx, 10) : null);
    return;
  }
  // Click outside image closes lightbox
  if (e.target === lightbox) {
    closeLightbox();
  }
});

document.addEventListener('keydown', function(e){
  if (e.key === 'Escape') {
    closeLightbox();
    closeStallSidePanel();
    closeApplyModal();
  } else if (e.key === 'ArrowLeft' && lightbox.classList.contains('open')) {
    lightboxPrev();
  } else if (e.key === 'ArrowRight' && lightbox.classList.contains('open')) {
    lightboxNext();
  }
});
</script>

<?php include 'includes/footer.php'; ?>