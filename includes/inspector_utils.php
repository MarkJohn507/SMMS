<?php
if (session_status() !== PHP_SESSION_ACTIVE) session_start();

/* -------- Role Detection -------- */
if (!function_exists('isInspector')) {
function isInspector($db, $userId = null): bool {
    $userId = $userId ?? ($_SESSION['user_id'] ?? null);
    if (!$userId) return false;
    try {
        if (function_exists('userIsInRole') && userIsInRole($db, $userId, 'inspector')) return true;
        $roles = $_SESSION['roles'] ?? [];
        if (is_array($roles) && in_array('inspector', $roles, true)) return true;
        $rows = $db->fetchAll("SELECT r.name FROM user_roles ur JOIN roles r ON ur.role_id = r.role_id WHERE ur.user_id = ? AND ur.status='active'", [$userId]) ?: [];
        foreach ($rows as $r) if (!empty($r['name']) && strtolower($r['name']) === 'inspector') return true;
    } catch (Throwable $e) { error_log("isInspector failed user {$userId}: ".$e->getMessage()); }
    return false;
}}
if (!function_exists('getInspectorMarketIds')) {
function getInspectorMarketIds($db, int $userId): array {
    $ids = [];
    try {
        $rows = $db->fetchAll("SELECT market_id FROM market_managers WHERE user_id = ?", [$userId]) ?: [];
        foreach ($rows as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id'];
    } catch (Throwable $e) {}
    if (empty($ids)) {
        try {
            $rows = $db->fetchAll("SELECT DISTINCT market_id FROM user_roles WHERE user_id = ? AND market_id IS NOT NULL AND status='active'", [$userId]) ?: [];
            foreach ($rows as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id'];
        } catch (Throwable $e) {}
    }
    return array_values(array_unique($ids));
}}
/* -------- Guards -------- */
if (!function_exists('ensure_can_inspect_market')) {
function ensure_can_inspect_market($db, ?int $marketId = null) {
    $uid = $_SESSION['user_id'] ?? null;
    if (!$uid) redirect('login.php');
    $adminRoles = ['super_admin','municipal_admin','issuer_admin','admin','agency_admin'];
    foreach ($adminRoles as $r) {
        if (function_exists('userIsInRole') && userIsInRole($db, $uid, $r)) return true;
    }
    if (function_exists('userHasPermission')) {
        try { if (userHasPermission($db, $uid, 'inspect_markets')) return true; } catch (Throwable $e) {}
    }
    if (isInspector($db, $uid)) {
        if ($marketId === null) return true;
        $allowed = getInspectorMarketIds($db, $uid);
        if (in_array($marketId, $allowed, true)) return true;
        http_response_code(403); echo "Forbidden: you do not have permissions to inspect this market."; exit;
    }
    http_response_code(403); echo "Forbidden: you do not have permissions."; exit;
}}
if (!function_exists('ensure_can_inspect_stall')) {
function ensure_can_inspect_stall($db, int $stallId) {
    try {
        $row = $db->fetch("SELECT market_id FROM stalls WHERE stall_id = ? LIMIT 1", [$stallId]);
        $mId = $row['market_id'] ?? null;
        ensure_can_inspect_market($db, $mId ? (int)$mId : null);
    } catch (Throwable $e) {
        http_response_code(403); echo "Forbidden: stall lookup failed."; exit;
    }
}}
/* -------- Outcome Validation -------- */
if (!function_exists('_validateInspectionOutcome')) {
function _validateInspectionOutcome(string $o): string {
    $o = strtolower(trim($o));
    // removed 'follow_up_required' per request; allowed outcomes are:
    // ok, minor_issue, major_issue, pending
    return in_array($o, ['ok','minor_issue','major_issue','pending'], true) ? $o : 'ok';
}}
/* -------- recordInspection -------- */
if (!function_exists('recordInspection')) {
function recordInspection($db, array $data) {
    foreach (['stall_id','market_id','inspector_id'] as $req) {
        if (empty($data[$req])) { error_log("recordInspection missing {$req}"); return false; }
    }
    $outcome = _validateInspectionOutcome((string)($data['outcome'] ?? 'ok'));
    $status  = strtolower(trim((string)($data['status'] ?? 'completed')));
    if (!in_array($status, ['completed','scheduled','pending'], true)) $status='completed';
    $notes       = (string)($data['notes'] ?? '');
    $stallId     = (int)$data['stall_id'];
    $marketId    = (int)$data['market_id'];
    $inspectorId = (int)$data['inspector_id'];
    $stallNumber = (string)($data['stall_number'] ?? '');
    $autoNotify  = array_key_exists('auto_notify',$data) ? (bool)$data['auto_notify'] : true;

    try {
        if (method_exists($db,'beginTransaction')) $db->beginTransaction();
        $db->query(
          "INSERT INTO inspections (stall_id, market_id, inspector_id, outcome, status, notes, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())",
          [$stallId,$marketId,$inspectorId,$outcome,$status,$notes!==''?$notes:null]
        );
        $inspection_id = (int)$db->lastInsertId();

        // table detection
        $tables=[]; try {
          $rows=$db->fetchAll("SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE()")?:[];
          foreach($rows as $r) if(!empty($r['table_name'])) $tables[strtolower($r['table_name'])]=true;
        } catch(Throwable $e){}

        if (!empty($data['items']) && is_array($data['items']) && isset($tables['inspection_items'])) {
            foreach ($data['items'] as $k=>$v) {
                if ($k==='') continue;
                $db->query("INSERT INTO inspection_items (inspection_id,item_key,item_value,created_at) VALUES (?,?,?,NOW())",
                    [$inspection_id,(string)$k,(string)$v]);
            }
        }
        if (!empty($data['photos']) && is_array($data['photos']) && isset($tables['inspection_photos'])) {
            foreach ($data['photos'] as $p) {
                if (empty($p['url'])) continue;
                $db->query("INSERT INTO inspection_photos (inspection_id,storage_url,caption,uploaded_by,uploaded_at) VALUES (?,?,?,?,NOW())",
                    [$inspection_id,(string)$p['url'],!empty($p['caption'])?(string)$p['caption']:null,$inspectorId]);
            }
        }
        if (method_exists($db,'commit')) $db->commit();

        // Notify only for major issues (follow_up_required removed)
        if ($autoNotify && $outcome === 'major_issue') {
            try {
                $admins=$db->fetchAll("SELECT user_id FROM market_managers WHERE market_id=?",[$marketId]) ?: [];
                if (empty($admins)) {
                    $admins=$db->fetchAll("SELECT ur.user_id FROM user_roles ur JOIN roles r ON ur.role_id=r.role_id WHERE r.name='market_manager' AND ur.market_id=? AND ur.status='active'",[$marketId]) ?: [];
                }
                $short=mb_substr($notes,0,200);
                $stallLabel=$stallNumber!==''?$stallNumber:"#{$stallId}";
                $msg="Inspection (ID: {$inspection_id}) for stall {$stallLabel} outcome '{$outcome}'. ".($short!==''?"Notes: {$short}":"No notes.");
                foreach($admins as $a){
                    if(empty($a['user_id'])) continue;
                    if(function_exists('createNotification')){
                        createNotification(
                          $db,(int)$a['user_id'],
                          'Inspection: Major Issue',
                          $msg,'warning','inspection',$inspection_id,'inspections'
                        );
                    }
                }
            } catch(Throwable $e){ error_log("recordInspection notify failed: ".$e->getMessage()); }
        }
        if (function_exists('logAudit')) {
            try { logAudit($db,$inspectorId,'Record Inspection','inspections',$inspection_id,null,$outcome); } catch(Throwable $e){}
        }
        return $inspection_id;
    } catch (Throwable $e) {
        try { if (method_exists($db,'rollBack')) $db->rollBack(); } catch(Throwable $e2){}
        error_log("recordInspection failed: ".$e->getMessage());
        return false;
    }
}}
/* -------- Pre-Lease Scheduling (minimal change: use 'pending' outcome) -------- */
if (!function_exists('schedulePreLeaseInspections')) {
function schedulePreLeaseInspections($db, int $leaseId, int $stallId, int $marketId, string $leaseStartDate, string $stallNumber = ''): int {
    $scheduled = 0;

    // Non-null scheduled timestamp for inspected_at
    $scheduledAt = (preg_match('/^\d{4}-\d{2}-\d{2}$/', $leaseStartDate))
        ? ($leaseStartDate . ' 00:00:00')
        : date('Y-m-d H:i:s');

    // Fetch active inspectors
    try {
        $inspectors = $db->fetchAll("
            SELECT u.user_id, u.full_name
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.role_id
            JOIN users u ON ur.user_id = u.user_id
            WHERE r.name = 'inspector'
              AND ur.status = 'active'
              AND u.status = 'active'
        ") ?: [];
    } catch (Throwable $e) {
        error_log("schedulePreLeaseInspections: inspector fetch failed: " . $e->getMessage());
        return 0;
    }

    if (!$inspectors) return 0;

    foreach ($inspectors as $insp) {
        $inspId = (int)$insp['user_id'];

        // Check inspector's market scope if available
        try {
            if (function_exists('getInspectorMarketIds')) {
                $allowed = getInspectorMarketIds($db, $inspId) ?: [];
                if (!empty($allowed) && !in_array($marketId, $allowed, true)) continue;
            }
        } catch (Throwable $e) {}

        // Duplicate check
        $dup = $db->fetch("
            SELECT inspection_id
              FROM inspections
             WHERE stall_id = ?
               AND inspector_id = ?
               AND status IN ('scheduled','pending')
             LIMIT 1
        ", [$stallId, $inspId]);
        if ($dup) continue;

        try {
            $label = $stallNumber !== '' ? $stallNumber : "#{$stallId}";
            $db->query("
                INSERT INTO inspections (
                    stall_id, market_id, inspector_id,
                    inspected_at, outcome, status, notes,
                    created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, 'scheduled', ?, NOW(), NOW())
            ", [
                $stallId,
                $marketId,
                $inspId,
                $scheduledAt,
                'pending', // neutral placeholder outcome
                "[Auto] Pre-lease inspection for stall {$label}; lease ID {$leaseId}; target start {$leaseStartDate}"
            ]);

            $newId = (int)$db->lastInsertId();
            $scheduled++;

            // Notify inspector (best-effort)
            if (function_exists('createNotification')) {
                $msg = "Pre-lease inspection scheduled for stall {$label} (Lease ID: {$leaseId}). Complete by {$leaseStartDate}.";
                try { createNotification($db, $inspId, 'Pre-Lease Inspection Scheduled', $msg, 'info', 'inspection', $newId, 'inspections'); }
                catch (Throwable $e) { error_log("schedulePreLeaseInspections: notify fail inspector {$inspId}: ".$e->getMessage()); }
            }

            // Audit
            if (function_exists('logAudit')) {
                try { logAudit($db, $inspId, 'Schedule Inspection (Pre-Lease)', 'inspections', $newId, null, "lease_id={$leaseId}"); } catch (Throwable $e) {}
            }
        } catch (Throwable $e) {
            error_log("schedulePreLeaseInspections insert failed inspector {$inspId}: " . $e->getMessage());
        }
    }

    return $scheduled;
}}
?>