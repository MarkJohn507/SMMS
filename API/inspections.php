<?php
// API/inspections.php - JSON endpoint to create/list inspections
// Purpose: allow inspectors/admins to create/list inspections and allow
// the stall owner (vendor) to view inspections for their stall.
// Hardened to always return JSON on error.

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../includes/auth_roles.php';     // provides isAdmin(), isLoggedIn(), etc.
require_once __DIR__ . '/../includes/inspector_utils.php'; // provides isInspector(), ensure_can_inspect_market(), recordInspection()
header('Content-Type: application/json; charset=utf-8');

try {
    if (session_status() !== PHP_SESSION_ACTIVE) session_start();
    $uid = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
    if (!$uid) {
        http_response_code(401);
        echo json_encode(['error' => 'unauthenticated']);
        exit;
    }

    $db_conn = $db; // local alias

    function isStallOwnedByUser($dbConn, int $stallId, int $userId): bool {
        if ($stallId <= 0 || $userId <= 0) return false;
        try {
                // Inspect stalls table columns for common owner fields
                $cols = $dbConn->fetchAll(
                    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'stalls'"
                ) ?: [];
                $colNames = array_map(fn($r) => $r['COLUMN_NAME'], $cols);
                $candidates = ['vendor_user_id','vendor_id','user_id','owner_id','assigned_user_id','assigned_to','holder_id','account_id'];

                $found = array_values(array_intersect($candidates, $colNames));
                if (!empty($found)) {
                    $selectParts = array_map(fn($c) => "NULLIF(s.`{$c}`,'')", $found);
                    $sql = "SELECT COALESCE(" . implode(',', $selectParts) . ") AS possible_owner FROM stalls s WHERE s.stall_id = ? LIMIT 1";
                    $r = $dbConn->fetch($sql, [$stallId]);
                    if ($r && !empty($r['possible_owner'])) {
                        if (((int)$r['possible_owner']) === $userId) return true;
                }
            }

            // Fallback: check leases table for most recent lease on this stall.
            // Support both 'user_id' and 'vendor_id' naming variations.
            $leaseCols = $dbConn->fetchAll(
                "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'leases'"
            ) ?: [];
            $leaseColNames = array_map(fn($r) => $r['COLUMN_NAME'], $leaseCols);

            // If leases has vendor_id column, prefer that; otherwise try user_id.
            if (in_array('vendor_id', $leaseColNames, true)) {
                $lease = $dbConn->fetch("SELECT vendor_id AS owner_id FROM leases WHERE stall_id = ? ORDER BY lease_start_date DESC LIMIT 1", [$stallId]);
                if ($lease && !empty($lease['owner_id'])) return ((int)$lease['owner_id']) === $userId;
            }
            if (in_array('user_id', $leaseColNames, true)) {
                $lease = $dbConn->fetch("SELECT user_id AS owner_id FROM leases WHERE stall_id = ? ORDER BY lease_start_date DESC LIMIT 1", [$stallId]);
                if ($lease && !empty($lease['owner_id'])) return ((int)$lease['owner_id']) === $userId;
            }
        } catch (Throwable $e) {
            error_log("API/inspections:isStallOwnedByUser error stall={$stallId} user={$userId}: " . $e->getMessage());
        }
        return false;
    }

    // POST: create inspection
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $raw = file_get_contents('php://input');
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            http_response_code(400);
            echo json_encode(['error' => 'invalid_json']);
            exit;
        }

        $stall_id  = (int)($data['stall_id'] ?? 0);
        $market_id = (int)($data['market_id'] ?? 0);
        if ($stall_id <= 0 || $market_id <= 0) {
            http_response_code(400);
            echo json_encode(['error' => 'stall_id and market_id required']);
            exit;
        }

        // Guard scope: inspector must have access to this market
        ensure_can_inspect_market($db_conn, $market_id);

        // Normalize outcome/status
        $allowed_outcomes = ['ok', 'minor_issue', 'major_issue', 'follow_up_required'];
        $outcome = strtolower(trim((string)($data['outcome'] ?? 'ok')));
        if (!in_array($outcome, $allowed_outcomes, true)) $outcome = 'ok';

        $status  = strtolower(trim((string)($data['status'] ?? 'completed')));
        if (!in_array($status, ['completed', 'scheduled', 'pending'], true)) $status = 'completed';

        $payload = [
            'stall_id'     => $stall_id,
            'market_id'    => $market_id,
            'inspector_id' => (int)$uid,
            'outcome'      => $outcome,
            'status'       => $status,
            'notes'        => (string)($data['notes'] ?? ''),
            'items'        => is_array($data['items'] ?? null) ? $data['items'] : [],
            'photos'       => is_array($data['photos'] ?? null) ? $data['photos'] : []
        ];

        $id = recordInspection($db_conn, $payload);
        if ($id === false) {
            http_response_code(500);
            echo json_encode(['error' => 'failed_to_create']);
        } else {
            http_response_code(201);
            echo json_encode(['ok' => true, 'inspection_id' => (int)$id]);
        }
        exit;
    }

    // GET: list inspections or single inspection details
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $inspection_id  = isset($_GET['inspection_id']) ? (int)$_GET['inspection_id'] : 0;
        $stall_id       = isset($_GET['stall_id']) ? (int)$_GET['stall_id'] : 0;
        $market_id      = isset($_GET['market_id']) ? (int)$_GET['market_id'] : 0;
        $include_photos = isset($_GET['include_photos']) && $_GET['include_photos'] == '1';
        $compact        = isset($_GET['compact']) && $_GET['compact'] == '1';

        // If requesting a single inspection, fetch it and authorize
        if ($inspection_id > 0) {
            $sqlOne = "SELECT i.*, u.full_name AS inspector_name, s.stall_number, m.market_name
                       FROM inspections i
                       JOIN stalls s  ON i.stall_id = s.stall_id
                       JOIN markets m ON i.market_id = m.market_id
                       LEFT JOIN users u   ON i.inspector_id = u.user_id
                       WHERE i.inspection_id = ?
                       LIMIT 1";
            $row = $db_conn->fetch($sqlOne, [$inspection_id]);
            if (!$row) {
                http_response_code(404);
                echo json_encode(['error' => 'not_found']);
                exit;
            }

            $allowed = false;
            if (isAdmin()) {
                $allowed = true;
            } elseif (isInspector($db_conn, $uid)) {
                // inspectors must be able to inspect the market (getInspectorMarketIds may return empty meaning "all")
                $mids = getInspectorMarketIds($db_conn, $uid);
                if (empty($mids) || in_array((int)$row['market_id'], $mids, true)) $allowed = true;
            } else {
                // Non-inspector, non-admin: allow vendor if they own the stall
                if (isStallOwnedByUser($db_conn, (int)$row['stall_id'], $uid)) $allowed = true;
            }

            if (!$allowed) {
                http_response_code(403);
                echo json_encode(['error' => 'forbidden']);
                exit;
            }

            $resp = ['inspection' => $row];

            if ($include_photos) {
                try {
                    $photos = $db_conn->fetchAll("SELECT storage_url, caption FROM inspection_photos WHERE inspection_id = ? ORDER BY uploaded_at DESC", [$inspection_id]) ?: [];
                    $resp['photos'] = $photos;
                } catch (Throwable $e) { $resp['photos'] = []; }
            }

            echo json_encode($resp);
            exit;
        }

        // Listing path: apply scoping rules
        // If market_id provided: inspector/admin required (ensure_can_inspect_market enforces)
        if ($market_id > 0) {
            ensure_can_inspect_market($db_conn, $market_id);
        } else {
            if ($stall_id > 0) {
                // Allow if inspector/admin OR stall owner
                $isInspectorUser = isInspector($db_conn, $uid);
                if (!$isInspectorUser && !isAdmin()) {
                    if (!isStallOwnedByUser($db_conn, $stall_id, $uid)) {
                        http_response_code(403);
                        echo json_encode(['error' => 'forbidden']);
                        exit;
                    }
                }
            } else {
                // No market and no stall: only inspectors/admins
                if (!isInspector($db_conn, $uid) && !isAdmin()) {
                    http_response_code(403);
                    echo json_encode(['error' => 'forbidden']);
                    exit;
                }
            }
        }

        $sql = "SELECT i.*, u.full_name AS inspector_name, s.stall_number, m.market_name
                FROM inspections i
                JOIN users u   ON i.inspector_id = u.user_id
                JOIN stalls s  ON i.stall_id = s.stall_id
                JOIN markets m ON i.market_id = m.market_id
                WHERE 1=1";
        $params = [];

        if ($market_id > 0) { $sql .= " AND i.market_id = ?"; $params[] = $market_id; }
        if ($stall_id > 0)  { $sql .= " AND i.stall_id = ?";  $params[] = $stall_id; }

        // Inspector scoping (non-admin)
        if (isInspector($db_conn, $uid) && !isAdmin()) {
            $mids = getInspectorMarketIds($db_conn, $uid);
            if (empty($mids)) {
                echo json_encode(['inspections' => []]);
                exit;
            }
            $ph = implode(',', array_fill(0, count($mids), '?'));
            $sql .= " AND i.market_id IN ($ph)";
            $params = array_merge($params, $mids);
        }

        $sql .= " ORDER BY i.inspected_at DESC, i.updated_at DESC LIMIT " . ($compact ? 50 : 200);

        $rows = $db_conn->fetchAll($sql, $params) ?: [];
        echo json_encode(['inspections' => $rows]);
        exit;
    }

    http_response_code(405);
    echo json_encode(['error' => 'method_not_allowed']);
} catch (Throwable $e) {
    error_log("API/inspections.php error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'server_error', 'message' => $e->getMessage()]);
}