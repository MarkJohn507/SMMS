<?php
// fetch_stall.php
// Returns JSON information about a stall and its current active lease (if any).
require_once 'config.php';
require_once 'includes/auth_roles.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

$uid = (int)($_SESSION['user_id'] ?? 0);
if (!$uid) {
    http_response_code(401);
    echo json_encode(['error' => 'Not authenticated']);
    exit;
}

/**
 * Helper: check whether a user has any of the provided role names.
 * Uses userIsInRole() when available, otherwise falls back to _fetchUserRoleNames() or $_SESSION['roles'].
 */
function userHasAnyRoleNames($db, int $userId, array $roleNames): bool {
    $roleNames = array_map('strtolower', $roleNames);
    try {
        if (function_exists('userIsInRole')) {
            foreach ($roleNames as $r) {
                if (userIsInRole($db, $userId, $r)) return true;
            }
            return false;
        }
    } catch (Throwable $e) {
        error_log("userHasAnyRoleNames: userIsInRole failed: " . $e->getMessage());
    }

    try {
        if (function_exists('_fetchUserRoleNames')) {
            $roles = _fetchUserRoleNames($userId, $db) ?: [];
        } else {
            $roles = $_SESSION['roles'] ?? [];
        }
        $roles = array_map('strtolower', (array)$roles);
        foreach ($roleNames as $r) {
            if (in_array($r, $roles, true)) return true;
        }
    } catch (Throwable $e) {
        error_log("userHasAnyRoleNames fallback failed: " . $e->getMessage());
    }
    return false;
}

/**
 * Return array of market_ids managed by $userId.
 * Prefer explicit market_managers mapping table; fallback to markets.created_by.
 */
function getManagedMarketIds($db, int $userId): array {
    $ids = [];
    try {
        $rows = $db->fetchAll("SELECT market_id FROM market_managers WHERE user_id = ?", [$userId]) ?: [];
        foreach ($rows as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id'];
    } catch (Throwable $e) {
        error_log("getManagedMarketIds: market_managers query failed: " . $e->getMessage());
    }

    if (empty($ids)) {
        try {
            $rows = $db->fetchAll("SELECT market_id FROM markets WHERE created_by = ?", [$userId]) ?: [];
            foreach ($rows as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id'];
        } catch (Throwable $e) {
            error_log("getManagedMarketIds: fallback markets.created_by query failed: " . $e->getMessage());
        }
    }

    return array_values(array_unique($ids));
}

try {
    global $db;

    $stall_id = isset($_GET['stall_id']) ? (int)$_GET['stall_id'] : 0;
    if ($stall_id <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid stall id']);
        exit;
    }

    // fetch stall and its market_id to perform authorization checks
    $stall = $db->fetch(
        "SELECT s.stall_id, s.stall_number, s.status, s.stall_size, s.floor_number, m.market_name, m.market_id
         FROM stalls s
         JOIN markets m ON s.market_id = m.market_id
         WHERE s.stall_id = ? LIMIT 1",
        [$stall_id]
    );

    if (!$stall) {
        http_response_code(404);
        echo json_encode(['error' => 'Stall not found']);
        exit;
    }

    // Authorization:
    // allow admin-like roles; allow market_manager only for stalls in their managed markets
    $adminLikeRoles = ['super_admin','municipal_admin','issuer_admin','admin','agency_admin','accountant','inspector'];
    if (!userHasAnyRoleNames($db, $uid, $adminLikeRoles)) {
        // Not an admin-like user; check if market_manager and has access to this stall's market
        if (userHasAnyRoleNames($db, $uid, ['market_manager'])) {
            $managed = getManagedMarketIds($db, $uid);
            $marketId = isset($stall['market_id']) ? (int)$stall['market_id'] : null;
            if ($marketId === null || !in_array($marketId, $managed, true)) {
                http_response_code(403);
                echo json_encode(['error' => 'Forbidden']);
                exit;
            }
            // else allowed
        } else {
            // neither admin-like nor market_manager
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            exit;
        }
    }

    // Find active lease on this stall (if any)
    $lease = $db->fetch(
        "SELECT l.lease_id, l.vendor_id, l.business_name, l.lease_start_date, l.lease_end_date, u.full_name AS vendor_name
         FROM leases l
         LEFT JOIN users u ON l.vendor_id = u.user_id
         WHERE l.stall_id = ? AND l.status = 'active' LIMIT 1",
        [$stall_id]
    );

    $result = ['stall' => $stall];
    if ($lease) $result['lease'] = $lease;

    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($result);
    exit;
} catch (Throwable $e) {
    error_log("fetch_stall.php error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Server error']);
    exit;
}