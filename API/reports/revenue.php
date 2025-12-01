<?php
// API endpoint: API/reports/revenue.php
// Returns daily paid-revenue timeseries scoped to markets the current market_manager manages.
// Place this file into your existing API folder (your path likely is /API/reports/revenue.php).
//
// Query params:
//  - start_date (YYYY-MM-DD) optional, defaults to first day of current month
//  - end_date   (YYYY-MM-DD) optional, defaults to today
//
// Response JSON:
//  { "ok": true, "labels": ["2025-11-01", ...], "data": [1234.50, ...] }
// On error: { "ok": false, "error": "message" }

require_once __DIR__ . '/../../config.php';
require_once __DIR__ . '/../../includes/auth_roles.php';
require_once __DIR__ . '/../../includes/helpers.php';
require_once __DIR__ . '/../../includes/audit.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

function json_response($payload, $status = 200) {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload);
    exit;
}

// Auth
if (!function_exists('isLoggedIn') || !isLoggedIn()) {
    json_response(['ok' => false, 'error' => 'Authentication required'], 401);
}

// Only market_manager may access this timeseries
$roles = array_map('strtolower', (array)($_SESSION['roles'] ?? []));
if (!in_array('market_manager', $roles, true)) {
    json_response(['ok' => false, 'error' => 'Forbidden: market manager only'], 403);
}

$uid = (int)($_SESSION['user_id'] ?? 0);
if ($uid <= 0) json_response(['ok' => false, 'error' => 'Invalid session user'], 401);

// Parse dates
$rawStart = trim((string)($_GET['start_date'] ?? ''));
$rawEnd   = trim((string)($_GET['end_date'] ?? ''));

try {
    $start = $rawStart !== '' ? new DateTime($rawStart) : new DateTime('first day of this month');
} catch (Throwable $e) {
    json_response(['ok' => false, 'error' => 'Invalid start_date'], 400);
}
try {
    $end = $rawEnd !== '' ? new DateTime($rawEnd) : new DateTime('now');
} catch (Throwable $e) {
    json_response(['ok' => false, 'error' => 'Invalid end_date'], 400);
}

$start->setTime(0,0,0);
$end->setTime(23,59,59);
if ($end < $start) json_response(['ok' => false, 'error' => 'end_date must be >= start_date'], 400);

// Limit range
$maxRangeDays = 365;
$interval = $start->diff($end);
if ($interval->days > $maxRangeDays) {
    json_response(['ok' => false, 'error' => "Date range too large (max {$maxRangeDays} days)"], 400);
}

// Build market scope for this market manager (same logic as reports page)
$mScopeSql = '';
$mScopeParams = [];
try {
    $mPieces = [];
    $mParams = [];

    // explicit mapping via market_managers
    $mPieces[] = "EXISTS (SELECT 1 FROM market_managers mm WHERE mm.user_id = ? AND mm.market_id = m.market_id)";
    $mParams[] = $uid;
    // created_by fallback
    $mPieces[] = "m.created_by = ?";
    $mParams[] = $uid;
    // user_roles.market_id fallback
    $mPieces[] = "EXISTS (SELECT 1 FROM user_roles ur2 WHERE ur2.user_id = ? AND ur2.market_id = m.market_id AND ur2.status = 'active')";
    $mParams[] = $uid;

    if (!empty($mPieces)) {
        $mScopeSql = ' AND (' . implode(' OR ', $mPieces) . ')';
        $mScopeParams = $mParams;
    }
} catch (Throwable $e) {
    error_log("API/reports/revenue: scope build error: " . $e->getMessage());
    json_response(['ok' => false, 'error' => 'Server error building scope'], 500);
}

// If no scope, return full date series of zeros (keeps client simple)
if (empty($mScopeSql)) {
    $labels = [];
    $data = [];
    $period = new DatePeriod($start, new DateInterval('P1D'), (clone $end)->modify('+1 day'));
    foreach ($period as $dt) {
        $labels[] = $dt->format('Y-m-d');
        $data[] = 0.0;
    }
    json_response(['ok' => true, 'labels' => $labels, 'data' => $data]);
}

// Query timeseries
try {
    $sql = "
        SELECT DATE(p.payment_date) AS dt,
               COALESCE(SUM(CASE WHEN p.status = 'paid' THEN p.amount ELSE 0 END),0) AS total_amount
        FROM payments p
        JOIN leases l ON p.lease_id = l.lease_id
        JOIN stalls s ON l.stall_id = s.stall_id
        JOIN markets m ON s.market_id = m.market_id
        WHERE p.payment_date BETWEEN ? AND ? {$mScopeSql}
        GROUP BY dt
        ORDER BY dt ASC
    ";
    $params = array_merge([$start->format('Y-m-d H:i:s'), $end->format('Y-m-d H:i:s')], $mScopeParams);
    $rows = $db->fetchAll($sql, $params) ?: [];

    $map = [];
    foreach ($rows as $r) {
        $map[$r['dt']] = (float)$r['total_amount'];
    }

    $labels = [];
    $data = [];
    $period = new DatePeriod($start, new DateInterval('P1D'), (clone $end)->modify('+1 day'));
    foreach ($period as $dt) {
        $label = $dt->format('Y-m-d');
        $labels[] = $label;
        $data[] = isset($map[$label]) ? $map[$label] : 0.0;
    }

    json_response(['ok' => true, 'labels' => $labels, 'data' => $data]);
} catch (Throwable $e) {
    error_log("API/reports/revenue: query failed: " . $e->getMessage());
    json_response(['ok' => false, 'error' => 'Server error while querying data'], 500);
}