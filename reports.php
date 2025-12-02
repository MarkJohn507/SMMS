<?php
require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/helpers.php';

/**
 * reports.php (fixed)
 *
 * - Keeps deterministic SQL scoping for market_manager / accountant.
 * - Loads revenue timeseries asynchronously from /API/reports/revenue.php (market_manager only).
 * - Chart is rendered client-side; avoids layout thrash and infinite scrolling by:
 *     - fixed container height,
 *     - debounced resize handling,
 *     - client/server downsampling safeguards.
 *
 * Use ?debug=1 to show scope SQL fragments and params for the current user.
 */

// Page config
$page_title = 'Reports & Analytics';
$debug = !empty($_GET['debug']) && $_GET['debug'] === '1';

// Date range parsing / normalization
$start_date = isset($_GET['start_date']) ? sanitize($_GET['start_date']) : date('Y-m-01');
$end_date   = isset($_GET['end_date'])   ? sanitize($_GET['end_date'])   : date('Y-m-t');
try {
    $sd = new DateTime($start_date);
    $ed = new DateTime($end_date);
    $start_date = $sd->format('Y-m-d');
    $end_date   = $ed->format('Y-m-d');
} catch (Exception $e) {
    $start_date = date('Y-m-01');
    $end_date   = date('Y-m-t');
}

// Current user
$uid = $_SESSION['user_id'] ?? null;
if (!$uid) $uid = null;

// Helper: safe IN clause builder (kept for potential explicit-ID usage)
function buildInClause(array $ids, string $column) {
    if (empty($ids)) return ['', []];
    $ids = array_map('intval', array_values(array_unique($ids)));
    $placeholders = implode(',', array_fill(0, count($ids), '?'));
    return [" AND {$column} IN ({$placeholders})", $ids];
}

// Load user_roles and role names (authoritative source of per-staff scope)
try {
    $roleRows = $uid
        ? $db->fetchAll(
            "SELECT ur.user_role_id, ur.role_id, ur.market_id, ur.status AS ur_status, r.name AS role_name
             FROM user_roles ur
             JOIN roles r ON ur.role_id = r.role_id
             WHERE ur.user_id = ?
             ORDER BY ur.assigned_at DESC",
            [$uid]
        ) : [];
} catch (Throwable $e) {
    error_log("reports: failed to fetch user_roles for user {$uid}: " . $e->getMessage());
    $roleRows = [];
}

// Normalize roles & collect explicit market_ids on user_roles (kept for debug / optional explicit path)
$normalizedRoles = [];
$userRoleMarketIds = [];
foreach ($roleRows as $rr) {
    $rname = isset($rr['role_name']) ? strtolower(trim($rr['role_name'])) : null;
    if ($rname && !in_array($rname, $normalizedRoles, true)) $normalizedRoles[] = $rname;
    if (isset($rr['market_id']) && $rr['market_id'] !== null && $rr['market_id'] !== '') {
        $userRoleMarketIds[] = (int)$rr['market_id'];
    }
}
$userRoleMarketIds = array_values(array_unique($userRoleMarketIds));

// Role flags
$is_market_manager = in_array('market_manager', $normalizedRoles, true);
$is_accountant     = in_array('accountant', $normalizedRoles, true);
// Prefer authoritative DB check for super_admin to avoid trusting stale session flags
$is_super_admin = in_array('super_admin', $normalizedRoles, true);

// If not found in the freshly fetched normalizedRoles, query DB directly (fallback)
if (!$is_super_admin && function_exists('_fetchUserRoleNames')) {
    $dbRoleNames = _fetchUserRoleNames($uid, $db);
    $is_super_admin = in_array('super_admin', $dbRoleNames, true);
}

// ---------------------- Deterministic SQL scoping (EXISTS-based) ----------------------
// Build market-level scope (mScopeSql/mScopeParams) and stalls-level scope (sScopeSql/sScopeParams).
$mScopeSql = '';
$mScopeParams = [];
$sScopeSql = '';
$sScopeParams = [];

if (!$is_super_admin && ($is_market_manager || $is_accountant)) {
    $mPieces = [];
    $mParams = [];

    if ($is_accountant) {
        $mPieces[] = "EXISTS (SELECT 1 FROM user_roles ur WHERE ur.user_id = ? AND ur.market_id = m.market_id AND ur.status = 'active')";
        $mParams[] = $uid;
    }

    if ($is_market_manager) {
        $mPieces[] = "EXISTS (SELECT 1 FROM market_managers mm WHERE mm.user_id = ? AND mm.market_id = m.market_id)";
        $mParams[] = $uid;
        $mPieces[] = "m.created_by = ?";
        $mParams[] = $uid;
        $mPieces[] = "EXISTS (SELECT 1 FROM user_roles ur2 WHERE ur2.user_id = ? AND ur2.market_id = m.market_id AND ur2.status = 'active')";
        $mParams[] = $uid;
    }

    if (!empty($mPieces)) {
        $mScopeSql = ' AND (' . implode(' OR ', $mPieces) . ')';
        $mScopeParams = $mParams;
    }

    // Stalls scope mirrors markets scope but references s.market_id
    $sPieces = [];
    $sParams = [];

    if ($is_accountant) {
        $sPieces[] = "EXISTS (SELECT 1 FROM user_roles ur WHERE ur.user_id = ? AND ur.market_id = s.market_id AND ur.status = 'active')";
        $sParams[] = $uid;
    }

    if ($is_market_manager) {
        $sPieces[] = "EXISTS (SELECT 1 FROM market_managers mm WHERE mm.user_id = ? AND mm.market_id = s.market_id)";
        $sParams[] = $uid;
        $sPieces[] = "s.market_id IN (SELECT market_id FROM markets WHERE created_by = ?)";
        $sParams[] = $uid;
        $sPieces[] = "EXISTS (SELECT 1 FROM user_roles ur2 WHERE ur2.user_id = ? AND ur2.market_id = s.market_id AND ur2.status = 'active')";
        $sParams[] = $uid;
    }

    if (!empty($sPieces)) {
        $sScopeSql = ' AND (' . implode(' OR ', $sPieces) . ')';
        $sScopeParams = $sParams;
    }
}
// ----------------------------------------------------------------------

// Final server-side debug log
error_log("reports: user_id={$uid} roles=" . json_encode($normalizedRoles) .
    " userRoleMarketIds=" . json_encode($userRoleMarketIds) .
    " mScopeSql=" . $mScopeSql . " mScopeParams=" . json_encode($mScopeParams) .
    " sScopeSql=" . $sScopeSql . " sScopeParams=" . json_encode($sScopeParams)
);

// Determine whether this user is scoped (market_manager/accountant and not super admin)
$is_scoped_user = ($uid && !$is_super_admin && ($is_market_manager || $is_accountant));

// -------------------- Queries --------------------
// KPIs
try {
    if ($is_scoped_user) {
        if (empty($mScopeSql) && empty($sScopeSql)) {
            $stats = ['total_markets' => 0, 'total_stalls' => 0, 'total_vendors' => 0];
        } else {
            $row = $db->fetch("SELECT COUNT(*) AS cnt FROM markets m WHERE 1=1 {$mScopeSql}", $mScopeParams);
            $total_markets = (int)($row['cnt'] ?? 0);

            $row = $db->fetch("SELECT COUNT(DISTINCT s.stall_id) AS cnt FROM stalls s WHERE 1=1 {$sScopeSql}", $sScopeParams);
            $total_stalls = (int)($row['cnt'] ?? 0);

            $vendor_sql = "
                SELECT COUNT(DISTINCT l.vendor_id) AS cnt
                FROM leases l
                JOIN stalls s ON l.stall_id = s.stall_id
                WHERE 1=1 {$sScopeSql}
            ";
            $row = $db->fetch($vendor_sql, $sScopeParams) ?: [];
            $total_vendors = (int)($row['cnt'] ?? 0);

            $stats = ['total_markets' => $total_markets, 'total_stalls' => $total_stalls, 'total_vendors' => $total_vendors];
        }
    } else {
        $row = $db->fetch("
            SELECT
                (SELECT COUNT(*) FROM markets) AS total_markets,
                (SELECT COUNT(*) FROM stalls) AS total_stalls,
                (SELECT COUNT(DISTINCT vendor_id) FROM leases) AS total_vendors
        ");
        $stats = [
            'total_markets' => (int)($row['total_markets'] ?? 0),
            'total_stalls'  => (int)($row['total_stalls'] ?? 0),
            'total_vendors' => (int)($row['total_vendors'] ?? 0),
        ];
    }
} catch (Throwable $e) {
    error_log("reports: KPI query failed: " . $e->getMessage());
    $stats = ['total_markets' => 0, 'total_stalls' => 0, 'total_vendors' => 0];
}

// Revenue totals
try {
    if ($is_scoped_user) {
        if (empty($mScopeSql) && empty($sScopeSql)) {
            $revenue = ['total_revenue' => 0, 'pending_revenue' => 0, 'overdue_revenue' => 0, 'total_payments' => 0];
        } else {
            $revenue_sql = "
                SELECT
                    COALESCE(SUM(CASE WHEN p.status = 'paid' THEN p.amount ELSE 0 END),0) AS total_revenue,
                    COALESCE(SUM(CASE WHEN p.status = 'pending' THEN p.amount ELSE 0 END),0) AS pending_revenue,
                    COALESCE(SUM(CASE WHEN p.status = 'overdue' THEN p.amount ELSE 0 END),0) AS overdue_revenue,
                    COUNT(DISTINCT p.payment_id) AS total_payments
                FROM payments p
                JOIN leases l ON p.lease_id = l.lease_id
                JOIN stalls s ON l.stall_id = s.stall_id
                JOIN markets m ON s.market_id = m.market_id
                WHERE p.payment_date BETWEEN ? AND ? {$mScopeSql}";
            $revenue = $db->fetch($revenue_sql, array_merge([$start_date, $end_date], $mScopeParams)) ?: [];
        }
    } else {
        $revenue_sql = "
            SELECT
                COALESCE(SUM(CASE WHEN status = 'paid' THEN amount ELSE 0 END),0) AS total_revenue,
                COALESCE(SUM(CASE WHEN status = 'pending' THEN amount ELSE 0 END),0) AS pending_revenue,
                COALESCE(SUM(CASE WHEN status = 'overdue' THEN amount ELSE 0 END),0) AS overdue_revenue,
                COUNT(DISTINCT payment_id) AS total_payments
            FROM payments
            WHERE payment_date BETWEEN ? AND ?";
        $revenue = $db->fetch($revenue_sql, [$start_date, $end_date]) ?: [];
    }
} catch (Throwable $e) {
    error_log("reports: revenue query failed: " . $e->getMessage());
    $revenue = ['total_revenue' => 0, 'pending_revenue' => 0, 'overdue_revenue' => 0, 'total_payments' => 0];
}

// Occupancy
try {
    if ($is_scoped_user) {
        if (empty($mScopeSql) && empty($sScopeSql)) {
            $occupancy = ['total_stalls'=>0,'available'=>0,'occupied'=>0,'reserved'=>0,'maintenance'=>0];
        } else {
            $occupancy_sql = "
                SELECT
                    COUNT(DISTINCT s.stall_id) AS total_stalls,
                    COALESCE(SUM(CASE WHEN s.status = 'available' THEN 1 ELSE 0 END),0) AS available,
                    COALESCE(SUM(CASE WHEN s.status = 'occupied' THEN 1 ELSE 0 END),0) AS occupied,
                    COALESCE(SUM(CASE WHEN s.status = 'reserved' THEN 1 ELSE 0 END),0) AS reserved,
                    COALESCE(SUM(CASE WHEN s.status = 'maintenance' THEN 1 ELSE 0 END),0) AS maintenance
                FROM stalls s
                WHERE 1=1 {$sScopeSql}";
            $occupancy = $db->fetch($occupancy_sql, $sScopeParams) ?: [];
        }
    } else {
        $occupancy_sql = "
            SELECT
                COUNT(DISTINCT stall_id) AS total_stalls,
                COALESCE(SUM(CASE WHEN status = 'available' THEN 1 ELSE 0 END),0) AS available,
                COALESCE(SUM(CASE WHEN status = 'occupied' THEN 1 ELSE 0 END),0) AS occupied,
                COALESCE(SUM(CASE WHEN status = 'reserved' THEN 1 ELSE 0 END),0) AS reserved,
                COALESCE(SUM(CASE WHEN status = 'maintenance' THEN 1 ELSE 0 END),0) AS maintenance
            FROM stalls";
        $occupancy = $db->fetch($occupancy_sql) ?: [];
    }
} catch (Throwable $e) {
    error_log("reports: occupancy query failed: " . $e->getMessage());
    $occupancy = ['total_stalls'=>0,'available'=>0,'occupied'=>0,'reserved'=>0,'maintenance'=>0];
}

// Top vendors
try {
    if ($is_scoped_user) {
        if (empty($mScopeSql) && empty($sScopeSql)) {
            $top_vendors = [];
        } else {
            $top_vendors_sql = "
                SELECT u.user_id, u.full_name, u.email,
                    COUNT(DISTINCT p.payment_id) AS payment_count,
                    COALESCE(SUM(CASE WHEN p.status = 'paid' THEN p.amount ELSE 0 END),0) AS total_paid
                FROM users u
                JOIN payments p ON u.user_id = p.vendor_id
                JOIN leases l ON p.lease_id = l.lease_id
                JOIN stalls s ON l.stall_id = s.stall_id
                JOIN markets m ON s.market_id = m.market_id
                WHERE p.payment_date BETWEEN ? AND ? {$mScopeSql}
                GROUP BY u.user_id
                ORDER BY total_paid DESC
                LIMIT 10";
            $top_vendors = $db->fetchAll($top_vendors_sql, array_merge([$start_date, $end_date], $mScopeParams)) ?: [];
        }
    } else {
        $top_vendors_sql = "
            SELECT u.user_id, u.full_name, u.email,
                COUNT(DISTINCT p.payment_id) AS payment_count,
                COALESCE(SUM(CASE WHEN p.status = 'paid' THEN p.amount ELSE 0 END),0) AS total_paid
            FROM users u
            JOIN payments p ON u.user_id = p.vendor_id
            WHERE p.payment_date BETWEEN ? AND ?
            GROUP BY u.user_id
            ORDER BY total_paid DESC
            LIMIT 10";
        $top_vendors = $db->fetchAll($top_vendors_sql, [$start_date, $end_date]) ?: [];
    }
} catch (Throwable $e) {
    error_log("reports: top_vendors query failed: " . $e->getMessage());
    $top_vendors = [];
}

// Market performance
try {
    if ($is_scoped_user) {
        if (empty($mScopeSql) && empty($sScopeSql)) {
            $market_performance = [];
        } else {
            $market_performance_sql = "
                SELECT m.market_id, m.market_name,
                    COUNT(DISTINCT s.stall_id) AS total_stalls,
                    COALESCE(SUM(CASE WHEN s.status = 'occupied' THEN 1 ELSE 0 END),0) AS occupied_stalls,
                    COALESCE(SUM(CASE WHEN l.status = 'active' THEN l.monthly_rent ELSE 0 END),0) AS monthly_revenue
                FROM markets m
                LEFT JOIN stalls s ON m.market_id = s.market_id
                LEFT JOIN leases l ON s.stall_id = l.stall_id AND l.status = 'active'
                WHERE 1=1 {$mScopeSql}
                GROUP BY m.market_id
                ORDER BY monthly_revenue DESC";
            $market_performance = $db->fetchAll($market_performance_sql, $mScopeParams) ?: [];
        }
    } else {
        $market_performance_sql = "
            SELECT m.market_id, m.market_name,
                COUNT(DISTINCT s.stall_id) AS total_stalls,
                COALESCE(SUM(CASE WHEN s.status = 'occupied' THEN 1 ELSE 0 END),0) AS occupied_stalls,
                COALESCE(SUM(CASE WHEN l.status = 'active' THEN l.monthly_rent ELSE 0 END),0) AS monthly_revenue
            FROM markets m
            LEFT JOIN stalls s ON m.market_id = s.market_id
            LEFT JOIN leases l ON s.stall_id = l.stall_id AND l.status = 'active'
            GROUP BY m.market_id
            ORDER BY monthly_revenue DESC";
        $market_performance = $db->fetchAll($market_performance_sql) ?: [];
    }
} catch (Throwable $e) {
    error_log("reports: market_performance query failed: " . $e->getMessage());
    $market_performance = [];
}

// Recent activities (global)
try {
    $activities = $db->fetchAll("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 20") ?: [];
} catch (Throwable $e) {
    error_log("reports: activities query failed: " . $e->getMessage());
    $activities = [];
}

// Audit the view (include scoped info)
try {
    logAudit($db, $_SESSION['user_id'] ?? null, 'View Reports', 'reports', null, null, json_encode([
        'start_date' => $start_date,
        'end_date' => $end_date,
        'roles' => $normalizedRoles,
        'userRoleMarketIds' => $userRoleMarketIds,
        'mScopeSql' => $mScopeSql,
        'mScopeParams' => $mScopeParams,
        'sScopeSql' => $sScopeSql,
        'sScopeParams' => $sScopeParams
    ]));
} catch (Throwable $e) {
    error_log("reports: audit log failed: " . $e->getMessage());
}

// Render
require_once 'includes/header.php';
require_once 'includes/admin_sidebar.php';
?>

<section class="max-w-7xl mx-auto p-6 space-y-6">
    <div class="mb-6">
        <p class="text-gray-600">View system performance scoped to your assigned market(s)</p>
    </div>

    <?php if ($is_scoped_user && empty($mScopeSql) && empty($sScopeSql)): ?>
        <div class="bg-yellow-50 border border-yellow-200 text-yellow-900 px-4 py-3 rounded mb-6">
            You are a scoped user but are not assigned to any market. Reports will be empty until you are assigned a market.
        </div>
    <?php endif; ?>

    <?php if ($debug): ?>
        <div class="mb-6 bg-gray-50 border p-4 rounded">
            <h4 class="font-semibold">Debug</h4>
            <pre><?php
                $debugText = "user_id={$uid}\nroles=" . json_encode($normalizedRoles)
                    . "\nuser_roles_rows=" . json_encode($roleRows)
                    . "\nuserRoleMarketIds=" . json_encode($userRoleMarketIds)
                    . "\nmScopeSql=" . $mScopeSql
                    . "\nmScopeParams=" . json_encode($mScopeParams)
                    . "\nsScopeSql=" . $sScopeSql
                    . "\nsScopeParams=" . json_encode($sScopeParams);
                echo htmlspecialchars($debugText);
            ?></pre>
            <p class="text-sm text-gray-600">If the debug shows no scope but you expect one, clear PHP OPcache / restart PHP-FPM and re-load this file.</p>
        </div>
    <?php endif; ?>

    <!-- KPI tiles -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div class="bg-white rounded-lg shadow-md p-6 text-center">
            <p class="text-sm text-gray-500">Markets</p>
            <p class="text-2xl font-bold"><?php echo number_format($stats['total_markets'] ?? 0); ?></p>
        </div>
        <div class="bg-white rounded-lg shadow-md p-6 text-center">
            <p class="text-sm text-gray-500">Total Stalls</p>
            <p class="text-2xl font-bold"><?php echo number_format($stats['total_stalls'] ?? 0); ?></p>
        </div>
        <div class="bg-white rounded-lg shadow-md p-6 text-center">
            <p class="text-sm text-gray-500">Vendors</p>
            <p class="text-2xl font-bold"><?php echo number_format($stats['total_vendors'] ?? 0); ?></p>
        </div>
    </div>

    <!-- 1) Date range form - place above the market-manager chart (replace the existing static range text or insert above it) -->
    <form id="mmDateRangeForm" class="flex items-center gap-2 mb-4" style="flex-wrap:wrap;">
        <label class="text-sm text-gray-600 mr-2">Date range:</label>
        <input id="mmStartDate" type="date" name="start_date"
               value="<?php echo htmlspecialchars($start_date); ?>"
               class="px-3 py-2 border rounded" />
        <span class="text-sm text-gray-500">→</span>
        <input id="mmEndDate" type="date" name="end_date"
               value="<?php echo htmlspecialchars($end_date); ?>"
               class="px-3 py-2 border rounded" />
        <button id="mmApplyRange" type="submit" class="px-4 py-2 bg-blue-600 text-white rounded">Apply</button>
        <button id="mmResetRange" type="button" class="px-3 py-2 bg-gray-100 rounded">Reset</button>
        <div id="mmRangeNote" class="text-xs text-gray-500 ml-3">Max range: 365 days</div>
    </form>

    <!-- If user is market_manager, show a revenue timeseries chart (fetched async) -->
    <?php if ($is_market_manager): ?>
        <div class="bg-white rounded-lg shadow-md p-6 overflow-hidden" id="mm-revenue-panel">
        <div class="flex items-center justify-between mb-4">
          <h4 class="text-lg font-semibold">Revenue (<span id="mm-range"><?php echo h($start_date . ' → ' . $end_date); ?></span>)</h4>
          <p class="text-sm text-gray-500">Visible to Market Managers only</p>
        </div>

        <div id="mm-chart-loading" class="text-center py-8">Loading chart...</div>
        <div id="mm-chart-error" class="hidden text-center py-8 text-red-600"></div>
        <div id="mm-chart-wrapper" class="hidden" style="height:320px;">
          <canvas id="mmRevenueChart" style="width:100%;height:100%;display:block;"></canvas>
        </div>

        <div class="mt-3 text-xs text-gray-500">Amounts shown are sum of payments with status "paid" per day.</div>
      </div>
    <?php endif; ?>

    <!-- Revenue block -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div class="bg-white rounded-lg shadow-md p-6">
            <p class="text-gray-500 text-sm">Total Revenue</p>
            <h3 class="text-2xl font-bold text-green-600 mt-2"><?php echo formatCurrency($revenue['total_revenue'] ?? 0); ?></h3>
        </div>
        <div class="bg-white rounded-lg shadow-md p-6">
            <p class="text-gray-500 text-sm">Pending</p>
            <h3 class="text-2xl font-bold text-yellow-600 mt-2"><?php echo formatCurrency($revenue['pending_revenue'] ?? 0); ?></h3>
        </div>
        <div class="bg-white rounded-lg shadow-md p-6">
            <p class="text-gray-500 text-sm">Overdue</p>
            <h3 class="text-2xl font-bold text-red-600 mt-2"><?php echo formatCurrency($revenue['overdue_revenue'] ?? 0); ?></h3>
        </div>
        <div class="bg-white rounded-lg shadow-md p-6">
            <p class="text-gray-500 text-sm">Total Payments</p>
            <h3 class="text-3xl font-bold text-gray-800 mt-2"><?php echo (int)($revenue['total_payments'] ?? 0); ?></h3>
        </div>
    </div>

    <!-- Occupancy block -->
    <div class="bg-white rounded-lg shadow-md p-6">
        <h4 class="text-lg font-semibold mb-4">Stall Occupancy Overview</h4>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div class="text-center p-4 bg-gray-50 rounded-lg">
                <p class="text-3xl font-bold"><?php echo (int)($occupancy['total_stalls'] ?? 0); ?></p>
                <p class="text-sm text-gray-600">Total Stalls</p>
            </div>
            <div class="text-center p-4 bg-green-50 rounded-lg">
                <p class="text-3xl font-bold text-green-600"><?php echo (int)($occupancy['available'] ?? 0); ?></p>
                <p class="text-sm text-gray-600">Available</p>
            </div>
            <div class="text-center p-4 bg-blue-50 rounded-lg">
                <p class="text-3xl font-bold text-blue-600"><?php echo (int)($occupancy['occupied'] ?? 0); ?></p>
                <p class="text-sm text-gray-600">Occupied</p>
            </div>
            <div class="text-center p-4 bg-red-50 rounded-lg">
                <p class="text-3xl font-bold text-red-600"><?php echo (int)($occupancy['maintenance'] ?? 0); ?></p>
                <p class="text-sm text-gray-600">Maintenance</p>
            </div>
        </div>
    </div>

    <!-- Top vendors & Market performance -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div class="bg-white rounded-lg shadow-md p-6">
            <h4 class="text-lg font-semibold mb-4">Top Paying Vendors</h4>
            <?php if (!empty($top_vendors)): ?>
                <div class="space-y-3">
                    <?php foreach ($top_vendors as $vendor): ?>
                        <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                            <div class="flex-1">
                                <p class="font-semibold text-gray-800"><?php echo htmlspecialchars($vendor['full_name'] ?? ''); ?></p>
                                <p class="text-xs text-gray-600"><?php echo (int)($vendor['payment_count'] ?? 0); ?> payments</p>
                            </div>
                            <div class="text-right">
                                <p class="font-bold text-green-600"><?php echo formatCurrency($vendor['total_paid'] ?? 0); ?></p>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <p class="text-gray-500 text-center py-8">No payment data for selected period</p>
            <?php endif; ?>
        </div>

        <div class="bg-white rounded-lg shadow-md p-6">
            <h4 class="text-lg font-semibold mb-4">Market Performance</h4>
            <?php if (!empty($market_performance)): ?>
                <div class="space-y-3">
                    <?php foreach ($market_performance as $market): ?>
                        <?php
                            $total_stalls_m = (int)($market['total_stalls'] ?? 0);
                            $occupied_m = (int)($market['occupied_stalls'] ?? 0);
                            $pct = $total_stalls_m > 0 ? number_format(($occupied_m / $total_stalls_m) * 100, 1) : 0;
                        ?>
                        <div class="p-3 bg-gray-50 rounded-lg">
                            <div class="flex items-center justify-between mb-2">
                                <p class="font-semibold text-gray-800"><?php echo htmlspecialchars($market['market_name'] ?? ''); ?></p>
                                <p class="font-bold text-blue-600"><?php echo formatCurrency($market['monthly_revenue'] ?? 0); ?>/mo</p>
                            </div>
                            <div class="flex items-center justify-between text-sm text-gray-600">
                                <span><?php echo $occupied_m; ?> / <?php echo $total_stalls_m; ?> stalls occupied</span>
                                <span><?php echo $pct; ?>%</span>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <p class="text-gray-500 text-center py-8">No market data available</p>
            <?php endif; ?>
        </div>
    </div>

    <!-- Recent Activities (collapsible) -->
    <div class="bg-white rounded-lg shadow-md p-6">
        <div class="flex items-center justify-between mb-4">
            <h4 class="text-lg font-semibold">Recent System Activities</h4>
            <div class="flex items-center gap-2">
                <button id="toggleActivitiesBtn" class="px-3 py-1 bg-gray-100 hover:bg-gray-200 rounded text-sm" aria-expanded="true">
                    <span id="toggleActivitiesLabel">Collapse</span>
                </button>
            </div>
        </div>

        <div id="activitiesContainer" class="transition-all">
            <?php if (!empty($activities)): ?>
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="text-left py-3 px-4 text-sm font-semibold text-gray-700">Action</th>
                                <th class="text-left py-3 px-4 text-sm font-semibold text-gray-700">Table</th>
                                <th class="text-left py-3 px-4 text-sm font-semibold text-gray-700">Record ID</th>
                                <th class="text-left py-3 px-4 text-sm font-semibold text-gray-700">Date/Time</th>
                                <th class="text-left py-3 px-4 text-sm font-semibold text-gray-700">IP Address</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-200">
                            <?php foreach ($activities as $activity): ?>
                                <tr class="hover:bg-gray-50">
                                    <td class="py-3 px-4 text-sm text-gray-800"><?php echo htmlspecialchars($activity['action'] ?? ''); ?></td>
                                    <td class="py-3 px-4 text-sm text-gray-600"><?php echo htmlspecialchars($activity['table_name'] ?? ''); ?></td>
                                    <td class="py-3 px-4 text-sm text-gray-600"><?php echo htmlspecialchars($activity['record_id'] ?? ''); ?></td>
                                    <td class="py-3 px-4 text-sm text-gray-600"><?php echo !empty($activity['created_at']) ? date('M d, Y h:i A', strtotime($activity['created_at'])) : ''; ?></td>
                                    <td class="py-3 px-4 text-sm text-gray-600"><?php echo htmlspecialchars($activity['ip_address'] ?? ''); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php else: ?>
                <p class="text-gray-500 text-center py-8">No activities recorded</p>
            <?php endif; ?>
        </div>
    </div>
</section>

<?php if ($is_market_manager): ?>
<script>
(function(){
  // Elements
  const panel = document.getElementById('mm-revenue-panel');
  if (!panel) return;

  const startInput = document.getElementById('mmStartDate');
  const endInput   = document.getElementById('mmEndDate');
  const form       = document.getElementById('mmDateRangeForm');
  const loadingEl  = document.getElementById('mm-chart-loading');
  const errorEl    = document.getElementById('mm-chart-error');
  const wrapper    = document.getElementById('mm-chart-wrapper');
  const canvas     = document.getElementById('mmRevenueChart');
  const rangeLabel = document.getElementById('mm-range');

  // Use relative path so it works under subfolders (e.g. /NEW/API/...)
  function apiUrl(start, end){
    return 'API/reports/revenue.php?start_date=' + encodeURIComponent(start) + '&end_date=' + encodeURIComponent(end);
  }

  function showError(msg, details){
    if (loadingEl) loadingEl.classList.add('hidden');
    if (wrapper) wrapper.classList.add('hidden');
    if (errorEl) {
      errorEl.classList.remove('hidden');
      errorEl.innerHTML = '<div>' + (msg || 'Error') + '</div>' + (details ? '<pre style="max-height:240px;overflow:auto;margin-top:8px;background:#fff;padding:8px;border-radius:4px;color:#111;">' + details + '</pre>' : '');
    }
  }

  async function loadChartJs(){
    if (window.Chart) return window.Chart;
    return new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js';
      s.async = true;
      s.onload = () => resolve(window.Chart);
      s.onerror = () => reject(new Error('Failed to load Chart.js'));
      document.head.appendChild(s);
    });
  }

  function validateDates(start, end){
    const s = new Date(start);
    const e = new Date(end);
    if (isNaN(s) || isNaN(e)) return { ok:false, msg:'Invalid date' };
    if (e < s) return { ok:false, msg:'End date must be the same or after start date' };
    const diffDays = Math.ceil((e - s) / (1000*60*60*24)) + 1; // inclusive
    if (diffDays > 365) return { ok:false, msg:'Date range too large. Max 365 days.' };
    return { ok:true, days:diffDays };
  }

  async function fetchAndRender(start, end, pushUrl = true){
    if (!start || !end) { showError('Please select both start and end dates.'); return; }

    // validate client-side
    const v = validateDates(start, end);
    if (!v.ok) { showError(v.msg); return; }

    if (rangeLabel) rangeLabel.textContent = start + ' → ' + end;

    const url = apiUrl(start, end);

    // show loading
    if (errorEl) { errorEl.classList.add('hidden'); errorEl.textContent = ''; }
    if (wrapper) wrapper.classList.add('hidden');
    if (loadingEl) loadingEl.classList.remove('hidden');

    try {
      const resp = await fetch(url, { credentials: 'same-origin' });

      if (!resp.ok) {
        const txt = await resp.text().catch(()=>null);
        showError('Server returned ' + resp.status + ' ' + resp.statusText, txt || null);
        return;
      }

      const ct = resp.headers.get('content-type') || '';
      const bodyText = await resp.text();
      if (!ct.includes('application/json')) {
        showError('Invalid content-type from API (expected JSON)', bodyText);
        return;
      }

      let json;
      try {
        json = JSON.parse(bodyText);
      } catch (e) {
        showError('Invalid JSON response from API', bodyText);
        return;
      }

      if (!json.ok) {
        showError('API error: ' + (json.error || 'unknown'));
        return;
      }

      const labels = json.labels || [];
      const data = json.data || [];
      if (!labels.length || !data.length) {
        showError('No revenue data for that period.');
        return;
      }

      // load Chart.js
      try { await loadChartJs(); } catch (e) { showError('Unable to load chart library.'); return; }

      if (loadingEl) loadingEl.classList.add('hidden');
      if (errorEl) errorEl.classList.add('hidden');
      if (wrapper) wrapper.classList.remove('hidden');

      // optional downsample safety
      const MAX_POINTS = 500;
      let plotLabels = labels, plotData = data;
      if (labels.length > MAX_POINTS) {
        const step = Math.ceil(labels.length / MAX_POINTS);
        const l = [], d = [];
        for (let i = 0; i < labels.length; i += step) { l.push(labels[i]); d.push(data[i] ?? 0); }
        if (l[l.length-1] !== labels[labels.length-1]) { l.push(labels[labels.length-1]); d.push(data[data.length-1] ?? 0); }
        plotLabels = l; plotData = d;
      }

      // ensure fixed container height
      canvas.parentElement.style.height = '320px';
      const ctx = canvas.getContext('2d');

      // destroy previous chart instance if exists
      if (canvas._chartInstance) { try { canvas._chartInstance.destroy(); } catch (e) {} }

      canvas._chartInstance = new Chart(ctx, {
        type: 'line',
        data: {
          labels: plotLabels,
          datasets: [{
            label: 'Paid Revenue',
            data: plotData,
            backgroundColor: 'rgba(59,130,246,0.12)',
            borderColor: 'rgba(59,130,246,0.95)',
            borderWidth: 2,
            pointRadius: Math.min(3, Math.max(0, Math.floor(6 - plotLabels.length / 50))),
            tension: 0.22,
            fill: true
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: { mode: 'index', intersect: false },
          scales: {
            x: { ticks: { autoSkip: true, maxTicksLimit: 12 }, grid: { display: false } },
            y: {
              beginAtZero: true,
              ticks: {
                callback: function(value){
                  try { return new Intl.NumberFormat('en-US', { style:'currency', currency:'PHP' }).format(value); } catch(e){ return value; }
                }
              }
            }
          },
          plugins: {
            legend: { display: false },
            tooltip: {
              callbacks: {
                label: function(ctx){
                  const y = ctx.parsed.y ?? ctx.raw ?? 0;
                  try { return ctx.dataset.label + ': ' + new Intl.NumberFormat('en-US', { style:'currency', currency:'PHP' }).format(y); } catch(e) { return ctx.dataset.label + ': ' + y; }
                }
              }
            }
          },
          animation: { duration: 400, easing: 'easeOutQuart' }
        }
      });

      // update URL (pushState) to reflect range for bookmarking/sharing
      if (pushUrl && history && history.pushState) {
        const params = new URLSearchParams(window.location.search);
        params.set('start_date', start);
        params.set('end_date', end);
        const newUrl = window.location.pathname + '?' + params.toString();
        history.pushState({}, '', newUrl);
      }

    } catch (err) {
      console.error('Revenue chart error', err);
      showError('Failed to load revenue chart', String(err));
    }
  }

  // Form submit handler
  form?.addEventListener('submit', function(e){
    e.preventDefault();
    const s = startInput.value;
    const eDate = endInput.value;
    fetchAndRender(s, eDate, true);
  });

  // Reset button: reset to initial PHP defaults then fetch
  document.getElementById('mmResetRange')?.addEventListener('click', function(){
    startInput.value = '<?php echo addslashes($start_date); ?>';
    endInput.value = '<?php echo addslashes($end_date); ?>';
    fetchAndRender(startInput.value, endInput.value, true);
  });

  // Initial load using form values already filled by PHP
  fetchAndRender(startInput.value, endInput.value, false);

})();
</script>
<?php endif; ?>

<script>
(function(){
  const STORAGE_KEY = 'reports_activities_expanded';
  const btn = document.getElementById('toggleActivitiesBtn');
  const label = document.getElementById('toggleActivitiesLabel');
  const container = document.getElementById('activitiesContainer');

  let expanded = true;
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v !== null) expanded = v === '1';
  } catch (e) {}

  function applyState() {
    if (!container) return;
    if (expanded) {
      container.style.maxHeight = '2000px';
      container.style.overflow = 'visible';
      if (btn) btn.setAttribute('aria-expanded','true');
      if (label) label.textContent = 'Collapse';
    } else {
      container.style.maxHeight = '0px';
      container.style.overflow = 'hidden';
      if (btn) btn.setAttribute('aria-expanded','false');
      if (label) label.textContent = 'Expand';
    }
    try { localStorage.setItem(STORAGE_KEY, expanded ? '1' : '0'); } catch(e){}
  }

  if (btn) {
    btn.addEventListener('click', function(e){
      e.preventDefault();
      expanded = !expanded;
      applyState();
    });
  }

  applyState();
})();
</script>

<?php include 'includes/footer.php'; ?>