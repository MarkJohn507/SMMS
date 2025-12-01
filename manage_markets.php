<?php
require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/csrf.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

/**
 * Return array of market_ids managed by $userId.
 */
function getManagedMarketIds($db, int $userId): array {
    $ids = [];
    try {
        $rows = $db->fetchAll("SELECT market_id FROM market_managers WHERE user_id = ?", [$userId]) ?: [];
        foreach ($rows as $r) {
            if (!empty($r['market_id'])) $ids[] = (int)$r['market_id'];
        }
    } catch (Throwable $e) {
        error_log("getManagedMarketIds: market_managers query failed: " . $e->getMessage());
    }

    if (empty($ids)) {
        try {
            $rows = $db->fetchAll("SELECT market_id FROM markets WHERE created_by = ?", [$userId]) ?: [];
            foreach ($rows as $r) {
                if (!empty($r['market_id'])) $ids[] = (int)$r['market_id'];
            }
        } catch (Throwable $e) {
            error_log("getManagedMarketIds: fallback markets.created_by query failed: " . $e->getMessage());
        }
    }

    return array_values(array_unique($ids));
}

/**
 * Check if user has an approved permit document (for ANY role they hold).
 * We treat doc_type='permit' and status='approved' in user_role_documents as verified.
 */
function userHasApprovedPermit($db, int $userId): bool {
    try {
        $row = $db->fetch("
            SELECT 1
            FROM user_role_documents d
            JOIN user_roles ur ON d.user_role_id = ur.user_role_id
            JOIN roles r ON ur.role_id = r.role_id
            WHERE ur.user_id = ?
              AND d.doc_type = 'permit'
              AND LOWER(d.status) = 'approved'
            LIMIT 1
        ", [$userId]);
        return (bool)$row;
    } catch (Throwable $e) {
        error_log("userHasApprovedPermit: query failed for user {$userId}: ".$e->getMessage());
        return false;
    }
}

/**
 * Authorization guard.
 */
function ensure_can_manage_markets($db, ?int $marketId = null) {
    $uid = $_SESSION['user_id'] ?? null;
    if (!$uid) {
        redirect('login.php');
    }

    $adminRoles = ['super_admin', 'municipal_admin', 'issuer_admin', 'admin', 'agency_admin'];
    foreach ($adminRoles as $r) {
        if (function_exists('userIsInRole') && userIsInRole($db, $uid, $r)) {
            return true;
        }
    }

    if (function_exists('userHasPermission')) {
        try {
            if (userHasPermission($db, $uid, 'manage_markets')) {
                return true;
            }
        } catch (Throwable $e) {
            error_log("ensure_can_manage_markets: userHasPermission failed for user {$uid}: ".$e->getMessage());
        }
    }

    if (function_exists('userIsInRole') && userIsInRole($db, $uid, 'market_manager')) {
        if ($marketId === null) return true;
        $managed = getManagedMarketIds($db, $uid);
        if (in_array($marketId, $managed, true)) return true;

        error_log("AUTH DENY: market_manager user {$uid} attempted access to market {$marketId}");
        http_response_code(403);
        echo "Forbidden: you do not have permissions to manage this market.";
        exit;
    }

    $sessionRoles = $_SESSION['roles'] ?? [];
    $dbRoles = [];
    try {
        $rows = $db->fetchAll("
            SELECT r.name
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.role_id
            WHERE ur.user_id = ? AND ur.status = 'active'
        ", [$uid]) ?: [];
        foreach ($rows as $rr) {
            if (!empty($rr['name'])) $dbRoles[] = $rr['name'];
        }
    } catch (Throwable $e) {
        error_log("ensure_can_manage_markets: fetch roles for debug failed: ".$e->getMessage());
    }

    error_log("AUTH DENY: user_id={$uid} session_roles=".json_encode($sessionRoles)." db_roles=".json_encode($dbRoles));
    http_response_code(403);
    echo "Forbidden: you do not have permissions to manage markets.";
    exit;
}

// Determine market id for action guard
$actionMarketId = null;
if (isset($_GET['delete'])) {
    $actionMarketId = (int)$_GET['delete'];
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['market_id'])) {
    $actionMarketId = (int)($_POST['market_id'] ?? 0);
}
ensure_can_manage_markets($db, $actionMarketId);

$page_title = 'Manage Markets';
$error   = '';
$success = '';

$uid = $_SESSION['user_id'] ?? null;
$isMarketManager = false;
try {
    if ($uid && function_exists('userIsInRole') && userIsInRole($db, $uid, 'market_manager')) {
        $isMarketManager = true;
    }
} catch (Throwable $e) {
    error_log("manage_markets: userIsInRole check failed for user {$uid}: " . $e->getMessage());
}

/* NEW: For market manager, determine if they have verified permit */
$hasVerifiedPermit = $uid ? userHasApprovedPermit($db, $uid) : false;

/* Determine if user can add markets */
$adminRoles = ['super_admin','municipal_admin','issuer_admin','admin','agency_admin'];
$canAddMarket = false;
foreach ($adminRoles as $r) {
    if (function_exists('userIsInRole') && userIsInRole($db, $uid, $r)) {
        $canAddMarket = true;
        break;
    }
}
if (!$canAddMarket && $isMarketManager) {
    // Only allow if permit verified
    $canAddMarket = $hasVerifiedPermit;
}

/* Handle Add Market */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_market'])) {
    if (!csrf_validate_request()) {
        $error = 'Invalid CSRF token.';
    } else {
        // Additional guard: market_manager without verified permit cannot add
        if ($isMarketManager && !$hasVerifiedPermit) {
            $error = 'You cannot add a market until your business permit is verified.';
        } else {
            $market_name  = sanitize($_POST['market_name'] ?? '');
            $location     = sanitize($_POST['location'] ?? '');
            $description  = sanitize($_POST['description'] ?? '');
            $total_floors = max(1, (int)($_POST['total_floors'] ?? 1));

            if ($market_name === '' || $location === '') {
                $error = 'Market name and location are required.';
            } else {
                $created_by = $uid ?? null;
                $sql = "INSERT INTO markets (market_name, location, description, total_floors, status, created_by)
                        VALUES (?, ?, ?, ?, 'active', ?)";
                if ($db->query($sql, [$market_name, $location, $description, $total_floors, $created_by])) {
                    $market_id = $db->lastInsertId();
                    logAudit($db, $uid, 'Market Added', 'markets', $market_id, null, null);
                    if ($isMarketManager) {
                        try {
                            $db->query("INSERT IGNORE INTO market_managers (market_id, user_id) VALUES (?, ?)", [$market_id, $uid]);
                        } catch (Throwable $e) {
                            error_log("manage_markets: mapping insert failed: ".$e->getMessage());
                        }
                    }
                    $success = 'Market added successfully!';
                } else {
                    $error = 'Failed to add market.';
                }
            }
        }
    }
}

/* Handle Update Market */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_market'])) {
    if (!csrf_validate_request()) {
        $error = 'Invalid CSRF token.';
    } else {
        $market_id    = (int)($_POST['market_id'] ?? 0);
        $market_name  = sanitize($_POST['market_name'] ?? '');
        $location     = sanitize($_POST['location'] ?? '');
        $description  = sanitize($_POST['description'] ?? '');
        $total_floors = max(1, (int)($_POST['total_floors'] ?? 1));
        $status       = sanitize($_POST['status'] ?? 'active');

        if ($market_name === '' || $location === '' || $market_id <= 0) {
            $error = 'Market name and location are required.';
        } else {
            if ($isMarketManager) {
                $managed = getManagedMarketIds($db, $uid);
                if (!in_array($market_id, $managed, true)) {
                    error_log("manage_markets: market_manager {$uid} attempted update on market {$market_id} not managed by them.");
                    http_response_code(403);
                    $error = 'Forbidden: you do not have permissions to update this market.';
                }
            }
            if ($error === '') {
                $sql = "UPDATE markets
                        SET market_name = ?, location = ?, description = ?, total_floors = ?, status = ?
                        WHERE market_id = ?";
                if ($db->query($sql, [$market_name, $location, $description, $total_floors, $status, $market_id])) {
                    logAudit($db, $uid, 'Market Updated', 'markets', $market_id, null, null);
                    $success = 'Market updated successfully!';
                } else {
                    $error = 'Failed to update market.';
                }
            }
        }
    }
}

/* Handle Delete Market */
if (isset($_GET['delete']) && $_GET['delete'] !== '') {
    $market_id = (int)$_GET['delete'];

    if ($isMarketManager) {
        $managed = getManagedMarketIds($db, $uid);
        if (!in_array($market_id, $managed, true)) {
            error_log("manage_markets: market_manager {$uid} attempted delete on market {$market_id} not managed by them.");
            http_response_code(403);
            $error = 'Forbidden: you do not have permissions to delete this market.';
        }
    }

    if ($error === '') {
        $stallCount = 0;
        try {
            $stallCount = (int)($db->fetch("SELECT COUNT(*) AS c FROM stalls WHERE market_id = ?", [$market_id])['c'] ?? 0);
        } catch (Throwable $e) {
            error_log("manage_markets: stall count query failed: ".$e->getMessage());
        }

        if ($stallCount > 0) {
            $error = 'Cannot delete market with existing stalls. Remove all stalls first.';
        } else {
            if ($db->query("DELETE FROM markets WHERE market_id = ?", [$market_id])) {
                try { $db->query("DELETE FROM market_managers WHERE market_id = ?", [$market_id]); } catch (Throwable $e) {}
                logAudit($db, $uid, 'Market Deleted', 'markets', $market_id, null, null);
                $success = 'Market deleted successfully!';
            } else {
                $error = 'Failed to delete market.';
            }
        }
    }
}

/* Fetch markets list */
try {
    if ($isMarketManager) {
        $managedIds = getManagedMarketIds($db, $uid);
        if (!$managedIds) {
            $markets = [];
        } else {
            $placeholders = implode(',', array_fill(0, count($managedIds), '?'));
            $sql = "
                SELECT m.*,
                       COUNT(s.stall_id) AS total_stalls,
                       SUM(CASE WHEN s.status='available' THEN 1 ELSE 0 END) AS available_stalls,
                       SUM(CASE WHEN s.status='occupied' THEN 1 ELSE 0 END) AS occupied_stalls
                FROM markets m
                LEFT JOIN stalls s ON m.market_id = s.market_id
                WHERE m.market_id IN ($placeholders)
                GROUP BY m.market_id
                ORDER BY m.market_name
            ";
            $markets = $db->fetchAll($sql, $managedIds) ?: [];
        }
    } else {
        $sql = "
            SELECT m.*,
                   COUNT(s.stall_id) AS total_stalls,
                   SUM(CASE WHEN s.status='available' THEN 1 ELSE 0 END) AS available_stalls,
                   SUM(CASE WHEN s.status='occupied' THEN 1 ELSE 0 END) AS occupied_stalls
            FROM markets m
            LEFT JOIN stalls s ON m.market_id = s.market_id
            GROUP BY m.market_id
            ORDER BY m.market_name
        ";
        $markets = $db->fetchAll($sql) ?: [];
    }
} catch (Throwable $e) {
    error_log("manage_markets: failed to fetch markets: ".$e->getMessage());
    $markets = [];
}

include 'includes/header.php';
include 'includes/admin_sidebar.php';
?>

<section class="max-w-7xl mx-auto p-6">
    <div class="mb-6 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
            <p class="text-gray-600">
                Add, edit, and manage market facilities.
                <?php if ($isMarketManager && !$hasVerifiedPermit): ?>
                    <span class="text-red-600 font-medium">
                        Your permit is not verified. You cannot add new markets.
                    </span>
                <?php endif; ?>
            </p>
        </div>
        <?php if ($canAddMarket): ?>
            <button onclick="openAddModal()"
                    class="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition flex items-center">
                <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                          d="M12 4v16m8-8H4"></path>
                </svg>
                Add New Market
            </button>
        <?php endif; ?>
    </div>

    <?php if ($error): ?>
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-6">
            <?php echo htmlspecialchars($error); ?>
        </div>
    <?php endif; ?>

    <?php if ($success): ?>
        <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-6">
            <?php echo htmlspecialchars($success); ?>
        </div>
    <?php endif; ?>

    <?php if ($markets): ?>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <?php foreach ($markets as $market): ?>
                <div class="bg-white rounded-lg shadow-md overflow-hidden hover:shadow-lg transition">
                    <div class="bg-gradient-to-r from-blue-500 to-blue-600 text-white p-6">
                        <div class="flex items-start justify-between">
                            <div class="flex-1">
                                <h3 class="text-xl font-bold mb-2"><?php echo htmlspecialchars($market['market_name']); ?></h3>
                                <p class="text-blue-100 text-sm flex items-center">
                                    <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                              d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z"></path>
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                              d="M15 11a3 3 0 11-6 0 3 3 0 016 0z"></path>
                                    </svg>
                                    <?php echo htmlspecialchars($market['location']); ?>
                                </p>
                            </div>
                            <?php
                              if (function_exists('getStatusBadge')) {
                                  echo getStatusBadge($market['status'] ?? 'active');
                              } else {
                                  $status = htmlspecialchars($market['status'] ?? 'active');
                                  echo "<span class='px-2 py-1 rounded bg-white/20 text-xs font-semibold'>{$status}</span>";
                              }
                            ?>
                        </div>
                    </div>
                    <div class="p-6">
                        <?php if (!empty($market['description'])): ?>
                            <p class="text-gray-600 text-sm mb-4"><?php echo htmlspecialchars($market['description']); ?></p>
                        <?php endif; ?>

                        <div class="grid grid-cols-2 gap-4 mb-4">
                            <div class="bg-gray-50 rounded-lg p-3">
                                <p class="text-xs text-gray-600">Floors</p>
                                <p class="text-2xl font-bold text-gray-800"><?php echo (int)$market['total_floors']; ?></p>
                            </div>
                            <div class="bg-gray-50 rounded-lg p-3">
                                <p class="text-xs text-gray-600">Stalls</p>
                                <p class="text-2xl font-bold text-gray-800"><?php echo (int)$market['total_stalls']; ?></p>
                            </div>
                            <div class="bg-green-50 rounded-lg p-3">
                                <p class="text-xs text-green-600">Available</p>
                                <p class="text-2xl font-bold text-green-600"><?php echo (int)$market['available_stalls']; ?></p>
                            </div>
                            <div class="bg-blue-50 rounded-lg p-3">
                                <p class="text-xs text-blue-600">Occupied</p>
                                <p class="text-2xl font-bold text-blue-600"><?php echo (int)$market['occupied_stalls']; ?></p>
                            </div>
                        </div>

                        <div class="flex gap-2">
                            <button
                                onclick='openEditModal(<?php echo json_encode([
                                    'market_id' => (int)$market['market_id'],
                                    'market_name' => $market['market_name'],
                                    'location' => $market['location'],
                                    'total_floors' => (int)$market['total_floors'],
                                    'status' => $market['status'],
                                    'description' => $market['description']
                                ], JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP); ?>)'
                                class="flex-1 bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700 transition text-sm">
                                Edit
                            </button>
                            <a
                                href="manage_stalls.php?market_id=<?php echo (int)$market['market_id']; ?>"
                                class="flex-1 bg-green-600 text-white py-2 rounded-lg hover:bg-green-700 transition text-sm text-center">
                                View Stalls
                            </a>
                            <?php if ((int)$market['total_stalls'] === 0): ?>
                                <button
                                    onclick="confirmDelete(<?php echo (int)$market['market_id']; ?>,'<?php echo htmlspecialchars($market['market_name']); ?>')"
                                    class="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition text-sm">
                                    Delete
                                </button>
                            <?php endif; ?>
                        </div>
                    </div>
                    <div class="bg-gray-50 px-6 py-3 text-xs text-gray-500">
                        Created: <?php echo htmlspecialchars(formatDate($market['created_at'])); ?>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    <?php else: ?>
        <div class="bg-white rounded-lg shadow-md p-16 text-center">
            <svg class="w-24 h-24 mx-auto mb-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                      d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/>
            </svg>
            <h3 class="text-xl font-semibold text-gray-700 mb-2">No markets yet</h3>
            <p class="text-gray-500 mb-6">
                <?php if ($isMarketManager && !$hasVerifiedPermit): ?>
                    You must have a verified permit before adding your first market.
                <?php else: ?>
                    Get started by adding your first market facility.
                <?php endif; ?>
            </p>
            <?php if ($canAddMarket): ?>
                <button onclick="openAddModal()" class="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition">
                    Add New Market
                </button>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <!-- Add Market Modal -->
    <div id="addModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
        <div class="bg-white rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div class="p-6">
                <div class="flex items-center justify-between mb-6">
                    <h3 class="text-2xl font-bold text-gray-800">Add New Market</h3>
                    <button onclick="closeAddModal()" class="text-gray-500 hover:text-gray-700" aria-label="Close">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                  d="M6 18L18 6M6 6l12 12"/>
                        </svg>
                    </button>
                </div>
                <?php if (!$canAddMarket): ?>
                    <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-4 text-sm">
                        You cannot add a market. <?php if ($isMarketManager && !$hasVerifiedPermit): ?>
                        Your permit is not verified yet.
                        <?php else: ?>Insufficient permissions.<?php endif; ?>
                    </div>
                <?php else: ?>
                    <form method="POST">
                        <?php echo csrf_field(); ?>
                        <div class="space-y-4">
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Market Name *</label>
                                <input type="text" name="market_name" required class="w-full px-4 py-2 border rounded" placeholder="e.g., Main Community Market">
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Location *</label>
                                <input type="text" name="location" required class="w-full px-4 py-2 border rounded" placeholder="e.g., Barangay Centro, Manila">
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Total Floors *</label>
                                <input type="number" name="total_floors" required min="1" value="1" class="w-full px-4 py-2 border rounded">
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Description</label>
                                <textarea name="description" rows="4" class="w-full px-4 py-2 border rounded"></textarea>
                            </div>
                            <div class="flex gap-4 pt-4">
                                <button type="submit" name="add_market" class="flex-1 bg-blue-600 text-white py-3 rounded">Add Market</button>
                                <button type="button" onclick="closeAddModal()" class="flex-1 bg-gray-300 py-3 rounded">Cancel</button>
                            </div>
                        </div>
                    </form>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Edit Market Modal -->
    <div id="editModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
        <div class="bg-white rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div class="p-6">
                <div class="flex items-center justify-between mb-6">
                    <h3 class="text-2xl font-bold text-gray-800">Edit Market</h3>
                    <button onclick="closeEditModal()" class="text-gray-500 hover:text-gray-700" aria-label="Close">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                  d="M6 18L18 6M6 6l12 12"/>
                        </svg>
                    </button>
                </div>

                <form method="POST">
                    <?php echo csrf_field(); ?>
                    <input type="hidden" name="market_id" id="edit_market_id">
                    <div class="space-y-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Market Name *</label>
                            <input type="text" name="market_name" id="edit_market_name" required class="w-full px-4 py-2 border rounded">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Location *</label>
                            <input type="text" name="location" id="edit_location" required class="w-full px-4 py-2 border rounded">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Total Floors *</label>
                            <input type="number" name="total_floors" id="edit_total_floors" required min="1" class="w-full px-4 py-2 border rounded">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Status *</label>
                            <select name="status" id="edit_status" class="w-full px-4 py-2 border rounded">
                                <option value="active">Active</option>
                                <option value="inactive">Inactive</option>
                            </select>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Description</label>
                            <textarea name="description" id="edit_description" rows="4" class="w-full px-4 py-2 border rounded"></textarea>
                        </div>
                        <div class="flex gap-4 pt-4">
                            <button type="submit" name="update_market" class="flex-1 bg-blue-600 text-white py-3 rounded">Update Market</button>
                            <button type="button" onclick="closeEditModal()" class="flex-1 bg-gray-300 py-3 rounded">Cancel</button>
                        </div>
                    </div>
                </form>

            </div>
        </div>
    </div>
</section>

<script>
function openAddModal() { document.getElementById('addModal').classList.remove('hidden'); }
function closeAddModal() { document.getElementById('addModal').classList.add('hidden'); }

function openEditModal(market) {
    document.getElementById('edit_market_id').value = market.market_id;
    document.getElementById('edit_market_name').value = market.market_name;
    document.getElementById('edit_location').value = market.location;
    document.getElementById('edit_total_floors').value = market.total_floors;
    document.getElementById('edit_status').value = market.status;
    document.getElementById('edit_description').value = market.description || '';
    document.getElementById('editModal').classList.remove('hidden');
}
function closeEditModal() { document.getElementById('editModal').classList.add('hidden'); }

function confirmDelete(marketId, marketName) {
    if (confirm('Delete "' + marketName + '"? This cannot be undone.')) {
        window.location.href = '?delete=' + marketId;
    }
}
</script>

<?php include 'includes/footer.php'; ?>