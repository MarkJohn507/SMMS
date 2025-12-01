<?php
require_once 'config.php';
require_once 'includes/auth_roles.php';   // try to load auth helpers (may define hasRoleInScope)
require_once 'includes/audit.php';
require_once 'includes/csrf.php';
require_once 'includes/notifications.php'; // best-effort notifications

// Fallback: define hasRoleInScope() if the auth_roles include doesn't provide it.
// This prevents fatal errors on installs where auth_roles.php is missing that helper.
// The fallback is conservative: it checks the users/user_roles tables to see if the user has the given role.
// Signature: hasRoleInScope($db, $user_id, $roleName, $scope = null, $scopeId = null)
if (!function_exists('hasRoleInScope')) {
    function hasRoleInScope($db, $user_id, $roleName, $scope = null, $scopeId = null) {
        try {
            if (empty($user_id) || empty($roleName)) return false;

            // Basic lookup: first check user_roles table for matching role name (via roles table) and optional organization/market scope.
            // Expect schema: user_roles(user_id, role_id, organization_id, market_id, status)
            // and roles(role_id, name)
            $sql = "SELECT COUNT(*) AS cnt
                    FROM user_roles ur
                    JOIN roles r ON ur.role_id = r.role_id
                    WHERE ur.user_id = ? AND r.name = ? AND ur.status = 'active'";
            $params = [$user_id, $roleName];

            // If scope provided, attempt to match organization or market depending on parameter content.
            if (!empty($scope) && !empty($scopeId)) {
                // support common scope names
                if (in_array(strtolower($scope), ['organization','org','organization_id'])) {
                    $sql .= " AND ur.organization_id = ?";
                    $params[] = $scopeId;
                } elseif (in_array(strtolower($scope), ['market','market_id'])) {
                    $sql .= " AND ur.market_id = ?";
                    $params[] = $scopeId;
                } else {
                    // generic scope column attempt (sanitized)
                    $col = preg_replace('/[^a-z0-9_]/i','', $scope);
                    $sql .= " AND COALESCE(ur.{$col}, '') = ?";
                    $params[] = $scopeId;
                }
            }

            $row = $db->fetch($sql, $params);
            return !empty($row) && (int)($row['cnt'] ?? 0) > 0;
        } catch (Throwable $e) {
            error_log("hasRoleInScope fallback error: " . $e->getMessage());
            return false;
        }
    }
}

// Only super_admin should manage organizations
if (!isset($_SESSION['user_id']) || !hasRoleInScope($db, $_SESSION['user_id'], 'super_admin', null, null)) {
    http_response_code(403);
    echo "Forbidden: you must be a super admin to access this page.";
    exit;
}

// --- the rest of your existing manage_organizations.php follows ---
// (I include the full rest of the file below; keep it as-is from your previous version)

$page_title = 'Manage Organizations';
$error = '';
$success = '';

// Handle Create Organization
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create_organization'])) {
    // CSRF protection
    if (!csrf_validate_request()) {
        $error = 'Invalid CSRF token.';
    } else {
        $name = sanitize($_POST['organization_name'] ?? '');
        $description = sanitize($_POST['description'] ?? '');

        if (empty($name)) {
            $error = 'Organization name is required.';
        } else {
            // Prevent duplicates
            try {
                $exists = $db->fetch("SELECT organization_id FROM organizations WHERE organization_name = ? LIMIT 1", [$name]);
            } catch (Throwable $e) {
                error_log("manage_organizations: DB error checking exists: " . $e->getMessage());
                $exists = null;
            }

            if ($exists) {
                $error = 'Organization with that name already exists.';
            } else {
                try {
                    $ok = $db->query("INSERT INTO organizations (organization_name, description, created_at) VALUES (?, ?, NOW())", [$name, $description]);
                    if ($ok) {
                        $org_id = $db->lastInsertId();
                        logAudit($db, $_SESSION['user_id'], 'Organization Created', 'organizations', $org_id, null, null);

                        // Notify creator (best-effort)
                        if (function_exists('createNotification')) {
                            try {
                                createNotification($db, $_SESSION['user_id'], 'Organization Created', "Organization '{$name}' created.", 'success', 'organization', $org_id, 'organizations');
                            } catch (Throwable $e) {
                                error_log("manage_organizations: createNotification failed: " . $e->getMessage());
                            }
                        }

                        $success = 'Organization created successfully.';
                    } else {
                        $error = 'Failed to create organization.';
                    }
                } catch (Throwable $e) {
                    error_log("manage_organizations: insert error: " . $e->getMessage());
                    $error = 'Failed to create organization (server error).';
                }
            }
        }
    }
}

// Handle Update Organization
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_organization'])) {
    // CSRF protection
    if (!csrf_validate_request()) {
        $error = 'Invalid CSRF token.';
    } else {
        $org_id = (int)($_POST['organization_id'] ?? 0);
        $name = sanitize($_POST['organization_name'] ?? '');
        $description = sanitize($_POST['description'] ?? '');

        if ($org_id <= 0) {
            $error = 'Invalid organization.';
        } elseif (empty($name)) {
            $error = 'Organization name is required.';
        } else {
            try {
                // Check duplicate name excluding current
                $dup = $db->fetch("SELECT organization_id FROM organizations WHERE organization_name = ? AND organization_id <> ? LIMIT 1", [$name, $org_id]);
            } catch (Throwable $e) {
                error_log("manage_organizations: DB error checking duplicate: " . $e->getMessage());
                $dup = null;
            }

            if ($dup) {
                $error = 'Another organization with that name already exists.';
            } else {
                try {
                    $ok = $db->query("UPDATE organizations SET organization_name = ?, description = ?, updated_at = NOW() WHERE organization_id = ?", [$name, $description, $org_id]);
                    if ($ok) {
                        logAudit($db, $_SESSION['user_id'], 'Organization Updated', 'organizations', $org_id, null, null);

                        if (function_exists('createNotification')) {
                            try {
                                createNotification($db, $_SESSION['user_id'], 'Organization Updated', "Organization '{$name}' updated.", 'info', 'organization', $org_id, 'organizations');
                            } catch (Throwable $e) {
                                error_log("manage_organizations: createNotification failed (update): " . $e->getMessage());
                            }
                        }

                        $success = 'Organization updated successfully.';
                    } else {
                        $error = 'Failed to update organization.';
                    }
                } catch (Throwable $e) {
                    error_log("manage_organizations: update error: " . $e->getMessage());
                    $error = 'Failed to update organization (server error).';
                }
            }
        }
    }
}

// Handle Delete Organization (kept as GET for backward compatibility, but validated)
if (isset($_GET['delete']) && !empty($_GET['delete'])) {
    $org_id = (int)$_GET['delete'];
    if ($org_id <= 0) {
        $error = 'Invalid organization.';
    } else {
        try {
            // Prevent delete if markets or user_roles reference it
            $marketCountRow = $db->fetch("SELECT COUNT(*) AS cnt FROM markets WHERE organization_id = ?", [$org_id]);
            $marketCount = (int)($marketCountRow['cnt'] ?? 0);
            $roleCountRow = $db->fetch("SELECT COUNT(*) AS cnt FROM user_roles WHERE organization_id = ?", [$org_id]);
            $roleCount = (int)($roleCountRow['cnt'] ?? 0);
        } catch (Throwable $e) {
            error_log("manage_organizations: error checking references before delete: " . $e->getMessage());
            $marketCount = 1;
            $roleCount = 1;
        }

        if ($marketCount > 0) {
            $error = 'Cannot delete organization while markets are assigned to it. Reassign or remove markets first.';
        } elseif ($roleCount > 0) {
            $error = 'Cannot delete organization while users are assigned to it. Reassign or remove role assignments first.';
        } else {
            try {
                $ok = $db->query("DELETE FROM organizations WHERE organization_id = ?", [$org_id]);
                if ($ok) {
                    logAudit($db, $_SESSION['user_id'], 'Organization Deleted', 'organizations', $org_id, null, null);
                    $success = 'Organization deleted successfully.';
                } else {
                    $error = 'Failed to delete organization.';
                }
            } catch (Throwable $e) {
                error_log("manage_organizations: delete error: " . $e->getMessage());
                $error = 'Failed to delete organization (server error).';
            }
        }
    }
}

// Fetch organizations and counts (defensive)
try {
    $organizations = $db->fetchAll("SELECT o.*,
        (SELECT COUNT(*) FROM markets m WHERE m.organization_id = o.organization_id) AS market_count,
        (SELECT COUNT(*) FROM user_roles ur WHERE ur.organization_id = o.organization_id) AS role_count
        FROM organizations o
        ORDER BY o.organization_name ASC");
} catch (Throwable $e) {
    error_log("manage_organizations: fetchAll error: " . $e->getMessage());
    $organizations = [];
}

include 'includes/header.php';
include 'includes/admin_sidebar.php';
?>
<div class="mb-6">
    <h3 class="text-2xl font-bold text-gray-800 mb-2">Manage Organizations</h3>
    <p class="text-gray-600">Create and manage organizations (e.g., barangay, municipal agency). Only system super admins can access this page.</p>
</div>

<?php if ($error): ?>
    <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-6" role="alert"><?php echo htmlspecialchars($error); ?></div>
<?php endif; ?>
<?php if ($success): ?>
    <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-6" role="alert"><?php echo htmlspecialchars($success); ?></div>
<?php endif; ?>

<!-- Create Organization Form -->
<div class="bg-white rounded-lg shadow-md p-6 mb-6">
    <h4 class="text-lg font-semibold text-gray-800 mb-4">Create Organization</h4>
    <form method="POST" action="">
        <?php echo csrf_field(); ?>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div class="md:col-span-2">
                <label class="block text-sm font-medium text-gray-700 mb-2">Organization Name *</label>
                <input name="organization_name" type="text" required class="w-full px-4 py-2 border border-gray-300 rounded-lg" placeholder="e.g., Barangay Centro">
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2"> </label>
                <button name="create_organization" type="submit" class="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700">Create</button>
            </div>
            <div class="md:col-span-3">
                <label class="block text-sm font-medium text-gray-700 mb-2">Description</label>
                <textarea name="description" rows="2" class="w-full px-4 py-2 border border-gray-300 rounded-lg" placeholder="Optional description"></textarea>
            </div>
        </div>
    </form>
</div>

<!-- Organizations List -->
<div class="bg-white rounded-lg shadow-md p-6">
    <h4 class="text-lg font-semibold text-gray-800 mb-4">Existing Organizations</h4>

    <?php if ($organizations && count($organizations) > 0): ?>
        <div class="space-y-4">
            <?php foreach ($organizations as $org): ?>
                <div class="border border-gray-100 rounded p-4 flex items-start justify-between">
                    <div>
                        <p class="font-semibold text-gray-800"><?php echo htmlspecialchars($org['organization_name']); ?></p>
                        <?php if (!empty($org['description'])): ?>
                            <p class="text-sm text-gray-600 mt-1"><?php echo htmlspecialchars($org['description']); ?></p>
                        <?php endif; ?>
                        <p class="text-xs text-gray-500 mt-2">Markets: <?php echo (int)$org['market_count']; ?> • Assigned Roles: <?php echo (int)$org['role_count']; ?></p>
                    </div>
                    <div class="flex gap-2">
                        <button onclick="openEditModal(<?php echo json_encode($org, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT); ?>)" class="bg-yellow-500 text-white px-3 py-1 rounded hover:bg-yellow-600 text-sm">Edit</button>
                        <?php if ((int)$org['market_count'] === 0 && (int)$org['role_count'] === 0): ?>
                            <a href="?delete=<?php echo (int)$org['organization_id']; ?>" onclick="return confirm('Delete organization <?php echo htmlspecialchars(addslashes($org['organization_name'])); ?>?');" class="bg-red-600 text-white px-3 py-1 rounded hover:bg-red-700 text-sm">Delete</a>
                        <?php else: ?>
                            <button disabled class="bg-gray-300 text-gray-700 px-3 py-1 rounded text-sm" title="Cannot delete while referenced">Delete</button>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    <?php else: ?>
        <div class="text-center py-6 text-gray-600">No organizations yet. Create one using the form above.</div>
    <?php endif; ?>
</div>

<!-- Edit Modal -->
<div id="editModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
    <div class="bg-white rounded-lg max-w-xl w-full">
        <div class="p-6">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-xl font-semibold">Edit Organization</h3>
                <button onclick="closeEditModal()" class="text-gray-500 hover:text-gray-700" aria-label="Close">✕</button>
            </div>
            <form method="POST" action="">
                <?php echo csrf_field(); ?>
                <input type="hidden" name="organization_id" id="edit_org_id">
                <div class="mb-4">
                    <label class="block text-sm font-medium text-gray-700 mb-2">Organization Name *</label>
                    <input id="edit_org_name" name="organization_name" type="text" required class="w-full px-4 py-2 border border-gray-300 rounded-lg">
                </div>
                <div class="mb-4">
                    <label class="block text-sm font-medium text-gray-700 mb-2">Description</label>
                    <textarea id="edit_org_description" name="description" rows="3" class="w-full px-4 py-2 border border-gray-300 rounded-lg"></textarea>
                </div>
                <div class="flex gap-2">
                    <button type="submit" name="update_organization" class="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">Save</button>
                    <button type="button" onclick="closeEditModal()" class="bg-gray-300 text-gray-700 px-4 py-2 rounded hover:bg-gray-400">Cancel</button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
function openEditModal(org) {
    try {
        if (typeof org === 'string') org = JSON.parse(org);
    } catch(e) {}
    document.getElementById('edit_org_id').value = org.organization_id || '';
    document.getElementById('edit_org_name').value = org.organization_name || '';
    document.getElementById('edit_org_description').value = org.description || '';
    document.getElementById('editModal').classList.remove('hidden');
}
function closeEditModal() {
    document.getElementById('editModal').classList.add('hidden');
}
</script>

<?php include 'includes/footer.php'; ?>