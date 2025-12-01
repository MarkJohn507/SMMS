<?php
/**
 * includes/auth_roles.php (Fixed)
 * Key changes:
 *  - Added fetchAllUserRoleNames() (no status filter) so pending roles appear.
 *  - refreshSessionRoles() now uses fetchAllUserRoleNames() (not _fetchUserRoleNames()) for fuller visibility.
 *  - Added shouldUseAdminSidebar() to decide if admin sidebar should be shown (includes market_manager, accountant, inspector).
 *  - Broadened isAdminPanel() (wrapper of shouldUseAdminSidebar()) if needed by other code.
 *  - Kept isAdmin() behavior (core admin only) for security gating, but you can broaden if desired.
 */

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

/* ---------------- Basic session helpers ---------------- */
if (!function_exists('isLoggedIn')) {
    function isLoggedIn(): bool {
        return !empty($_SESSION['user_id']);
    }
}
if (!function_exists('getCurrentUserId')) {
    function getCurrentUserId() {
        return $_SESSION['user_id'] ?? null;
    }
}
if (!function_exists('getSessionRoles')) {
    function getSessionRoles(): array {
        return (isset($_SESSION['roles']) && is_array($_SESSION['roles'])) ? $_SESSION['roles'] : [];
    }
}

/* --------------------------------------------------------
   Legacy fetch (ACTIVE roles only) – kept for backward use
---------------------------------------------------------*/
if (!function_exists('_fetchUserRoleNames')) {
    function _fetchUserRoleNames($uid, $db = null): array {
        $dbInst = $db ?? ($GLOBALS['db'] ?? null);
        if (!$dbInst || !$uid) return [];
        try {
            $rows = $dbInst->fetchAll("
                SELECT r.name
                FROM user_roles ur
                JOIN roles r ON ur.role_id = r.role_id
                WHERE ur.user_id = ? AND ur.status = 'active'
            ", [$uid]) ?: [];
            $names = [];
            foreach ($rows as $r) {
                if (!empty($r['name'])) $names[] = strtolower($r['name']);
            }
            // Fallback legacy single-role column
            if (empty($names)) {
                $u = $dbInst->fetch("SELECT role FROM users WHERE user_id = ? LIMIT 1", [$uid]);
                if (!empty($u['role'])) $names[] = strtolower($u['role']);
            }
            return array_values(array_unique($names));
        } catch (Throwable $e) {
            error_log("_fetchUserRoleNames (active only) error: " . $e->getMessage());
            return [];
        }
    }
}

/* --------------------------------------------------------
   NEW: Fetch ALL role names (no status filter)
---------------------------------------------------------*/
if (!function_exists('fetchAllUserRoleNames')) {
    function fetchAllUserRoleNames($db, int $user_id): array {
        if (!$db || !$user_id) return [];
        try {
            $rows = $db->fetchAll("
                SELECT r.name, ur.status
                FROM user_roles ur
                JOIN roles r ON ur.role_id = r.role_id
                WHERE ur.user_id = ?
            ", [$user_id]) ?: [];
            $out = [];
            foreach ($rows as $row) {
                if (!empty($row['name'])) {
                    $out[] = strtolower(trim($row['name']));
                }
            }
            // Include legacy single role if still absent
            if (empty($out)) {
                $legacy = $db->fetch("SELECT role FROM users WHERE user_id=? LIMIT 1", [$user_id]);
                if (!empty($legacy['role'])) $out[] = strtolower($legacy['role']);
            }
            return array_values(array_unique($out));
        } catch (Throwable $e) {
            error_log("fetchAllUserRoleNames error: " . $e->getMessage());
            return [];
        }
    }
}

/* --------------------------------------------------------
   Primary role: choose priority among roles stored
---------------------------------------------------------*/
if (!function_exists('getPrimaryRoleName')) {
    function getPrimaryRoleName($db = null, $user_id = null) {
        if (isset($_SESSION['primary_role'])) return $_SESSION['primary_role'];
        $uid = $user_id ?? ($_SESSION['user_id'] ?? null);
        if (!$uid) return null;
        // Use full role list (pending included)
        $names = fetchAllUserRoleNames($db ?? ($GLOBALS['db'] ?? null), (int)$uid);
        $priority = ['super_admin','municipal_admin','issuer_admin','admin','market_manager','accountant','inspector','vendor'];
        foreach ($priority as $p) {
            if (in_array($p, $names, true)) {
                $_SESSION['primary_role'] = $p;
                return $p;
            }
        }
        $_SESSION['primary_role'] = $names[0] ?? null;
        return $_SESSION['primary_role'];
    }
}

/* --------------------------------------------------------
   Sidebar decision: treat staff roles as admin panel
---------------------------------------------------------*/
if (!function_exists('shouldUseAdminSidebar')) {
    function shouldUseAdminSidebar(array $roles = null): bool {
        if ($roles === null) {
            $roles = getSessionRoles();
        }
        $roles = array_map('strtolower', (array)$roles);
        $adminPanelRoles = [
            'super_admin','municipal_admin','issuer_admin','admin',
            'market_manager','accountant','inspector'
        ];
        foreach ($adminPanelRoles as $r) {
            if (in_array($r, $roles, true)) return true;
        }
        return false;
    }
}
if (!function_exists('isAdminPanel')) {
    function isAdminPanel(): bool {
        return shouldUseAdminSidebar();
    }
}

/* --------------------------------------------------------
   Backward-compatible userIsInRole()
---------------------------------------------------------*/
if (!function_exists('userIsInRole')) {
    function userIsInRole($a = null, $b = null, $c = null): bool {
        $db = null; $uid = null; $roleName = null;

        // Legacy form: userIsInRole($db, $userId, 'role')
        if ((is_object($a) || is_array($a)) && (is_int($b) || (is_string($b) && ctype_digit($b))) && is_string($c)) {
            $db = $a; $uid = (int)$b; $roleName = $c;
        }
        // userIsInRole('role')
        elseif (is_string($a) && $b === null && $c === null) {
            $roleName = $a; $uid = $_SESSION['user_id'] ?? null;
        }
        // userIsInRole($userId, 'role')
        elseif ((is_int($a) || (is_string($a) && ctype_digit($a))) && is_string($b) && $c === null) {
            $uid = (int)$a; $roleName = $b;
        } else {
            // Invalid arguments — be forgiving and return false
            return false;
        }

        if (!$roleName || !$uid) return false;
        $roleName = strtolower($roleName);

        // Session quick path
        if (!empty($_SESSION['user_id']) && (int)$_SESSION['user_id'] === (int)$uid) {
            $sessionRoles = array_map('strtolower', getSessionRoles());
            if (in_array($roleName, $sessionRoles, true)) return true;
        }

        // DB fallback (ALL roles, not just active)
        $names = fetchAllUserRoleNames($db ?? ($GLOBALS['db'] ?? null), (int)$uid);
        return in_array($roleName, $names, true);
    }
}

/* --------------------------------------------------------
   isAdmin(): keep core admin definition (security gating)
   If you want market_manager to count as “admin” in guards,
   add 'market_manager' to $core.
---------------------------------------------------------*/
if (!function_exists('isAdmin')) {
    function isAdmin(): bool {
        $roles = array_map('strtolower', getSessionRoles());
        $core = ['super_admin','municipal_admin','issuer_admin','admin'];
        foreach ($core as $r) if (in_array($r, $roles, true)) return true;

        // DB fallback if session empty/stale
        if (empty($roles) && !empty($_SESSION['user_id'])) {
            $names = fetchAllUserRoleNames($GLOBALS['db'] ?? null, (int)$_SESSION['user_id']);
            foreach ($core as $r) if (in_array($r, $names, true)) return true;
        }
        return false;
    }
}

/* ---------------- Authorization guards ---------------- */
if (!function_exists('requireLogin')) {
    function requireLogin() {
        if (!isLoggedIn()) {
            $_SESSION['intended_url'] = $_SERVER['REQUEST_URI'] ?? '/';
            redirect('login.php');
        }
    }
}

if (!function_exists('requireVendor')) {
    function requireVendor() {
        if (!isLoggedIn()) redirect('login.php?timeout=1');
        $primary = $_SESSION['primary_role'] ?? getPrimaryRoleName($GLOBALS['db'] ?? null, $_SESSION['user_id'] ?? null);
        if (shouldUseAdminSidebar()) {
            // Redirect staff/admin users away from vendor-only area
            redirect('admin_dashboard.php');
        }
        // Allow vendor or other non-admin roles
    }
}

if (!function_exists('requireAdmin')) {
    function requireAdmin() {
        if (!isLoggedIn()) redirect('login.php?timeout=1');
        if (!isAdmin()) {
            // If explicitly vendor as primary, send to vendor dashboard
            if (!empty($_SESSION['primary_role']) && $_SESSION['primary_role'] === 'vendor') {
                redirect('vendor_dashboard.php');
            }
            http_response_code(403);
            echo "Forbidden";
            exit;
        }
    }
}

/* ---------------- Market management guard ---------------- */
if (!function_exists('ensure_can_manage_markets')) {
    function ensure_can_manage_markets($db = null) {
        if (!isLoggedIn()) redirect('login.php?timeout=1');
        // Staff roles considered
        if (shouldUseAdminSidebar()) return;
        http_response_code(403);
        echo "Forbidden";
        exit;
    }
}

/* ---------------- Role refresh ---------------- */
if (!function_exists('refreshSessionRoles')) {
    function refreshSessionRoles($db = null) {
        $uid = $_SESSION['user_id'] ?? null;
        if (!$uid) return false;

        // Clear cached primary role so recalculation always reflects DB state
        unset($_SESSION['primary_role']);

        $dbInst = $db ?? ($GLOBALS['db'] ?? null);
        if (!$dbInst) {
            error_log("refreshSessionRoles called but no DB instance provided.");
            // Still attempt to preserve session roles if present
            return false;
        }

        $names = fetchAllUserRoleNames($dbInst, (int)$uid);
        $_SESSION['roles'] = $names;

        $priority = ['super_admin','municipal_admin','issuer_admin','admin','market_manager','accountant','inspector','vendor'];
        $primary = null;
        foreach ($priority as $p) {
            if (in_array($p, $names, true)) { $primary = $p; break; }
        }
        if (!$primary && !empty($names)) $primary = $names[0] ?? null;
        $_SESSION['primary_role'] = $primary ?? null;

        // Maintain legacy is_admin flag (core admin only)
        $_SESSION['is_admin'] = in_array($_SESSION['primary_role'], ['super_admin','municipal_admin','issuer_admin','admin'], true);
        return true;
    }
}