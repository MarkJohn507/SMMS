<?php
function shouldUseAdminSidebar(): bool {
    if (!isset($_SESSION) || session_status() !== PHP_SESSION_ACTIVE) session_start();
    $roles = array_map('strtolower', (array)($_SESSION['roles'] ?? []));
    if (!$roles) return false;
    $adminPanelRoles = [
        'super_admin','market_manager','accountant','inspector'
    ];
    foreach ($adminPanelRoles as $r) {
        if (in_array($r, $roles, true)) return true;
    }
    return false;
}