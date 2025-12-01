<?php
// Replace the existing "priority" / primary-role selection block in your login flow
// with this function + usage. Insert it right after you build $roles (the active role names array).

/**
 * Compute primary role given list of roles and a priority list.
 * Ensures management/admin roles are selected before vendor.
 */
function computePrimaryRole(array $roles): ?string {
    // priority: highest first
    $priority = [
        'super_admin',
        'municipal_admin',
        'issuer_admin',
        'market_manager',
        'admin',
        'accountant',
        'inspector',
        'vendor'
    ];

    foreach ($priority as $p) {
        if (in_array($p, $roles, true)) {
            return $p;
        }
    }

    // fallback: return first role or null
    return $roles[0] ?? null;
}

/*
Usage: replace whatever you currently do for primary role selection with:

    $_SESSION['roles'] = $roleNames;    // or $roles depending on your variable
    $_SESSION['primary_role'] = computePrimaryRole($_SESSION['roles']);

Make sure any subsequent logic uses $_SESSION['primary_role'] for redirects.
*/