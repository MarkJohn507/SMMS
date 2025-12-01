<?php
// includes/audit.php - simple audit logger
if (!function_exists('logAudit')) {
    function logAudit($db, $user_id, $action, $table = null, $record_id = null, $old = null, $new = null) {
        try {
            $ip = $_SERVER['REMOTE_ADDR'] ?? null;
            $ctx = null;
            $db->query("INSERT INTO audit_logs (user_id, action, table_name, record_id, old_value, new_value, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?)", [
                $user_id, $action, $table, $record_id, $old, $new, $ip
            ]);
        } catch (Exception $e) {
            // do not block page on audit failure
            error_log("Audit failed: " . $e->getMessage());
        }
    }
}