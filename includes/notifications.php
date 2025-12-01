<?php
// includes/notifications.php
// Notification helpers for the application with defensive handling for missing dependencies.
//
// This file ensures:
// - audit helper is loaded (required by various callers).
// - a safe fallback logAudit() exists if your audit helper is missing.
// - createNotification and other helpers check for the notifications table and do not throw fatal errors.

$__notifications_dir = __DIR__;

// Ensure audit helper is available (logAudit)
if (file_exists($__notifications_dir . '/audit.php')) {
    require_once $__notifications_dir . '/audit.php';
} elseif (file_exists(__DIR__ . '/../includes/audit.php')) {
    // in case this file is included from root and includes/ is sibling
    require_once __DIR__ . '/../includes/audit.php';
} else {
    // Defensive fallback: define minimal logAudit if not already defined
    if (!function_exists('logAudit')) {
        /**
         * Minimal fallback logAudit implementation.
         * Writes a simple line to PHP error_log so calls won't fatally error.
         * Signature matches common usage: logAudit($db, $user_id, $action, $entity, $entity_id = null, $from = null, $to = null)
         */
        function logAudit($db = null, $user_id = null, $action = '', $entity = '', $entity_id = null, $from = null, $to = null) {
            $msg = sprintf(
                "[AUDIT] user:%s action:%s entity:%s entity_id:%s from:%s to:%s time:%s",
                $user_id ?? 'unknown',
                $action,
                $entity,
                $entity_id ?? 'null',
                is_scalar($from) ? $from : json_encode($from),
                is_scalar($to) ? $to : json_encode($to),
                date('Y-m-d H:i:s')
            );
            error_log($msg);
            return true;
        }
    }
}

// Helper: check if notifications table exists (cache per-request)
if (!isset($GLOBALS['__notifications_table_exists_checked'])) {
    $GLOBALS['__notifications_table_exists_checked'] = false;
    $GLOBALS['__notifications_table_exists'] = false;
}
function __notifications_table_exists($db) {
    if ($GLOBALS['__notifications_table_exists_checked']) {
        return $GLOBALS['__notifications_table_exists'];
    }
    $GLOBALS['__notifications_table_exists_checked'] = true;
    try {
        // Use information_schema to determine existence
        $row = $db->fetch("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'notifications' LIMIT 1");
        $exists = (bool)$row;
        $GLOBALS['__notifications_table_exists'] = $exists;
        return $exists;
    } catch (Throwable $e) {
        error_log("notifications: table existence check failed: " . $e->getMessage());
        $GLOBALS['__notifications_table_exists'] = false;
        return false;
    }
}

if (!function_exists('createNotification')) {
    /**
     * Create an in-app notification for a user.
     *
     * @param object $db DB wrapper with fetch/query methods
     * @param int $user_id recipient user id
     * @param string $title
     * @param string $message
     * @param string $type
     * @param string $category
     * @param int|null $related_id
     * @param string|null $related_table
     * @return bool
     */
    function createNotification($db, $user_id, $title, $message, $type = 'info', $category = 'general', $related_id = null, $related_table = null) {
        try {
            if (!$db) {
                error_log("createNotification: missing db connection");
                return false;
            }
            if (!__notifications_table_exists($db)) {
                // Fallback: log to error_log and return false (no DB table)
                error_log("createNotification: notifications table not found. user={$user_id} title={$title}");
                // Still write an audit entry so there's a trace
                if (function_exists('logAudit')) {
                    @logAudit($db, $_SESSION['user_id'] ?? null, 'Notification (fallback log)', 'notifications', null, null, json_encode(['to'=>$user_id,'title'=>$title]));
                }
                return false;
            }
            $sql = "INSERT INTO notifications (user_id, title, message, type, category, related_id, related_table, is_read, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, NOW())";
            $db->query($sql, [$user_id, $title, $message, $type, $category, $related_id, $related_table]);
            // Audit the notification creation if audit helper available
            if (function_exists('logAudit')) {
                try { logAudit($db, $_SESSION['user_id'] ?? null, 'Notification Created', 'notifications', null, null, $title); } catch (Throwable $e) {}
            }
            return true;
        } catch (Throwable $e) {
            error_log("createNotification failed: " . $e->getMessage());
            return false;
        }
    }
}

if (!function_exists('getUnreadCount')) {
    function getUnreadCount($db, $user_id) {
        try {
            if (!$db || !__notifications_table_exists($db)) return 0;
            $r = $db->fetch("SELECT COUNT(*) AS cnt FROM notifications WHERE user_id = ? AND is_read = 0", [$user_id]);
            return (int)($r['cnt'] ?? 0);
        } catch (Throwable $e) {
            error_log("getUnreadCount failed: " . $e->getMessage());
            return 0;
        }
    }
}

if (!function_exists('getNotifications')) {
    function getNotifications($db, $user_id, $limit = 20, $offset = 0) {
        try {
            if (!$db || !__notifications_table_exists($db)) return [];
            $limit = (int)$limit;
            $offset = (int)$offset;
            return $db->fetchAll("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT {$limit} OFFSET {$offset}", [$user_id]);
        } catch (Throwable $e) {
            error_log("getNotifications failed: " . $e->getMessage());
            return [];
        }
    }
}

if (!function_exists('markAsRead')) {
    function markAsRead($db, $notification_id) {
        try {
            if (!$db || !__notifications_table_exists($db)) return false;
            $db->query("UPDATE notifications SET is_read = 1, read_at = NOW() WHERE notification_id = ?", [$notification_id]);
            if (function_exists('logAudit')) {
                try { logAudit($db, $_SESSION['user_id'] ?? null, 'Notification Read', 'notifications', $notification_id); } catch (Throwable $e) {}
            }
            return true;
        } catch (Throwable $e) {
            error_log("markAsRead failed: " . $e->getMessage());
            return false;
        }
    }
}

if (!function_exists('markAllAsRead')) {
    function markAllAsRead($db, $user_id) {
        try {
            if (!$db || !__notifications_table_exists($db)) return false;
            $db->query("UPDATE notifications SET is_read = 1, read_at = NOW() WHERE user_id = ? AND is_read = 0", [$user_id]);
            if (function_exists('logAudit')) {
                try { logAudit($db, $_SESSION['user_id'] ?? null, 'Notifications Marked Read', 'notifications', null); } catch (Throwable $e) {}
            }
            return true;
        } catch (Throwable $e) {
            error_log("markAllAsRead failed: " . $e->getMessage());
            return false;
        }
    }
}

if (!function_exists('deleteNotification')) {
    function deleteNotification($db, $notification_id) {
        try {
            if (!$db || !__notifications_table_exists($db)) return false;
            $db->query("DELETE FROM notifications WHERE notification_id = ?", [$notification_id]);
            if (function_exists('logAudit')) {
                try { logAudit($db, $_SESSION['user_id'] ?? null, 'Notification Deleted', 'notifications', $notification_id); } catch (Throwable $e) {}
            }
            return true;
        } catch (Throwable $e) {
            error_log("deleteNotification failed: " . $e->getMessage());
            return false;
        }
    }
}

if (!function_exists('deleteAllRead')) {
    function deleteAllRead($db, $user_id) {
        try {
            if (!$db || !__notifications_table_exists($db)) return false;
            $db->query("DELETE FROM notifications WHERE user_id = ? AND is_read = 1", [$user_id]);
            return true;
        } catch (Throwable $e) {
            error_log("deleteAllRead failed: " . $e->getMessage());
            return false;
        }
    }
}

if (!function_exists('getNotificationIcon')) {
    function getNotificationIcon($type = 'info') {
        switch ($type) {
            case 'success':
                return '<svg class="w-6 h-6 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>';
            case 'warning':
                return '<svg class="w-6 h-6 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4M12 17h.01"/></svg>';
            case 'danger':
                return '<svg class="w-6 h-6 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2 2 2m0-6v4"/></svg>';
            case 'info':
            default:
                return '<svg class="w-6 h-6 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M12 2a10 10 0 100 20 10 10 0 000-20z"/></svg>';
        }
    }
}