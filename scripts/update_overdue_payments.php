<?php
/**
 * scripts/update_overdue_payments.php
 *
 * Marks payments as 'overdue' when:
 *   - status IN ('pending','partial')
 *   - due_date < CURRENT_DATE
 *   - DAY(due_date) <= 5 (or simply any past due_date; adjust logic as needed)
 *
 * Run daily via cron (e.g., every midnight):
 *   0 0 * * * /usr/bin/php /path/to/app/scripts/update_overdue_payments.php >> /path/to/app/logs/overdue.log 2>&1
 */

declare(strict_types=1);
require_once __DIR__ . '/../config.php';

echo "[".date('Y-m-d H:i:s')."] Overdue update start\n";

try {
    $affected = $db->query("
        UPDATE payments
        SET status='overdue', updated_at=NOW(),
            notes=CONCAT(COALESCE(notes,''), '\nMarked overdue on ', NOW())
        WHERE status IN ('pending','partial')
          AND due_date < CURDATE()
    ");
    // If query() returns PDOStatement-like, approximate row count
    $count = method_exists($affected,'rowCount') ? $affected->rowCount() : 0;
    echo "Marked overdue rows: {$count}\n";
} catch (Throwable $e) {
    error_log("update_overdue_payments error: ".$e->getMessage());
    echo "Error: ".$e->getMessage()."\n";
    exit(1);
}

echo "Done.\n";