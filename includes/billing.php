<?php
/**
 * includes/billing.php
 *
 * Monthly billing utilities for month-to-month leases:
 * - ensureMonthlyInvoices($db, ?int $vendorId = null)
 * - sendPaymentReminders($db, ?int $vendorId = null)
 * - autoTerminateLeasesPastGrace($db, ?int $vendorId = null)
 *
 * Business rules:
 * - Fixed Monthly Lease (default): month-to-month.
 * - Monthly Payment Cycle: invoice due on day INVOICE_DUE_DAY (default: 1).
 * - Grace Period: GRACE_DAYS (default: 5). No penalties. After grace, auto-terminate the lease.
 * - Auto-Reminder: in-app notifications by default; plug email/SMS in the hooks below if available.
 *
 * You can override defaults in config.php:
 *   define('INVOICE_DUE_DAY', 1);
 *   define('GRACE_DAYS', 5); // 3–5 recommended
 *   define('REMINDER_DAYS_BEFORE', [3, 1]); // optional
 *   define('REMINDER_GRACE_DAY_ZERO', true); // optional
 *   define('REMINDER_GRACE_LAST_DAY', true); // optional
 */

if (!function_exists('billing_invoice_due_day')) {
    function billing_invoice_due_day(): int {
        return defined('INVOICE_DUE_DAY') ? max(1, min(28, (int)INVOICE_DUE_DAY)) : 1;
    }
}
if (!function_exists('billing_grace_days')) {
    function billing_grace_days(): int {
        $d = defined('GRACE_DAYS') ? (int)GRACE_DAYS : 5;
        if ($d < 0) $d = 0;
        if ($d > 10) $d = 10;
        return $d;
    }
}
/**
 * If a lease starts after this month’s due day, first invoice shifts to next month’s due day to avoid instant “in grace”.
 */
if (!function_exists('billing_first_due_date_for_lease')) {
    function billing_first_due_date_for_lease(?string $leaseStartYmd): string {
        $dueDay = billing_invoice_due_day();
        $firstThisMonth = date('Y-m-' . str_pad((string)$dueDay, 2, '0', STR_PAD_LEFT));
        if ($leaseStartYmd && $leaseStartYmd !== '0000-00-00' && strtotime($leaseStartYmd) > strtotime($firstThisMonth)) {
            return date('Y-m-' . str_pad((string)$dueDay, 2, '0', STR_PAD_LEFT), strtotime('first day of next month'));
        }
        return $firstThisMonth;
    }
}

/**
 * Create a current-month invoice for each active lease if missing.
 * Active if status in ('active','ongoing','current') OR today's date is within [start,end] (open-ended permitted).
 * If vendorId provided, restrict scope.
 *
 * This version uses an atomic INSERT ... SELECT ... WHERE NOT EXISTS to avoid duplicates
 * when ensureMonthlyInvoices is called concurrently.
 */
if (!function_exists('ensureMonthlyInvoices')) {
    function ensureMonthlyInvoices($db, ?int $vendorId = null): void {
        $params = [];
        $sql = "
            SELECT l.lease_id, l.vendor_id, l.monthly_rent, l.lease_start_date, l.lease_end_date,
                   LOWER(TRIM(l.status)) AS lstatus
            FROM leases l
            WHERE 1=1
              AND (
                   LOWER(TRIM(l.status)) IN ('active','ongoing','current')
                   OR (
                       (l.lease_start_date IS NULL OR l.lease_start_date='0000-00-00' OR DATE(l.lease_start_date) <= CURDATE())
                       AND (l.lease_end_date IS NULL OR l.lease_end_date='0000-00-00' OR DATE(l.lease_end_date) >= CURDATE())
                   )
              )
        ";
        if ($vendorId) { $sql .= " AND l.vendor_id = ?"; $params[] = $vendorId; }

        try {
            $leases = $db->fetchAll($sql, $params) ?: [];
        } catch (Throwable $e) {
            error_log("billing: fetch active leases failed: " . $e->getMessage());
            return;
        }

        if (!$leases) return;

        // Detect if payments table has vendor_id column (once)
        $hasVendorIdCol = false;
        try {
            $hasVendorIdCol = (bool)$db->fetch("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'payments' AND column_name = 'vendor_id' LIMIT 1");
        } catch (Throwable $e) {}

        foreach ($leases as $l) {
            $leaseId = (int)($l['lease_id'] ?? 0);
            if ($leaseId <= 0) continue;

            $dueYmd = billing_first_due_date_for_lease($l['lease_start_date'] ?? null);
            $amount = (float)($l['monthly_rent'] ?? 0.0);
            if ($amount < 0) $amount = 0.0;

            try {
                // Atomic insert: only insert when no payment for this lease and year-month exists.
                if ($hasVendorIdCol) {
                    // Params: lease_id, vendor_id, amount, dueYmd, lease_id, dueYmd
                    $sqlIns = "
                        INSERT INTO payments (lease_id, vendor_id, amount, amount_paid, status, payment_type, currency, due_date, created_at)
                        SELECT ?, ?, ?, 0.0, 'pending', 'rent', 'PHP', ?, NOW()
                        FROM DUAL
                        WHERE NOT EXISTS (
                            SELECT 1 FROM payments p
                             WHERE p.lease_id = ?
                               AND DATE_FORMAT(p.due_date, '%Y-%m') = DATE_FORMAT(?, '%Y-%m')
                        )
                    ";
                    $paramsIns = [
                        $leaseId,
                        (int)$l['vendor_id'],
                        number_format($amount, 2, '.', ''),
                        $dueYmd,
                        $leaseId,
                        $dueYmd
                    ];
                } else {
                    // Params: lease_id, amount, dueYmd, lease_id, dueYmd
                    $sqlIns = "
                        INSERT INTO payments (lease_id, amount, amount_paid, status, payment_type, currency, due_date, created_at)
                        SELECT ?, ?, 0.0, 'pending', 'rent', 'PHP', ?, NOW()
                        FROM DUAL
                        WHERE NOT EXISTS (
                            SELECT 1 FROM payments p
                             WHERE p.lease_id = ?
                               AND DATE_FORMAT(p.due_date, '%Y-%m') = DATE_FORMAT(?, '%Y-%m')
                        )
                    ";
                    $paramsIns = [
                        $leaseId,
                        number_format($amount, 2, '.', ''),
                        $dueYmd,
                        $leaseId,
                        $dueYmd
                    ];
                }

                $db->query($sqlIns, $paramsIns);
            } catch (Throwable $e) {
                // Log and continue; do not abort whole loop on one failure
                error_log("billing: atomic insert failed for lease {$leaseId}: " . $e->getMessage());
                continue;
            }
        }
    }
}

/**
 * Send reminders before due date, on due date, and on last grace day (no penalties).
 * If vendorId provided, restrict scope.
 */
if (!function_exists('sendPaymentReminders')) {
    function sendPaymentReminders($db, ?int $vendorId = null): void {
        $daysBefore = defined('REMINDER_DAYS_BEFORE') && is_array(REMINDER_DAYS_BEFORE) ? REMINDER_DAYS_BEFORE : [3, 1];
        $onDue = defined('REMINDER_GRACE_DAY_ZERO') ? (bool)REMINDER_GRACE_DAY_ZERO : true;
        $onLastGrace = defined('REMINDER_GRACE_LAST_DAY') ? (bool)REMINDER_GRACE_LAST_DAY : true;
        $grace = billing_grace_days();

        $scopes = [];
        foreach ($daysBefore as $d) {
            $d = (int)$d;
            if ($d < 0 || $d > 31) continue;
            $scopes[] = ['label' => "due_minus_{$d}", 'dateExpr' => "DATE(p.due_date) = DATE_ADD(CURDATE(), INTERVAL {$d} DAY)"];
        }
        if ($onDue)       $scopes[] = ['label' => 'due_day', 'dateExpr' => "DATE(p.due_date) = CURDATE()"];
        if ($onLastGrace && $grace > 0) $scopes[] = ['label' => 'grace_last_day', 'dateExpr' => "DATE_ADD(DATE(p.due_date), INTERVAL {$grace} DAY) = CURDATE()"];

        foreach ($scopes as $scope) {
            $sql = "
                SELECT p.payment_id, p.due_date, p.amount, p.amount_paid, p.status,
                       l.vendor_id, l.business_name
                FROM payments p
                JOIN leases l ON l.lease_id = p.lease_id
                WHERE LOWER(TRIM(p.status)) IN ('pending','partial')
                  AND {$scope['dateExpr']}
            ";
            $params = [];
            if ($vendorId) { $sql .= " AND l.vendor_id = ?"; $params[] = $vendorId; }

            try {
                $rows = $db->fetchAll($sql, $params) ?: [];
            } catch (Throwable $e) {
                error_log("billing: fetch reminders ({$scope['label']}) failed: " . $e->getMessage());
                $rows = [];
            }
            if (!$rows) continue;

            foreach ($rows as $r) {
                $vid = (int)$r['vendor_id'];
                $paymentId = (int)$r['payment_id'];
                $due = date('M j, Y', strtotime($r['due_date']));
                $remain = max(0, (float)$r['amount'] - (float)$r['amount_paid']);
                $title = 'Lease Payment Reminder';
                $body = "Your invoice #{$paymentId} for {$r['business_name']} is due on {$due}. Amount due: ₱" . number_format($remain, 2) . ".";
                if (function_exists('createNotification')) {
                    try { createNotification($db, $vid, $title, $body, 'info', 'payment', $paymentId, 'payments'); }
                    catch (Throwable $e) { error_log("billing: notification failed for payment {$paymentId}: " . $e->getMessage()); }
                }
                // Optional hooks:
                // sendEmailToUser($vid, $title, $body);
                // sendSMSToUser($vid, $body);
            }
        }
    }
}

/**
 * Automatically terminate leases where any unpaid invoice (pending/partial) is past grace window.
 * - No penalties are applied.
 * - Lease set to 'terminated', stall set to 'available'.
 * - Vendor gets notification.
 * If vendorId provided, restrict scope.
 */
if (!function_exists('autoTerminateLeasesPastGrace')) {
    function autoTerminateLeasesPastGrace($db, ?int $vendorId = null): void {
        $grace = billing_grace_days();

        // Detect amount_paid column once for safer remaining-balance check
        $hasAmountPaid = false;
        try {
            $hasAmountPaid = (bool)$db->fetch("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'payments' AND column_name = 'amount_paid' LIMIT 1");
        } catch (Throwable $e) {
            $hasAmountPaid = false;
        }

        // Build remaining-balance predicate (schema-safe)
        $remainingPred = $hasAmountPaid
            ? "(COALESCE(p.amount,0) - COALESCE(p.amount_paid,0)) > 0.00001"
            : "LOWER(TRIM(p.status)) <> 'paid'";

        // Find active leases that have any UNPAID invoice past the grace window.
        // Include 'overdue' because older flows may have set that status already.
        $sql = "
            SELECT 
                l.lease_id, l.vendor_id, l.stall_id, l.business_name,
                MIN(p.due_date) AS first_due_past_grace
            FROM leases l
            JOIN payments p ON p.lease_id = l.lease_id
            WHERE LOWER(TRIM(l.status)) IN ('active','ongoing','current')
              AND LOWER(TRIM(p.status)) IN ('pending','partial','overdue')
              AND {$remainingPred}
              AND CURDATE() > DATE_ADD(DATE(p.due_date), INTERVAL ? DAY)
        ";
        $params = [$grace];
        if ($vendorId) { $sql .= " AND l.vendor_id = ?"; $params[] = $vendorId; }
        $sql .= " GROUP BY l.lease_id, l.vendor_id, l.stall_id, l.business_name";

        try {
            $rows = $db->fetchAll($sql, $params) ?: [];
        } catch (Throwable $e) {
            error_log("billing: fetch leases to terminate failed: " . $e->getMessage());
            return;
        }
        if (!$rows) return;

        foreach ($rows as $r) {
            $leaseId = (int)$r['lease_id'];
            $stallId = (int)$r['stall_id'];
            $vid     = (int)$r['vendor_id'];
            $biz     = (string)($r['business_name'] ?? '');
            $firstPastGrace = $r['first_due_past_grace'] ?? null;

            try {
                $db->beginTransaction();

                // Double-check remaining balance at the time of termination to avoid race conditions
                $stillDue = $db->fetch("
                    SELECT 1
                    FROM payments p
                    WHERE p.lease_id = ?
                      AND LOWER(TRIM(p.status)) IN ('pending','partial','overdue')
                      AND {$remainingPred}
                      AND CURDATE() > DATE_ADD(DATE(p.due_date), INTERVAL ? DAY)
                    LIMIT 1
                ", [$leaseId, $grace]);

                if (!$stillDue) {
                    $db->rollBack();
                    continue;
                }

                // Terminate lease and free stall
                $db->query("UPDATE leases SET status='terminated', updated_at=NOW() WHERE lease_id=? LIMIT 1", [$leaseId]);
                if ($stallId > 0) {
                    $db->query("UPDATE stalls SET status='available' WHERE stall_id=? LIMIT 1", [$stallId]);
                }

                // Annotate
                try {
                    $note = "\n[Auto-terminated for non-payment after grace on " . date('Y-m-d') . "]";
                    $db->query("UPDATE leases SET admin_notes = CONCAT(COALESCE(admin_notes,''), ?) WHERE lease_id=?", [$note, $leaseId]);
                } catch (Throwable $e2) {}

                $db->commit();

                // Notify vendor
                if (function_exists('createNotification')) {
                    $when = $firstPastGrace ? date('M j, Y', strtotime($firstPastGrace)) : 'the grace period';
                    $msg = "Your lease (ID: {$leaseId}) for '{$biz}' was terminated for non-payment after the grace period (invoice due: {$when}).";
                    try { createNotification($db, $vid, 'Lease Terminated for Non-payment', $msg, 'warning', 'lease', $leaseId, 'leases'); }
                    catch (Throwable $e3) { error_log("billing: termination notify failed lease {$leaseId}: " . $e3->getMessage()); }
                }

                if (function_exists('logAudit')) {
                    try { logAudit($db, $vid, 'Lease Auto-Terminated (Non-payment)', 'leases', $leaseId, null, "past grace"); } catch (Throwable $e4) {}
                }
            } catch (Throwable $e) {
                $db->rollBack();
                error_log("billing: terminate lease {$leaseId} failed: " . $e->getMessage());
            }
        }
    }
}