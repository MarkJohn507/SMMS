<?php
// paypal/pending_payment.php
// Helpers to create and manage idempotent pending payment rows.
// Requires your DB wrapper ($db) from config.php to be available.

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

/*
Recommended minimal table schema (if you don't already have one):
CREATE TABLE pending_payments (
  pending_id INT AUTO_INCREMENT PRIMARY KEY,
  vendor_id INT NOT NULL,
  lease_id INT NOT NULL,
  amount DECIMAL(12,2) NOT NULL,
  currency VARCHAR(10) NOT NULL,
  payment_type VARCHAR(50) DEFAULT 'rent',
  months_count INT DEFAULT 1,
  status VARCHAR(20) DEFAULT 'pending', -- pending, processed, cancelled
  order_id VARCHAR(128) DEFAULT NULL,   -- PayPal order id
  capture_id VARCHAR(128) DEFAULT NULL, -- PayPal capture id (after capture)
  metadata JSON DEFAULT NULL,
  payment_id INT DEFAULT NULL,          -- payments.payment_id when processed
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_order_id (order_id)
);
*/

/**
 * Create or return an existing pending payment (idempotent).
 *
 * @param array $data Required keys: vendor_id, lease_id, amount. Optional: currency, payment_type, months_count, metadata
 * @param mixed $db   Optional DB instance (if omitted, global $db is used)
 * @return int pending_id
 * @throws Throwable
 */
function createPendingPayment(array $data, $db = null)
{
    // Use provided $db or fallback to global $db
    if ($db === null) {
        if (!isset($GLOBALS['db'])) {
            throw new \RuntimeException('Database connection ($db) not available');
        }
        $db = $GLOBALS['db'];
    }

    $vendor_id = (int)($data['vendor_id'] ?? 0);
    $lease_id = (int)($data['lease_id'] ?? 0);
    $amount = number_format((float)($data['amount'] ?? 0), 2, '.', '');
    $currency = strtoupper($data['currency'] ?? 'PHP');
    $payment_type = $data['payment_type'] ?? 'rent';
    $months_count = (int)($data['months_count'] ?? 1);
    $metadata = isset($data['metadata']) ? json_encode($data['metadata']) : null;

    try {
        // Try to find an existing recent pending row matching key attributes to ensure idempotency
        $existing = $db->fetch(
            "SELECT * FROM pending_payments WHERE vendor_id = ? AND lease_id = ? AND amount = ? AND payment_type = ? AND status = 'pending' ORDER BY created_at DESC LIMIT 1",
            [$vendor_id, $lease_id, $amount, $payment_type]
        );
        if ($existing && !empty($existing['pending_id'])) {
            return (int)$existing['pending_id'];
        }

        // Insert new pending row
        $db->query(
            "INSERT INTO pending_payments (vendor_id, lease_id, amount, currency, payment_type, months_count, metadata, status, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', NOW(), NOW())",
            [$vendor_id, $lease_id, $amount, $currency, $payment_type, $months_count, $metadata]
        );
        return (int)$db->lastInsertId();
    } catch (\Throwable $e) {
        error_log('createPendingPayment failed: ' . $e->getMessage());
        throw $e;
    }
}

/**
 * Update pending row with PayPal order id (idempotent).
 *
 * @param int $pendingId
 * @param string $orderId
 * @param mixed $db Optional DB instance
 */
function updatePendingWithOrderId($pendingId, $orderId, $db = null)
{
    if ($db === null) {
        if (!isset($GLOBALS['db'])) {
            throw new \RuntimeException('Database connection ($db) not available');
        }
        $db = $GLOBALS['db'];
    }
    $db->query(
        "UPDATE pending_payments SET order_id = ?, updated_at = NOW() WHERE pending_id = ? AND (order_id IS NULL OR order_id = '')",
        [$orderId, $pendingId]
    );
}

/**
 * Find pending by order id
 *
 * @param string $orderId
 * @param mixed $db Optional DB instance
 * @return array|false
 */
function getPendingByOrderId($orderId, $db = null)
{
    if ($db === null) {
        if (!isset($GLOBALS['db'])) {
            throw new \RuntimeException('Database connection ($db) not available');
        }
        $db = $GLOBALS['db'];
    }
    return $db->fetch("SELECT * FROM pending_payments WHERE order_id = ? LIMIT 1", [$orderId]);
}

/**
 * Mark pending as processed and save capture/payment references (idempotent)
 *
 * @param int $pendingId
 * @param int|null $payment_id
 * @param string|null $capture_id
 * @param mixed $db Optional DB instance
 */
function markPendingProcessed($pendingId, $payment_id = null, $capture_id = null, $db = null)
{
    if ($db === null) {
        if (!isset($GLOBALS['db'])) {
            throw new \RuntimeException('Database connection ($db) not available');
        }
        $db = $GLOBALS['db'];
    }
    $db->query(
        "UPDATE pending_payments SET status = 'processed', payment_id = ?, capture_id = ?, updated_at = NOW() WHERE pending_id = ? AND status != 'processed'",
        [$payment_id, $capture_id, $pendingId]
    );
}