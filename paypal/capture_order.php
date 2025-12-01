<?php
// paypal/capture_order.php
// Two-step flow:
// - GET  (from PayPal approve): show a confirmation page; DO NOT CAPTURE YET.
// - POST (Confirm button): perform capture, update DB, redirect to receipt.php.
//
// We still buffer errors to avoid breaking redirects, but in GET we render HTML.

ob_start();
error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_WARNING);
ini_set('display_errors', '0');

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../includes/auth_roles.php';
require_once __DIR__ . '/../includes/audit.php';
require_once __DIR__ . '/../includes/billing.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/csrf.php';

// pending_payments helper (idempotency + audit)
require_once __DIR__ . '/pending_payment.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

// Robust base URL when APP_URL is not defined
function base_app_url(): string {
    if (defined('APP_URL') && APP_URL) return rtrim(APP_URL, '/');
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $basePath = rtrim(dirname(dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/\\'); // parent of /paypal
    return $scheme . '://' . $host . ($basePath ? $basePath : '');
}

$base = base_app_url();

if (!isLoggedIn()) {
    if (ob_get_length()) ob_clean();
    header('Location: ' . $base . '/login.php');
    exit;
}
$vendor_id = (int)$_SESSION['user_id'];

// Composer / PayPal SDK
$composer = __DIR__ . '/../vendor/autoload.php';
if (!file_exists($composer)) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (ob_get_length()) ob_clean();
        header('Location: ' . $base . '/submit_payment.php?error=server_misconfig');
        exit;
    } else {
        // Render a small error page
        if (ob_get_length()) ob_clean();
        http_response_code(500);
        echo "Server misconfiguration (PayPal SDK missing).";
        exit;
    }
}
require_once $composer;
require_once __DIR__ . '/paypal_client.php';

$graceDays = billing_grace_days();

// Helper to fetch the payment row for this order (with extra context for display)
function fetchPaymentForOrder($db, string $orderId) {
    return $db->fetch("
        SELECT 
            p.payment_id, p.vendor_id AS p_vendor_id, p.lease_id, p.amount, p.amount_paid, p.status, 
            p.paypal_capture_id, p.paypal_order_id, p.receipt_number, p.payment_date, p.payment_method, p.due_date,
            l.vendor_id AS l_vendor_id, l.status AS lease_status, l.business_name,
            s.stall_number,
            m.market_name
        FROM payments p
        JOIN leases  l ON l.lease_id = p.lease_id
        JOIN stalls  s ON l.stall_id = s.stall_id
        JOIN markets m ON s.market_id = m.market_id
        WHERE p.paypal_order_id = ?
        LIMIT 1
    ", [$orderId]);
}

// Resolve order id (PayPal returns token or orderID)
$orderId = $_GET['token'] ?? $_GET['orderID'] ?? $_POST['order_id'] ?? null;
if (!$orderId) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (ob_get_length()) ob_clean();
        header('Location: ' . $base . '/submit_payment.php?error=missing_order');
        exit;
    } else {
        if (ob_get_length()) ob_clean();
        header('Location: ' . $base . '/submit_payment.php?error=missing_order');
        exit;
    }
}

// Load payment for this order
$payment = fetchPaymentForOrder($db, $orderId);
if (!$payment) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (ob_get_length()) ob_clean();
        header('Location: ' . $base . '/submit_payment.php?error=payment_not_found');
        exit;
    } else {
        if (ob_get_length()) ob_clean();
        http_response_code(404);
        echo "Payment not found.";
        exit;
    }
}

// Vendor scope check
$pVendor = (int)($payment['p_vendor_id'] ?? 0);
$lVendor = (int)($payment['l_vendor_id'] ?? 0);
if ($vendor_id !== $pVendor && $vendor_id !== $lVendor) {
    if (ob_get_length()) ob_clean();
    http_response_code(403);
    echo "Forbidden";
    exit;
}

// Active lease and grace window checks
$leaseStatus = strtolower(trim((string)$payment['lease_status']));
if (!in_array($leaseStatus, ['active','ongoing','current'], true)) {
    if (ob_get_length()) ob_clean();
    header('Location: ' . $base . '/submit_payment.php?error=lease_inactive');
    exit;
}
$dueDate = $payment['due_date'] ? date('Y-m-d', strtotime($payment['due_date'])) : null;
if ($dueDate) {
    $graceEnd = date('Y-m-d', strtotime("+{$graceDays} days", strtotime($dueDate)));
    if (date('Y-m-d') > $graceEnd) {
        if (ob_get_length()) ob_clean();
        header('Location: ' . $base . '/submit_payment.php?error=grace_expired');
        exit;
    }
}

// Compute expected amount (prefer session context)
$ctx = $_SESSION['paypal_payment_context'] ?? null;
if ($ctx && ($ctx['order_id'] ?? '') === $orderId && (int)($ctx['payment_id'] ?? 0) === (int)$payment['payment_id']) {
    $expected = $ctx['expected_amount'];
} else {
    $expected = number_format(max(0, (float)$payment['amount'] - (float)$payment['amount_paid']), 2, '.', '');
}

// If already captured/paid, redirect to receipt immediately
if (!empty($payment['paypal_capture_id']) || strtolower(trim((string)$payment['status'])) === 'paid') {
    $_SESSION['receipt_flash'] = [
        'payment_id'    => (int)$payment['payment_id'],
        'capture_id'    => $payment['paypal_capture_id'] ?? null,
        'order_id'      => $payment['paypal_order_id'] ?? $orderId,
        'capture_amount'=> null,
        'currency'      => 'PHP'
    ];
    if (ob_get_length()) ob_clean();
    header('Location: ' . $base . '/receipt.php?pid=' . (int)$payment['payment_id']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Show review/confirmation page (no capture yet)
    $page_title = 'Confirm Payment';
    require_once __DIR__ . '/../includes/header.php';
    require_once __DIR__ . '/../includes/vendor_sidebar.php';

    $amountDue   = (float)$payment['amount'];
    $amountPaid  = (float)$payment['amount_paid'];
    $remaining   = max(0, round($amountDue - $amountPaid, 2));
    ?>
    <section class="max-w-3xl mx-auto p-6">
      <div class="bg-white rounded-lg shadow p-6">
        <h1 class="text-xl font-semibold text-gray-900 mb-2">Confirm Payment</h1>
        <p class="text-sm text-gray-600 mb-4">You’ve authorized this payment in PayPal. Review the details below and click “Confirm & Process” to finalize it. No money has been captured yet.</p>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <div>
            <p class="text-xs text-gray-500">Business</p>
            <p class="font-semibold text-gray-800"><?php echo htmlspecialchars($payment['business_name'] ?? ''); ?></p>
          </div>
          <div>
            <p class="text-xs text-gray-500">Market / Stall</p>
            <p class="font-semibold text-gray-800"><?php echo htmlspecialchars(($payment['market_name'] ?? '').' • Stall '.($payment['stall_number'] ?? '')); ?></p>
          </div>
          <div>
            <p class="text-xs text-gray-500">Invoice Total</p>
            <p class="font-semibold text-gray-800"><?php echo formatCurrency($amountDue); ?></p>
          </div>
          <div>
            <p class="text-xs text-gray-500">Paid to Date</p>
            <p class="font-semibold text-gray-800"><?php echo formatCurrency($amountPaid); ?></p>
          </div>
          <div>
            <p class="text-xs text-gray-500">This Payment</p>
            <p class="font-semibold text-gray-800"><?php echo formatCurrency((float)$expected); ?></p>
          </div>
          <div>
            <p class="text-xs text-gray-500">Remaining After</p>
            <p class="font-semibold text-gray-800">
              <?php echo formatCurrency(max(0, $remaining - (float)$expected)); ?>
            </p>
          </div>
        </div>

        <form method="POST" class="mt-4 flex items-center gap-3">
          <?php echo csrf_field(); ?>
          <input type="hidden" name="order_id" value="<?php echo htmlspecialchars($orderId); ?>">
          <input type="hidden" name="payment_id" value="<?php echo (int)$payment['payment_id']; ?>">
          <button type="submit" name="confirm_capture" value="1" class="px-4 py-2 bg-blue-600 text-white rounded">Confirm & Process</button>
          <a href="<?php echo $base; ?>/submit_payment.php?cancel=1" class="px-4 py-2 bg-gray-200 rounded text-gray-800">Cancel</a>
        </form>

        <p class="text-xs text-gray-500 mt-4">If you cancel here, your PayPal order remains authorized but uncaptured and will not be charged by this system.</p>
      </div>
    </section>
    <?php
    if (ob_get_length()) ob_end_flush();
    exit;
}

// POST: Perform capture after explicit confirmation
if (!csrf_validate_request()) {
    if (ob_get_length()) ob_clean();
    header('Location: ' . $base . '/submit_payment.php?error=csrf');
    exit;
}

// Validate POST input integrity
$postPaymentId = (int)($_POST['payment_id'] ?? 0);
if ($postPaymentId !== (int)$payment['payment_id']) {
    if (ob_get_length()) ob_clean();
    header('Location: ' . $base . '/submit_payment.php?error=payment_mismatch');
    exit;
}

try {
    $client = getPayPalClient();
    $capReq = new \PayPalCheckoutSdk\Orders\OrdersCaptureRequest($orderId);
    $capReq->prefer('return=representation');
    $resp = $client->execute($capReq);

    // Extract capture
    $captures = [];
    if (!empty($resp->result->purchase_units)) {
        foreach ($resp->result->purchase_units as $pu) {
            if (!empty($pu->payments->captures)) {
                foreach ($pu->payments->captures as $c) $captures[] = $c;
            }
        }
    }
    $capture = $captures[0] ?? null;
    if (!$capture) {
        if (ob_get_length()) ob_clean();
        header('Location: ' . $base . '/submit_payment.php?error=no_capture');
        exit;
    }

    $captureAmount = number_format((float)($capture->amount->value ?? 0), 2, '.', '');
    $captureId     = $capture->id ?? '';
    $currency      = strtoupper($capture->amount->currency_code ?? 'PHP');

    // Validate expected amount
    $expected = $_SESSION['paypal_payment_context']['expected_amount'] ?? number_format(max(0, (float)$payment['amount'] - (float)$payment['amount_paid']), 2, '.', '');
    if ($expected !== $captureAmount) {
        if (ob_get_length()) ob_clean();
        header('Location: ' . $base . '/submit_payment.php?error=amount_mismatch');
        exit;
    }

    // Idempotency: if already captured/paid, go to receipt
    if (!empty($payment['paypal_capture_id']) || strtolower(trim((string)$payment['status'])) === 'paid') {
        $_SESSION['receipt_flash'] = [
            'payment_id'    => (int)$payment['payment_id'],
            'capture_id'    => $payment['paypal_capture_id'] ?? $captureId,
            'order_id'      => $orderId,
            'capture_amount'=> $captureAmount,
            'currency'      => $currency
        ];
        if (ob_get_length()) ob_clean();
        header('Location: ' . $base . '/receipt.php?pid=' . (int)$payment['payment_id']);
        exit;
    }

    // Finalize DB update
    $newPaid = round(((float)$payment['amount_paid']) + (float)$captureAmount, 2);
    $total   = (float)$payment['amount'];
    $finalStatus = ($newPaid + 0.00001 >= $total) ? 'paid' : 'partial';
    $receipt_number = ($finalStatus === 'paid')
        ? ('RCT-' . date('Ymd') . '-' . str_pad((string)mt_rand(0, 999999), 6, '0', STR_PAD_LEFT))
        : ($payment['receipt_number'] ?? null);

    $db->query("
        UPDATE payments
        SET amount_paid=?,
            status=?,
            payment_date=NOW(),
            paypal_capture_id=?,
            receipt_number=IF(? IS NOT NULL, ?, receipt_number),
            payment_method='paypal',
            notes=CONCAT(COALESCE(notes,''), '\nCapture ', ?, ' amount ₱', ?, ' order ', ?),
            updated_at=NOW()
        WHERE payment_id=? LIMIT 1
    ", [
        number_format($newPaid, 2, '.', ''),
        $finalStatus,
        $captureId,
        $receipt_number, $receipt_number,
        $captureId, $captureAmount, $orderId,
        $payment['payment_id']
    ]);

    // Mark pending payments row processed (best effort)
    try {
        $pending = getPendingByOrderId($orderId, $db);
        if ($pending && !empty($pending['pending_id'])) {
            markPendingProcessed((int)$pending['pending_id'], (int)$payment['payment_id'], $captureId, $db);
        }
    } catch (Throwable $e) {
        error_log("capture_order: markPendingProcessed failed: " . $e->getMessage());
    }

    // Optional audit table
    try {
        $notesJson = json_encode([
            'order_id' => $orderId,
            'capture_id' => $captureId,
            'expected' => $expected
        ]);
        $db->query("INSERT INTO payment_captures (payment_id, paypal_capture_id, capture_amount, currency, captured_at, notes, created_at)
                    VALUES (?,?,?,?, NOW(),?, NOW())",
                   [(int)$payment['payment_id'], $captureId, $captureAmount, $currency, $notesJson]);
    } catch (Throwable $e) {
        error_log("capture_order: payment_captures insert failed: " . $e->getMessage());
    }

    // Notify and audit
    if (function_exists('logAudit')) {
        logAudit($db, $vendor_id, 'Payment Captured', 'payments', $payment['payment_id'], null, "capture_id={$captureId}");
    }

    // Flash for receipt
    $_SESSION['receipt_flash'] = [
        'payment_id'    => (int)$payment['payment_id'],
        'capture_id'    => $captureId,
        'order_id'      => $orderId,
        'capture_amount'=> $captureAmount,
        'currency'      => $currency
    ];

    unset($_SESSION['paypal_payment_context']);

    if (ob_get_length()) ob_clean();
    header('Location: ' . $base . '/receipt.php?pid=' . (int)$payment['payment_id']);
    exit;

} catch (\PayPalHttp\HttpException $e) {
    if (ob_get_length()) ob_clean();
    header('Location: ' . $base . '/submit_payment.php?error=capture_failed');
    error_log('capture_order PayPalHttpException: ' . $e->getMessage());
    exit;
} catch (Throwable $e) {
    if (ob_get_length()) ob_clean();
    error_log('capture error: ' . $e->getMessage());
    header('Location: ' . $base . '/submit_payment.php?error=capture_failed');
    exit;
}