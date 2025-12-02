<?php
// paypal/create_order.php (UPDATED TO ALLOW OVERDUE PAYMENTS WITHIN GRACE)

ob_start();
error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_WARNING);
ini_set('display_errors', '0');
header('Content-Type: application/json; charset=utf-8');

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../includes/auth_roles.php';
require_once __DIR__ . '/../includes/billing.php';
require_once __DIR__ . '/../includes/helpers.php';

// pending_payments helper (idempotency + audit)
require_once __DIR__ . '/pending_payment.php';

if (!isset($_SESSION['user_id'])) {
    if (ob_get_length()) ob_clean();
    http_response_code(401);
    echo json_encode(['error' => 'Not logged in']);
    if (ob_get_length()) ob_end_flush();
    exit;
}

$vendor_id = (int)$_SESSION['user_id'];
if (!function_exists('userIsInRole') || !userIsInRole($db, $vendor_id, 'vendor')) {
    if (ob_get_length()) ob_clean();
    http_response_code(403);
    echo json_encode(['error' => 'Only vendors can pay']);
    if (ob_get_length()) ob_end_flush();
    exit;
}

$raw = file_get_contents('php://input');
$input = $raw ? json_decode($raw, true) : [];
if ($raw && $input === null) {
    if (ob_get_length()) ob_clean();
    http_response_code(400);
    echo json_encode(['error' => 'Bad JSON']);
    if (ob_get_length()) ob_end_flush();
    exit;
}

$payment_id     = isset($input['payment_id']) ? (int)$input['payment_id'] : 0;
$partial_amount = isset($input['partial_amount']) ? (float)$input['partial_amount'] : null;

if ($payment_id <= 0) {
    if (ob_get_length()) ob_clean();
    http_response_code(400);
    echo json_encode(['error' => 'Invalid payment_id']);
    if (ob_get_length()) ob_end_flush();
    exit;
}

$graceDays = billing_grace_days();

/* PayPal SDK presence */
$composer = __DIR__ . '/../vendor/autoload.php';
if (!file_exists($composer)) {
    if (ob_get_length()) ob_clean();
    http_response_code(500);
    echo json_encode(['error' => 'PayPal SDK missing']);
    if (ob_get_length()) ob_end_flush();
    exit;
}
require_once $composer;
require_once __DIR__ . '/paypal_client.php';

/* Robust base URL */
function base_app_url(): string {
    if (defined('APP_URL') && APP_URL) return rtrim(APP_URL, '/');
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host   = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $basePath = rtrim(dirname(dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/\\'); // parent of /paypal
    return $scheme . '://' . $host . ($basePath ? $basePath : '');
}

try {
    // Load payment + lease
    $payment = $db->fetch("
        SELECT p.payment_id, p.vendor_id AS p_vendor_id, p.lease_id, p.amount, p.amount_paid, p.status, 
               p.payment_type, p.currency, p.paypal_order_id, p.due_date,
               l.vendor_id AS l_vendor_id, l.status AS lease_status
        FROM payments p
        JOIN leases l ON l.lease_id = p.lease_id
        WHERE p.payment_id=? LIMIT 1
    ", [$payment_id]);

    if (!$payment) {
        if (ob_get_length()) ob_clean();
        http_response_code(404);
        echo json_encode(['error' => 'Payment not found']);
        if (ob_get_length()) ob_end_flush();
        exit;
    }

    // Ownership check
    $pVendor = (int)($payment['p_vendor_id'] ?? 0);
    $lVendor = (int)($payment['l_vendor_id'] ?? 0);
    if ($vendor_id !== $pVendor && $vendor_id !== $lVendor) {
        if (ob_get_length()) ob_clean();
        http_response_code(403);
        echo json_encode(['error' => 'Not your payment']);
        if (ob_get_length()) ob_end_flush();
        exit;
    }

    // Lease active check
    $leaseStatus = strtolower(trim((string)$payment['lease_status']));
    if (!in_array($leaseStatus, ['active','ongoing','current'], true)) {
        if (ob_get_length()) ob_clean();
        http_response_code(403);
        echo json_encode(['error' => 'Lease is not active']);
        if (ob_get_length()) ob_end_flush();
        exit;
    }

    // Status check — include overdue now
    $status = strtolower(trim((string)$payment['status']));
    $payableStatuses = ['pending','partial','overdue'];
    if (!in_array($status, $payableStatuses, true)) {
        if (ob_get_length()) ob_clean();
        http_response_code(403);
        echo json_encode(['error' => 'Payment not payable']);
        if (ob_get_length()) ob_end_flush();
        exit;
    }

    // Grace window check
    $dueDate = $payment['due_date'] ? date('Y-m-d', strtotime($payment['due_date'])) : null;
    if ($dueDate) {
        $graceEnd = date('Y-m-d', strtotime("+{$graceDays} days", strtotime($dueDate)));
        if (date('Y-m-d') > $graceEnd) {
            if (ob_get_length()) ob_clean();
            http_response_code(403);
            echo json_encode(['error' => 'Grace period ended']);
            if (ob_get_length()) ob_end_flush();
            exit;
        }
    }

    // Remaining balance (defensive if amount_paid column absent)
    $total = (float)$payment['amount'];
    $paidRaw = $payment['amount_paid'] ?? null;
    $paid = ($paidRaw !== null && $paidRaw !== '') ? (float)$paidRaw : (
        // If no amount_paid column or value, assume zero unless status already partial
        ($status === 'partial') ? ($total * 0.0) : 0.0
    );

    $remaining = max(0.0, round($total - $paid, 2));
    if ($remaining <= 0) {
        if (ob_get_length()) ob_clean();
        http_response_code(403);
        echo json_encode(['error' => 'No remaining balance']);
        if (ob_get_length()) ob_end_flush();
        exit;
    }

    // Validate partial amount
    $captureAmount = $partial_amount !== null ? round($partial_amount, 2) : $remaining;
    if ($captureAmount <= 0 || $captureAmount > $remaining) {
        if (ob_get_length()) ob_clean();
        http_response_code(400);
        echo json_encode(['error' => 'Invalid partial amount']);
        if (ob_get_length()) ob_end_flush();
        exit;
    }

    $currency = strtoupper($payment['currency'] ?? 'PHP');
    $payment_type = ucfirst($payment['payment_type'] ?? 'Rent');

    // OPTIONAL: If paying part of an overdue invoice, you might want to instantly set status to partial before capture.
    // Uncomment if desired:
    /*
    if ($status === 'overdue' && $captureAmount < $remaining) {
        $db->query("UPDATE payments SET status='partial', updated_at=NOW() WHERE payment_id=?", [$payment_id]);
        $status = 'partial';
    }
    */

    // Idempotent pending record
    $pending_id = null;
    try {
        $pendingData = [
            'vendor_id'   => $vendor_id,
            'lease_id'    => (int)$payment['lease_id'],
            'amount'      => $captureAmount,
            'currency'    => $currency,
            'payment_type'=> $payment['payment_type'] ?? 'rent',
            'months_count'=> 1,
            'metadata'    => ['payment_id' => (int)$payment_id]
        ];
        $pending_id = createPendingPayment($pendingData, $db);
    } catch (Throwable $e) {
        error_log("create_order: createPendingPayment failed: ".$e->getMessage());
    }

    $client = getPayPalClient();
    $req = new \PayPalCheckoutSdk\Orders\OrdersCreateRequest();
    $req->prefer('return=representation');
    $base = base_app_url();

    $req->body = [
        'intent' => 'CAPTURE',
        'purchase_units' => [[
            'amount' => [
                'currency_code' => $currency,
                'value' => number_format($captureAmount, 2, '.', '')
            ],
            'description' => "Payment #{$payment_id} (Lease {$payment['lease_id']}) - {$payment_type}"
        ]],
        'application_context' => [
            'return_url' => $base . '/paypal/capture_order.php',
            'cancel_url' => $base . '/submit_payment.php?cancel=1',
            'shipping_preference' => 'NO_SHIPPING',
            'user_action' => 'PAY_NOW'
        ]
    ];

    $resp = $client->execute($req);
    $approveUrl = null;
    if (!empty($resp->result->links)) {
        foreach ($resp->result->links as $l) {
            if (($l->rel ?? '') === 'approve') {
                $approveUrl = $l->href;
                break;
            }
        }
    }
    if (!$approveUrl) {
        if (ob_get_length()) ob_clean();
        http_response_code(502);
        echo json_encode(['error' => 'No approve URL']);
        if (ob_get_length()) ob_end_flush();
        exit;
    }

    // Persist PayPal order id
    $db->query("UPDATE payments SET paypal_order_id=?, payment_method='paypal', updated_at=NOW() WHERE payment_id=? LIMIT 1", [$resp->result->id, $payment_id]);

    // Link pending row
    if (!empty($pending_id)) {
        try { updatePendingWithOrderId($pending_id, $resp->result->id, $db); }
        catch (Throwable $e) { error_log("create_order: updatePendingWithOrderId failed: ".$e->getMessage()); }
    }

    // Context for capture validation
    $_SESSION['paypal_payment_context'] = [
        'payment_id'        => $payment_id,
        'order_id'          => $resp->result->id,
        'expected_amount'   => number_format($captureAmount, 2, '.', ''),
        'remaining_before'  => number_format($remaining, 2, '.', ''),
        'pending_id'        => $pending_id,
        'original_status'   => $status
    ];

    if (ob_get_length()) ob_clean();
    echo json_encode([
        'orderID'                 => $resp->result->id,
        'approveUrl'              => $approveUrl,
        'status'                  => $resp->result->status ?? 'CREATED',
        'payment_id'              => $payment_id,
        'capture_amount'          => number_format($captureAmount, 2, '.', ''),
        'remaining_after_estimate'=> number_format($remaining - $captureAmount, 2, '.', ''),
        'pending_id'              => $pending_id
    ]);
    if (ob_get_length()) ob_end_flush();
    exit;

} catch (\PayPalHttp\HttpException $e) {
    if (ob_get_length()) ob_clean();
    http_response_code(502);
    echo json_encode(['error' => 'PayPal API error']);
    error_log('create_order PayPalHttpException: '.$e->getMessage());
    if (ob_get_length()) ob_end_flush();
    exit;
} catch (Throwable $e) {
    if (ob_get_length()) ob_clean();
    error_log('create_order error: '.$e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Server error']);
    if (ob_get_length()) ob_end_flush();
    exit;
}