<?php
// get_application_details.php
// Returns an HTML fragment with application details. Allows:
// - the applicant (vendor) who submitted the application
// - admins (isAdmin())
// - market_manager users who manage the market that the stall belongs to
//
// Returns 4xx/5xx status codes on error but always emits a small HTML fragment so AJAX callers
// can show a friendly message.

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/helpers.php';
require_once 'includes/csrf.php'; // included for consistency (no POST here)

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

// Helper: return HTML error fragment and an HTTP status code
function respond_error_html($message, $code = 400) {
    http_response_code($code);
    header('Content-Type: text/html; charset=utf-8');
    echo '<div class="p-4 bg-red-50 text-red-700 rounded">' . htmlspecialchars($message) . '</div>';
    exit;
}

// Ensure user is logged in
if (!function_exists('isLoggedIn') || !isLoggedIn()) {
    respond_error_html('Forbidden', 403);
}

// Validate input
$application_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
if ($application_id <= 0) {
    respond_error_html('Invalid application id.', 400);
}

// Utility: get managed market ids for a user (same logic as manage_applications)
function getManagedMarketIdsForUser($db, int $userId): array {
    $ids = [];
    try {
        $rows = $db->fetchAll("SELECT market_id FROM market_managers WHERE user_id = ?", [$userId]) ?: [];
        foreach ($rows as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id'];
    } catch (Throwable $e) {
        error_log("getManagedMarketIdsForUser: market_managers query failed: " . $e->getMessage());
    }

    if (empty($ids)) {
        try {
            $rows = $db->fetchAll("SELECT market_id FROM markets WHERE created_by = ?", [$userId]) ?: [];
            foreach ($rows as $r) if (!empty($r['market_id'])) $ids[] = (int)$r['market_id'];
        } catch (Throwable $e) {
            error_log("getManagedMarketIdsForUser: fallback markets.created_by query failed: " . $e->getMessage());
        }
    }

    return array_values(array_unique($ids));
}

// Fetch application with stall/market id (defensive)
try {
    $app = $db->fetch(
        "SELECT a.*, s.stall_id, s.stall_number, s.monthly_rent, s.floor_number, s.stall_size, s.market_id,
                m.market_name, m.location,
                u.full_name AS vendor_name, u.email, u.contact_number
         FROM applications a
         JOIN stalls s ON a.stall_id = s.stall_id
         JOIN markets m ON s.market_id = m.market_id
         JOIN users u ON a.vendor_id = u.user_id
         WHERE a.application_id = ? LIMIT 1",
        [$application_id]
    );
} catch (Throwable $e) {
    error_log("get_application_details: fetch application failed: " . $e->getMessage());
    respond_error_html('Server error while fetching application details.', 500);
}

if (!$app) {
    respond_error_html('Application not found.', 404);
}

// Authorization: vendor owner, admin, or market_manager for that market
$user_id = $_SESSION['user_id'] ?? null;
$allowed = false;

// vendor owner
if ($user_id && $user_id == ($app['vendor_id'] ?? 0)) {
    $allowed = true;
}

// admin role check
if (!$allowed && function_exists('isAdmin') && isAdmin()) {
    $allowed = true;
}

// userIsInRole('market_manager') check: allow if user manages this market
if (!$allowed && function_exists('userIsInRole') && userIsInRole($db, $user_id, 'market_manager')) {
    $marketId = isset($app['market_id']) ? (int)$app['market_id'] : null;
    if ($marketId !== null) {
        try {
            $managed = getManagedMarketIdsForUser($db, $user_id);
            if (in_array($marketId, $managed, true)) {
                $allowed = true;
            } else {
                error_log("AUTH DENY: market_manager {$user_id} tried access application {$application_id} for market {$marketId} not managed: " . json_encode($managed));
            }
        } catch (Throwable $e) {
            error_log("get_application_details: managed markets check failed for user {$user_id}: " . $e->getMessage());
        }
    }
}

if (!$allowed) {
    respond_error_html('Forbidden: you do not have permission to view this application.', 403);
}

// Fetch documents safely — wrap and handle missing table gracefully
$docs = [];
try {
    $tableExists = false;
    try {
        $row = $db->fetch("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'application_documents' LIMIT 1");
        $tableExists = (bool)$row;
    } catch (Throwable $e) {
        // information_schema check failed — assume table might be missing
        $tableExists = false;
    }

    if ($tableExists) {
        $docs = $db->fetchAll("SELECT document_id, document_name, document_type, uploaded_at FROM application_documents WHERE application_id = ? ORDER BY uploaded_at ASC", [$application_id]) ?: [];
    } else {
        $docs = [];
    }
} catch (Throwable $e) {
    error_log("get_application_details: fetch docs failed: " . $e->getMessage());
    $docs = [];
}

// Render HTML fragment
header('Content-Type: text/html; charset=utf-8');
?>
<div class="space-y-4">
  <div class="bg-gray-50 p-4 rounded">
    <h4 class="font-semibold">Applicant</h4>
    <p><?php echo htmlspecialchars($app['vendor_name'] ?? ''); ?> — <?php echo htmlspecialchars($app['email'] ?? ''); ?></p>
    <p class="text-sm text-gray-600">Contact: <?php echo htmlspecialchars($app['contact_number'] ?? ''); ?></p>
  </div>

  <div class="bg-white p-4 rounded border">
    <h4 class="font-semibold">Business</h4>
    <p class="font-medium"><?php echo htmlspecialchars($app['business_name'] ?? ''); ?></p>
    <p class="text-sm text-gray-600"><?php echo htmlspecialchars($app['business_type'] ?? ''); ?></p>
    <p class="text-xs text-gray-500 mt-2">Applied: <?php
        echo !empty($app['application_date'])
            ? htmlspecialchars(date('M j, Y', strtotime($app['application_date'])))
            : '-';
    ?></p>
  </div>

  <div class="bg-white p-4 rounded border">
    <h4 class="font-semibold">Stall</h4>
    <p><?php echo htmlspecialchars($app['stall_number'] ?? ''); ?> — <?php echo htmlspecialchars($app['market_name'] ?? ''); ?></p>
    <p class="text-sm text-gray-600">Size: <?php echo htmlspecialchars($app['stall_size'] ?? ''); ?> • Floor <?php echo (int)($app['floor_number'] ?? 0); ?></p>
    <p class="text-sm font-semibold mt-2"><?php echo function_exists('formatCurrency') ? formatCurrency($app['monthly_rent'] ?? 0) : htmlspecialchars(number_format((float)($app['monthly_rent'] ?? 0),2)); ?> / month</p>
  </div>

  <div class="bg-white p-4 rounded border">
    <h4 class="font-semibold">Uploaded Documents</h4>
    <?php if (!empty($docs)): ?>
      <ul class="list-disc pl-5">
        <?php foreach ($docs as $d): ?>
          <li>
            <a class="text-blue-600 hover:underline" href="download_contract.php?type=application&doc_id=<?php echo (int)$d['document_id']; ?>" target="_blank" rel="noopener noreferrer">
              <?php echo htmlspecialchars($d['document_name'] ?: $d['document_type'] ?: 'Document'); ?>
            </a>
            <span class="text-xs text-gray-500"> — <?php echo htmlspecialchars($d['uploaded_at'] ?? ''); ?></span>
          </li>
        <?php endforeach; ?>
      </ul>
    <?php else: ?>
      <p class="text-sm text-gray-500">No documents uploaded.</p>
    <?php endif; ?>
  </div>

  <div class="bg-white p-4 rounded border">
    <h4 class="font-semibold">Admin Notes</h4>
    <pre class="text-sm text-gray-700"><?php echo htmlspecialchars($app['admin_notes'] ?? 'No notes'); ?></pre>
  </div>
</div>