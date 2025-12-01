<?php
/**
 * vendor_dashboard.php (Enhanced + schema-safe + active-lease-only financials)
 *
 * Fixes:
 *  - Scope payments to ACTIVE leases only (exclude terminated/cancelled/completed).
 *  - If no active leases, zero-out Outstanding/Next Due cards and hide Pending Balance detail.
 *  - Do not select payments.description when the column doesn't exist (use a derived alias from payment_type).
 *  - Do not select notifications.status when the column doesn't exist (derive is_read if possible and render "New/Read").
 *  - Scope payments by leases.vendor_id (robust even if payments.vendor_id is NULL).
 *
 * Features:
 *  - Summary metric cards (Leases, Applications, Outstanding Balance, Overdue Payments).
 *  - Pending Balance card (total unpaid / partially paid + breakdown).
 *  - Document verification status (Permit / ID).
 *  - Next due payment card (shows days remaining or overdue) — for active leases only.
 *  - Recent applications & leases quick lists.
 *  - Payment health bar (paid vs unpaid ratio).
 *  - Notifications preview.
 */

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/helpers.php';
require_once 'includes/audit.php';
requireVendor();

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
$user_id   = (int)($_SESSION['user_id'] ?? 0);
$page_title = 'Vendor Dashboard';

function safeFormatCurrency($v) {
    if (!function_exists('formatCurrency')) {
        return '₱' . number_format((float)$v, 2);
    }
    return formatCurrency($v);
}
if (!function_exists('h')) {
    function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
}

$today = date('Y-m-d');
$nowTs = strtotime($today);

function db_col_exists($db, string $table, string $col): bool {
    try {
        return (bool)$db->fetch("SELECT 1 FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? AND column_name=? LIMIT 1", [$table, $col]);
    } catch (Throwable $e) { return false; }
}

/* -----------------------------
   Fetch Document Verification
------------------------------*/
$permit_status = 'missing';
$id_status     = 'missing';
try {
    $docRows = $db->fetchAll("
        SELECT d.doc_type, LOWER(d.status) AS status
        FROM user_role_documents d
        JOIN user_roles ur ON d.user_role_id = ur.user_role_id
        JOIN roles r ON ur.role_id = r.role_id
        WHERE ur.user_id = ? AND r.name='vendor'
    ", [$user_id]) ?: [];
    foreach ($docRows as $dr) {
        $t = strtolower($dr['doc_type'] ?? '');
        $s = strtolower($dr['status'] ?? '');
        if (in_array($t, ['permit','business_permit'], true)) {
            if ($s === 'approved') $permit_status = 'approved';
            elseif ($permit_status !== 'approved' && $s === 'pending') $permit_status = 'pending';
            elseif ($s === 'rejected') $permit_status = 'rejected';
        }
        if (in_array($t, ['id','government_id','gov_id'], true)) {
            if ($s === 'approved') $id_status = 'approved';
            elseif ($id_status !== 'approved' && $s === 'pending') $id_status = 'pending';
            elseif ($s === 'rejected') $id_status = 'rejected';
        }
    }
} catch (Throwable $e) {
    error_log("vendor_dashboard docs fetch error: ".$e->getMessage());
}

/* Helper to badge classes */
function docBadgeClass($state){
    return match($state){
        'approved' => 'bg-green-100 text-green-700',
        'pending'  => 'bg-amber-100 text-amber-700',
        'rejected' => 'bg-red-100 text-red-700',
        'missing'  => 'bg-gray-100 text-gray-600',
        default    => 'bg-gray-100 text-gray-600'
    };
}

/* -----------------------------
   Leases
------------------------------*/
$leases = [];
$total_active_leases = 0;
try {
    $leases = $db->fetchAll("
        SELECT l.*, s.stall_number, m.market_name
        FROM leases l
        JOIN stalls s ON l.stall_id = s.stall_id
        JOIN markets m ON s.market_id = m.market_id
        WHERE l.vendor_id = ?
        ORDER BY l.lease_start_date DESC
        LIMIT 8
    ", [$user_id]) ?: [];
    foreach ($leases as $l) {
        if (isset($l['status']) && in_array(strtolower($l['status']), ['active','ongoing','current'], true)) $total_active_leases++;
    }
} catch (Throwable $e) {
    error_log("vendor_dashboard leases error: ".$e->getMessage());
}

/* -----------------------------
   Applications
------------------------------*/
$applications = [];
$app_status_counts = [
    'pending'   => 0,
    'approved'  => 0,
    'rejected'  => 0,
    'withdrawn' => 0,
    'other'     => 0
];
try {
    $applications = $db->fetchAll("
        SELECT application_id, stall_id, business_name, business_type, status, application_date
        FROM applications
        WHERE vendor_id = ?
        ORDER BY application_date DESC
        LIMIT 8
    ", [$user_id]) ?: [];
    foreach ($applications as $a) {
        $s = strtolower($a['status'] ?? '');
        if (isset($app_status_counts[$s])) $app_status_counts[$s]++; else $app_status_counts['other']++;
    }
} catch (Throwable $e) {
    error_log("vendor_dashboard applications error: ".$e->getMessage());
}

/* -----------------------------
   Payments & Outstanding (ACTIVE LEASES ONLY)
------------------------------*/
$payment_rows = [];
$outstanding_total = 0.0;
$overdue_total     = 0.0;
$overdue_count     = 0;
$unpaid_count      = 0;
$next_due          = null; // row
$paid_total        = 0.0;
$gross_total       = 0.0;

$has_amount_paid_col = db_col_exists($db, 'payments', 'amount_paid');
$has_currency_col    = db_col_exists($db, 'payments', 'currency');
$has_created_col     = db_col_exists($db, 'payments', 'created_at');
$has_description_col = db_col_exists($db, 'payments', 'description');

try {
    // Build schema-safe select with description alias fallback
    $fields = [
        'p.payment_id',
        'p.amount',
        $has_amount_paid_col ? 'p.amount_paid' : '0 AS amount_paid',
        'p.status',
        'p.due_date'
    ];
    if ($has_currency_col) $fields[] = 'p.currency';
    if ($has_description_col) {
        $fields[] = 'p.description';
    } else {
        $fields[] = "CONCAT(UCASE(LEFT(COALESCE(p.payment_type,''),1)), LOWER(SUBSTRING(COALESCE(p.payment_type,''),2))) AS description";
    }

    // Scope by lease ownership AND only active/ongoing/current leases
    $sql = "
        SELECT " . implode(', ', $fields) . "
        FROM payments p
        JOIN leases l ON l.lease_id = p.lease_id
        WHERE l.vendor_id = ?
          AND LOWER(TRIM(l.status)) IN ('active','ongoing','current')
        ORDER BY COALESCE(p.due_date, ".($has_created_col ? 'p.created_at' : 'p.payment_id').") ASC
        LIMIT 50
    ";

    $payment_rows = $db->fetchAll($sql, [$user_id]) ?: [];

    foreach ($payment_rows as $p) {
        $amt = (float)($p['amount'] ?? 0);
        $paid = $has_amount_paid_col ? (float)($p['amount_paid'] ?? 0) : (strtolower($p['status'] ?? '') === 'paid' ? $amt : 0);
        $remaining = max($amt - $paid, 0);
        $gross_total += $amt;
        $paid_total  += ($amt - $remaining);

        $due       = $p['due_date'] ?? null;
        $dueTs     = $due ? strtotime($due) : null;
        $isPaid    = ($remaining <= 0.00001);

        if (!$isPaid) {
            $unpaid_count++;
            $outstanding_total += $remaining;

            if ($due && $dueTs && $dueTs < $nowTs) { // overdue by date (UI purpose)
                $overdue_count++;
                $overdue_total += $remaining;
            }

            if ($due && $dueTs) {
                if (!$next_due) {
                    $next_due = $p;
                } else {
                    $currNextTs = strtotime($next_due['due_date']);
                    if ($dueTs < $currNextTs) $next_due = $p;
                }
            }
        }
    }
} catch (Throwable $e) {
    error_log("vendor_dashboard payments error: ".$e->getMessage());
}

/* If there are NO active leases, clear financial widgets */
$has_active_leases = ($total_active_leases > 0);
if (!$has_active_leases) {
    $outstanding_total = 0.0;
    $overdue_total = 0.0;
    $overdue_count = 0;
    $unpaid_count = 0;
    $next_due = null;
    $paid_total = 0.0;
    $gross_total = 0.0;
}

/* Payment health ratio */
$paid_ratio = $gross_total > 0 ? min(1, max(0, $paid_total / $gross_total)) : 0;

/* Next due descriptor (only meaningful when there are active leases) */
$next_due_label = '';
if ($has_active_leases && $next_due && !empty($next_due['due_date'])) {
    $dueTs = strtotime($next_due['due_date']);
    $diffDays = (int)floor(($dueTs - $nowTs)/86400);
    if ($diffDays < 0) {
        $next_due_label = 'Overdue by '.abs($diffDays).' day'.(abs($diffDays)==1?'':'s');
    } elseif ($diffDays === 0) {
        $next_due_label = 'Due today';
    } else {
        $next_due_label = 'Due in '.$diffDays.' day'.($diffDays==1?'':'s');
    }
}

/* -----------------------------
   Notifications Preview (schema-safe)
------------------------------*/
$notifications = [];
try {
    $has_is_read  = db_col_exists($db, 'notifications', 'is_read');
    $has_status   = db_col_exists($db, 'notifications', 'status');
    $has_created  = db_col_exists($db, 'notifications', 'created_at');

    $nFields = [
        'n.notification_id',
        'n.title'
    ];
    if ($has_created) $nFields[] = 'n.created_at';
    // Normalize to is_read
    if ($has_is_read) {
        $nFields[] = 'n.is_read';
    } elseif ($has_status) {
        $nFields[] = "CASE WHEN LOWER(TRIM(n.status)) IN ('read','seen') THEN 1 ELSE 0 END AS is_read";
    } else {
        $nFields[] = '0 AS is_read';
    }

    $sqlN = "
        SELECT " . implode(', ', $nFields) . "
        FROM notifications n
        WHERE n.user_id = ?
        ORDER BY " . ($has_created ? 'n.created_at' : 'n.notification_id') . " DESC
        LIMIT 6
    ";
    $notifications = $db->fetchAll($sqlN, [$user_id]) ?: [];
} catch (Throwable $e) {
    error_log("vendor_dashboard notifications error: ".$e->getMessage());
}

logAudit($db, $user_id, 'View Vendor Dashboard', 'dashboard', null, null, json_encode([
    'leases' => count($leases),
    'applications' => count($applications),
    'outstanding' => $outstanding_total,
    'overdue' => $overdue_total
]));

require_once 'includes/header.php';
require_once 'includes/vendor_sidebar.php';
?>
<section class="max-w-7xl mx-auto p-6">

  <!-- Top Metrics Grid -->
  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
    <!-- Active Leases -->
    <div class="bg-white rounded-xl shadow p-5 flex flex-col">
      <div class="flex items-center justify-between mb-2">
        <span class="text-sm font-semibold text-gray-600 flex items-center gap-1">
          <svg class="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
              d="M3 20h18M6 20V8a2 2 0 012-2h8a2 2 0 012 2v12M8 12h2m4 0h2M8 16h2m4 0h2"/>
          </svg>
          Active Leases
        </span>
      </div>
      <div class="text-3xl font-bold text-gray-800"><?php echo $total_active_leases; ?></div>
      <p class="mt-1 text-xs text-gray-500">Total leases: <?php echo count($leases); ?></p>
    </div>

    <!-- Applications -->
    <div class="bg-white rounded-xl shadow p-5 flex flex-col">
      <div class="flex items-center justify-between mb-2">
        <span class="text-sm font-semibold text-gray-600 flex items-center gap-1">
          <svg class="w-4 h-4 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
              d="M9 5h6a2 2 0 012 2v1H7V7a2 2 0 012-2zm-2 4h10v10a2 2 0 01-2 2H9a2 2 0 01-2-2V9zm3 6l2 2 4-4"/>
          </svg>
          Applications
        </span>
      </div>
      <div class="text-3xl font-bold text-gray-800"><?php echo array_sum($app_status_counts); ?></div>
      <div class="mt-2 grid grid-cols-2 gap-x-2 gap-y-1 text-xs text-gray-600">
        <div>Pending: <span class="font-semibold"><?php echo $app_status_counts['pending']; ?></span></div>
        <div>Approved: <span class="font-semibold text-green-600"><?php echo $app_status_counts['approved']; ?></span></div>
        <div>Rejected: <span class="font-semibold text-red-600"><?php echo $app_status_counts['rejected']; ?></span></div>
        <div>Other: <span class="font-semibold"><?php echo $app_status_counts['other'] + $app_status_counts['withdrawn']; ?></span></div>
      </div>
    </div>

    <!-- Outstanding Balance (hide when no active leases) -->
    <div class="bg-white rounded-xl shadow p-5 flex flex-col">
      <div class="flex items-center justify-between mb-2">
        <span class="text-sm font-semibold text-gray-600 flex items-center gap-1">
          <svg class="w-4 h-4 text-amber-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
              d="M12 8c-1.105 0-2 .672-2 1.5S10.895 11 12 11s2 .672 2 1.5S13.105 14 12 14m0 4h.01M12 3C7.589 3 4 6.589 4 11c0 4.411 3.589 8 8 8s8-3.589 8-8c0-4.411-3.589-8-8-8z"/>
          </svg>
          Outstanding
        </span>
      </div>
      <?php if ($has_active_leases): ?>
        <div class="text-3xl font-bold text-gray-800"><?php echo safeFormatCurrency($outstanding_total); ?></div>
        <p class="mt-1 text-xs text-gray-500">
          Overdue: <span class="font-semibold <?php echo $overdue_total>0?'text-red-600':''; ?>"><?php echo safeFormatCurrency($overdue_total); ?></span>
        </p>
      <?php else: ?>
        <div class="text-3xl font-bold text-gray-800"><?php echo safeFormatCurrency(0); ?></div>
        <p class="mt-1 text-xs text-gray-500">No active leases.</p>
      <?php endif; ?>
    </div>

    <!-- Next Due Payment (hide when no active leases) -->
    <div class="bg-white rounded-xl shadow p-5 flex flex-col">
      <div class="flex items-center justify-between mb-2">
        <span class="text-sm font-semibold text-gray-600 flex items-center gap-1">
          <svg class="w-4 h-4 text-teal-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
              d="M12 8v4l3 3M12 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10-4.477 10-10 10z"/>
          </svg>
          Next Due
        </span>
      </div>
      <?php if ($has_active_leases && $next_due): ?>
        <div class="text-lg font-semibold text-gray-800">
          <?php echo safeFormatCurrency($next_due['amount']); ?>
        </div>
        <p class="text-xs text-gray-500">
          Due: <?php echo htmlspecialchars($next_due['due_date']); ?> • <?php echo $next_due_label; ?>
        </p>
      <?php else: ?>
        <div class="text-lg font-semibold text-gray-800">None</div>
        <p class="text-xs text-gray-500"><?php echo $has_active_leases ? 'No upcoming unpaid items.' : 'No active leases.'; ?></p>
      <?php endif; ?>
    </div>
  </div>

  <!-- Payment Health & Verification -->
  <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-10">
    <!-- Payment Health -->
    <div class="bg-white rounded-xl shadow p-6">
      <h2 class="text-sm font-semibold text-gray-700 flex items-center gap-2 mb-3">
        <svg class="w-5 h-5 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M3 3v18h18M7 14l3-3 4 4 5-10"/>
        </svg>
        Payment Health
      </h2>
      <div class="h-3 w-full bg-gray-200 rounded-full overflow-hidden mb-2">
        <div class="h-full bg-green-500" style="width: <?php echo (int)round($paid_ratio*100); ?>%; transition:width .6s;"></div>
      </div>
      <p class="text-xs text-gray-600">
        Paid: <?php echo safeFormatCurrency($paid_total); ?> • Total: <?php echo safeFormatCurrency($gross_total); ?>
        (<?php echo (int)round($paid_ratio*100); ?>%)
      </p>
      <div class="mt-3 text-xs text-gray-500">
        Unpaid invoices: <span class="font-semibold"><?php echo $unpaid_count; ?></span>,
        Overdue: <span class="font-semibold <?php echo $overdue_count>0?'text-red-600':''; ?>"><?php echo $overdue_count; ?></span>
      </div>
    </div>

    <!-- Verification Status -->
    <div class="bg-white rounded-xl shadow p-6">
      <h2 class="text-sm font-semibold text-gray-700 flex items-center gap-2 mb-3">
        <svg class="w-5 h-5 text-emerald-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M12 6l7 4-7 4-7-4 7-4zm0 8l7 4-7 4-7-4 7-4z"/>
        </svg>
        Document Verification
      </h2>
      <div class="flex gap-2 flex-wrap text-xs">
        <span class="px-2 py-1 rounded font-medium <?php echo docBadgeClass($permit_status); ?>">
          Permit: <?php echo ucfirst($permit_status); ?>
        </span>
        <span class="px-2 py-1 rounded font-medium <?php echo docBadgeClass($id_status); ?>">
          ID: <?php echo ucfirst($id_status); ?>
        </span>
      </div>
      <?php if ($permit_status !== 'approved' || $id_status !== 'approved'): ?>
        <p class="mt-3 text-xs text-gray-600">Complete verification to unlock applications.</p>
        <a href="settings.php#documentsSection" class="mt-2 inline-block text-xs bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700">
          Upload / Review
        </a>
      <?php else: ?>
        <p class="mt-3 text-xs text-green-600 font-semibold">All documents approved. You can apply freely.</p>
      <?php endif; ?>
    </div>

    <!-- Quick Actions -->
    <div class="bg-white rounded-xl shadow p-6">
      <h2 class="text-sm font-semibold text-gray-700 flex items center gap-2 mb-3">
        <svg class="w-5 h-5 text-orange-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M12 6v6m0 6m0-6h6M6 12h6m6 0a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>
        Quick Actions
      </h2>
      <div class="flex flex-wrap gap-2 text-xs">
        <a href="browse_stalls.php" class="px-3 py-2 rounded bg-green-600 text-white hover:bg-green-700">Browse Stalls</a>
        <a href="my_applications.php" class="px-3 py-2 rounded bg-indigo-600 text-white hover:bg-indigo-700">Applications</a>
        <a href="my_leases.php" class="px-3 py-2 rounded bg-sky-600 text-white hover:bg-sky-700">Leases</a>
        <a href="submit_payment.php" class="px-3 py-2 rounded bg-amber-600 text-white hover:bg-amber-700">Make Payment</a>
        <a href="my_payments.php" class="px-3 py-2 rounded bg-fuchsia-600 text-white hover:bg-fuchsia-700">Payment History</a>
        <a href="settings.php" class="px-3 py-2 rounded bg-gray-700 text-white hover:bg-gray-800">Settings</a>
      </div>
    </div>
  </div>

  <!-- Lower Panels -->
  <div class="grid grid-cols-1 xl:grid-cols-3 gap-6">
    <!-- Recent Leases -->
    <div class="bg-white rounded-xl shadow p-5 xl:col-span-1">
      <h3 class="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
        <svg class="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M7 7h7l3 3v7a2 2 0 01-2 2H7a2 2 0 01-2-2V9a2 2 0 012-2z"/>
        </svg>
        Recent Leases
      </h3>
      <?php if ($leases): ?>
        <ul class="space-y-3 text-xs">
          <?php foreach ($leases as $l): ?>
            <li class="border rounded p-3 flex justify-between">
              <div>
                <p class="font-medium"><?php echo h($l['stall_number']); ?> <span class="text-gray-500">• <?php echo h($l['market_name']); ?></span></p>
                <p class="text-gray-500">
                  <?php echo !empty($l['lease_start_date']) ? h(date('M Y', strtotime($l['lease_start_date']))) : '-'; ?>
                  <?php if (!empty($l['lease_end_date'])): ?>
                    — <?php echo h(date('M Y', strtotime($l['lease_end_date']))); ?>
                  <?php endif; ?>
                </p>
              </div>
              <div class="text-right">
                <?php
                  $statusClass = match(strtolower($l['status'] ?? '')) {
                    'active','ongoing','current' => 'bg-green-100 text-green-700',
                    'completed' => 'bg-blue-100 text-blue-700',
                    'cancelled','terminated' => 'bg-red-100 text-red-700',
                    default => 'bg-gray-100 text-gray-600'
                  };
                ?>
                <span class="px-2 py-1 rounded <?php echo $statusClass; ?>"><?php echo h(ucfirst((string)$l['status'])); ?></span>
              </div>
            </li>
          <?php endforeach; ?>
        </ul>
      <?php else: ?>
        <p class="text-xs text-gray-600">No leases yet.</p>
      <?php endif; ?>
      <div class="mt-3 text-right">
        <a href="my_leases.php" class="text-xs text-blue-600 hover:underline">View all leases</a>
      </div>
    </div>

    <!-- Recent Applications -->
    <div class="bg-white rounded-xl shadow p-5 xl:col-span-1">
      <h3 class="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
        <svg class="w-5 h-5 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M9 5h6a2 2 0 012 2v1H7V7a2 2 0 012-2zm-2 4h10v10a2 2 0 01-2 2H9a2 2 0 01-2-2V9zm3 6l2 2 4-4"/>
        </svg>
        Recent Applications
      </h3>
      <?php if ($applications): ?>
        <ul class="space-y-3 text-xs">
          <?php foreach ($applications as $a): ?>
            <?php
              $appStatusClass = match(strtolower($a['status'] ?? '')) {
                'pending' => 'bg-amber-100 text-amber-700',
                'approved' => 'bg-green-100 text-green-700',
                'rejected' => 'bg-red-100 text-red-700',
                default => 'bg-gray-100 text-gray-600'
              };
            ?>
            <li class="border rounded p-3 flex justify-between">
              <div>
                <p class="font-medium"><?php echo h($a['business_name']); ?></p>
                <p class="text-gray-500">
                  <?php echo h($a['business_type']); ?> •
                  <?php echo !empty($a['application_date']) ? h(date('M j', strtotime($a['application_date']))) : '-'; ?>
                </p>
              </div>
              <div class="text-right">
                <span class="px-2 py-1 rounded <?php echo $appStatusClass; ?>">
                  <?php echo h(ucfirst((string)$a['status'])); ?>
                </span>
              </div>
            </li>
          <?php endforeach; ?>
        </ul>
      <?php else: ?>
        <p class="text-xs text-gray-600">No applications yet.</p>
      <?php endif; ?>
      <div class="mt-3 text-right">
        <a href="my_applications.php" class="text-xs text-blue-600 hover:underline">View all applications</a>
      </div>
    </div>

    <!-- Notifications -->
    <div class="bg-white rounded-xl shadow p-5 xl:col-span-1">
      <h3 class="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
        <svg class="w-5 h-5 text-pink-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M15 17h5l-1.405-1.405A2 2 0 0118 14.172V11a6 6 0 10-12 0v3.172a2 2 0 01-.595 1.423L4 17h5m6 0v1a3 3 0 11-6 0v-1"/>
        </svg>
        Notifications
      </h3>
      <?php if ($notifications): ?>
        <ul class="space-y-3 text-xs">
          <?php foreach ($notifications as $n): ?>
            <?php
              $isRead = !empty($n['is_read']);
              $nClass = $isRead ? 'bg-gray-100 text-gray-600' : 'bg-blue-100 text-blue-700';
            ?>
            <li class="border rounded p-3 flex justify-between">
              <div class="pr-2">
                <p class="font-medium truncate"><?php echo h($n['title'] ?? ''); ?></p>
                <p class="text-gray-500">
                  <?php echo isset($n['created_at']) && $n['created_at'] ? h(date('M j, H:i', strtotime($n['created_at']))) : ''; ?>
                </p>
              </div>
              <div class="text-right">
                <span class="px-2 py-1 rounded <?php echo $nClass; ?>">
                  <?php echo $isRead ? 'Read' : 'New'; ?>
                </span>
              </div>
            </li>
          <?php endforeach; ?>
        </ul>
      <?php else: ?>
        <p class="text-xs text-gray-600">No notifications.</p>
      <?php endif; ?>
      <div class="mt-3 text-right">
        <a href="notifications.php" class="text-xs text-blue-600 hover:underline">View all</a>
      </div>
    </div>
  </div>

  <!-- Raw Outstanding Detail (optional; hide when no active leases) -->
  <?php if ($has_active_leases && $outstanding_total > 0): ?>
    <div class="mt-10 bg-white rounded-xl shadow p-6">
      <h3 class="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
        <svg class="w-5 h-5 text-amber-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M12 8c-1.105 0-2 .672-2 1.5S10.895 11 12 11s2 .672 2 1.5S13.105 14 12 14m0 4h.01M12 3C7.589 3 4 6.589 4 11c0 4.411 3.589 8 8 8s8-3.589 8-8c0-4.411-3.589-8-8-8z"/>
        </svg>
        Pending Balance Detail
      </h3>
      <div class="overflow-x-auto">
        <table class="min-w-full text-xs">
          <thead>
            <tr class="bg-gray-50 text-gray-600">
              <th class="px-3 py-2 text-left font-medium">Due Date</th>
              <th class="px-3 py-2 text-left font-medium">Description</th>
              <th class="px-3 py-2 text-right font-medium">Amount</th>
              <th class="px-3 py-2 text-right font-medium">Remaining</th>
              <th class="px-3 py-2 text-right font-medium">Status</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100">
            <?php foreach ($payment_rows as $p): ?>
              <?php
                $amt = (float)($p['amount'] ?? 0);
                $paid = $has_amount_paid_col ? (float)($p['amount_paid'] ?? 0) : (strtolower($p['status'] ?? '') === 'paid' ? $amt : 0);
                $remaining = max($amt - $paid, 0);
                if ($remaining <= 0.00001) continue;
                $due   = $p['due_date'] ?? '';
                $dueTs = $due ? strtotime($due) : null;
                $isOverdue = $dueTs && $dueTs < $nowTs;
                $statusBadge = $isOverdue ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700';
              ?>
              <tr>
                <td class="px-3 py-2">
                  <?php echo htmlspecialchars($due ?: '-'); ?>
                  <?php if ($isOverdue): ?>
                    <span class="ml-1 text-[10px] text-red-600 font-medium">Overdue</span>
                  <?php endif; ?>
                </td>
                <td class="px-3 py-2 truncate max-w-[160px]"><?php echo htmlspecialchars($p['description'] ?? 'Payment'); ?></td>
                <td class="px-3 py-2 text-right"><?php echo safeFormatCurrency($amt); ?></td>
                <td class="px-3 py-2 text-right font-semibold"><?php echo safeFormatCurrency($remaining); ?></td>
                <td class="px-3 py-2 text-right">
                  <span class="px-2 py-1 rounded <?php echo $statusBadge; ?>">
                    <?php echo $isOverdue ? 'Overdue' : 'Pending'; ?>
                  </span>
                </td>
              </tr>
            <?php endforeach; ?>
            <?php if ($outstanding_total <= 0): ?>
              <tr>
                <td colspan="5" class="px-3 py-4 text-center text-gray-500">All payments are settled.</td>
              </tr>
            <?php endif; ?>
          </tbody>
          <?php if ($outstanding_total > 0): ?>
            <tfoot>
              <tr class="bg-gray-50">
                <td colspan="3" class="px-3 py-2 text-right font-medium text-gray-600">Total Outstanding:</td>
                <td class="px-3 py-2 text-right font-bold text-gray-800"><?php echo safeFormatCurrency($outstanding_total); ?></td>
                <td></td>
              </tr>
            </tfoot>
          <?php endif; ?>
        </table>
      </div>
      <div class="mt-4 text-right">
        <a href="submit_payment.php" class="text-xs inline-block bg-green-600 text-white px-3 py-2 rounded hover:bg-green-700">
          Make a Payment
        </a>
      </div>
    </div>
  <?php endif; ?>
</section>

<?php include 'includes/footer.php'; ?>