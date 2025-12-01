<?php
/**
 * login.php
 *
 * NOTE (Adjusted):
 *  - "Register as Vendor" link now forces vendor registration by adding ?role=vendor
 *    so the registration page will not show a role selector (it auto-locks to vendor).
 *  - Market Manager requests still go through ?role=market_manager.
 *  - Added an eye icon to toggle password visibility on the password input.
 */

require_once 'config.php';
require_once 'includes/helpers.php';
require_once 'includes/auth_roles.php';
require_once 'includes/csrf.php';
require_once 'includes/audit.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

$page_title = 'Login';
$error = '';
$success = '';

function login_debug_log(string $msg) {
    error_log($msg);
    $dbg = (($_GET['debug'] ?? $_POST['debug'] ?? '') === '1');
    if ($dbg) {
        echo "<pre style='background:#111;color:#bada55;padding:6px;margin:6px 0;font-size:12px;border-radius:4px'>DEBUG: "
           . htmlspecialchars($msg) . "</pre>";
    }
}

function computePrimaryRole(array $roles): ?string {
    $priority = ['super_admin','market_manager','accountant','inspector','vendor'];
    foreach ($priority as $p) {
        if (in_array($p, $roles, true)) return $p;
    }
    return $roles[0] ?? null;
}

function getDashboardForRole(?string $role): string {
    $map = [
        'super_admin'    => 'admin_dashboard.php',
        'market_manager' => 'admin_dashboard.php',
        'accountant'     => 'admin_dashboard.php',
        'inspector'      => 'admin_dashboard.php',
        'vendor'         => 'vendor_dashboard.php',
    ];
    $r = is_string($role) ? strtolower($role) : null;
    return $map[$r] ?? 'vendor_dashboard.php';
}

function recordLoginAttempt($db,$username,$ip,$ok){
    try {
        $db->query("INSERT INTO login_attempts (username, ip_address, success, attempted_at) VALUES (?,?,?,NOW())",
            [$username,$ip,$ok?1:0]);
    } catch (Throwable $e) {
        login_debug_log("recordLoginAttempt: ".$e->getMessage());
    }
}

function tooManyFailedAttempts($db,$username,$ip,$threshold=6,$minutes=15): bool {
    try {
        $row = $db->fetch("SELECT COUNT(*) c FROM login_attempts WHERE username=? AND success=0 AND attempted_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)",
            [$username,$minutes]);
        return (int)($row['c'] ?? 0) >= $threshold;
    } catch (Throwable $e) {
        return false;
    }
}

if (function_exists('isLoggedIn') && isLoggedIn()) {
    redirect(getDashboardForRole($_SESSION['primary_role'] ?? null));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_validate_request()) {
        $error = 'Invalid CSRF token.';
    } else {
        $username = sanitize($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $ip       = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

        if ($username === '' || $password === '') {
            $error = 'Please enter both username and password.';
        } elseif (tooManyFailedAttempts($db,$username,$ip)) {
            $error = 'Too many failed attempts. Try again later.';
            logAudit($db,null,'Login Blocked - Rate Limit','users',null,null,null);
        } else {
            try {
                $user = $db->fetch("SELECT user_id, username, password, full_name, role, status, system_status FROM users WHERE username=? LIMIT 1", [$username]);
            } catch (Throwable $e) {
                error_log("login fetch user fail: ".$e->getMessage());
                $user = null;
            }

            login_debug_log("Fetched user keys=".json_encode(array_keys((array)$user)));

            $loginOk = false;
            $resubmitRows = [];
            $hasUnderReview = false;
            $hasProvisional = false;
            $docRejected = false;

            if ($user) {
                $hash = trim((string)$user['password']);
                if ($hash !== '' && function_exists('password_verify') && password_verify($password,$hash)) {
                    $loginOk = true;
                    login_debug_log("Password verify OK uid={$user['user_id']}");
                } elseif ($hash !== '' && hash_equals($hash,$password)) {
                    $loginOk = true;
                    login_debug_log("Legacy plaintext matched uid={$user['user_id']}, rehashing.");
                    try {
                        $newHash = password_hash($password,PASSWORD_DEFAULT);
                        if ($newHash) {
                            $db->query("UPDATE users SET password=? WHERE user_id=?", [$newHash,$user['user_id']]);
                        }
                    } catch (Throwable $e) { error_log("rehash fail: ".$e->getMessage()); }
                }

                if ($loginOk) {
                    if (!empty($user['system_status']) && strtolower($user['system_status']) === 'suspended') {
                        $error = 'Your account has been suspended. Contact support.';
                        $loginOk = false;
                        login_debug_log("Blocked suspended uid={$user['user_id']}");
                    } else {
                        $uid = (int)$user['user_id'];

                        try {
                            $resubmitRows = $db->fetchAll(
                                "SELECT ur.user_role_id, r.name AS role_name, ur.status,
                                        COALESCE(ur.resubmission_reason, ur.admin_notes) AS instructions
                                 FROM user_roles ur
                                 JOIN roles r ON ur.role_id = r.role_id
                                 WHERE ur.user_id = ?
                                   AND (
                                        LOWER(TRIM(ur.status)) IN ('rejected','revoked','denied','declined')
                                        OR (LOWER(TRIM(ur.status))='pending' AND ur.resubmission_reason IS NOT NULL)
                                   )
                                 ORDER BY ur.user_role_id DESC
                                 LIMIT 10",
                                [$uid]
                            ) ?: [];
                        } catch (Throwable $e) {}

                        try { $hasUnderReview = (bool)$db->fetch("SELECT 1 FROM user_roles WHERE user_id=? AND LOWER(TRIM(status))='under_review' LIMIT 1", [$uid]); } catch (Throwable $e) {}
                        try { $hasProvisional = (bool)$db->fetch("SELECT 1 FROM user_roles WHERE user_id=? AND LOWER(TRIM(status))='provisional_active' LIMIT 1", [$uid]); } catch (Throwable $e) {}
                        try {
                            $docRejected = (bool)$db->fetch(
                                "SELECT 1
                                 FROM user_role_documents d
                                 JOIN user_roles ur ON d.user_role_id = ur.user_role_id
                                 WHERE ur.user_id = ? AND d.status='rejected'
                                 LIMIT 1", [$uid]
                            );
                        } catch (Throwable $e) {}

                        login_debug_log("resubmitRows=".count($resubmitRows)
                            . " under_review=".($hasUnderReview?'1':'0')
                            . " provisional=".($hasProvisional?'1':'0')
                            . " doc_rejected=".($docRejected?'1':'0')
                            . " acct_status=".strtolower(trim((string)$user['status'])));

                        $acctPending = (trim(strtolower((string)$user['status'])) === 'pending');
                        if ($acctPending
                            && empty($resubmitRows)
                            && !$hasUnderReview
                            && !$hasProvisional
                            && !$docRejected) {
                            $error = 'Your account is pending verification. Please wait for admin approval.';
                            $loginOk = false;
                            login_debug_log("Blocked: pure pending uid={$uid}");
                        }
                    }
                }
            }

            if ($loginOk) {
                $roleNames = [];
                try {
                    $activeRoles = $db->fetchAll(
                        "SELECT r.name
                         FROM user_roles ur
                         JOIN roles r ON ur.role_id = r.role_id
                         WHERE ur.user_id=? AND ur.status IN ('active','provisional_active')
                         ORDER BY ur.user_role_id DESC",
                        [$user['user_id']]
                    ) ?: [];
                    foreach ($activeRoles as $ar) {
                        if (!empty($ar['name'])) $roleNames[] = strtolower(trim($ar['name']));
                    }
                } catch (Throwable $e) {}

                if (empty($roleNames) && !empty($user['role'])) {
                    $roleNames[] = strtolower(trim($user['role']));
                }

                session_regenerate_id(true);
                $_SESSION['user_id']       = $user['user_id'];
                $_SESSION['username']      = $user['username'];
                $_SESSION['full_name']     = $user['full_name'];
                $_SESSION['last_activity'] = time();
                $_SESSION['roles']         = $roleNames;
                $_SESSION['primary_role']  = computePrimaryRole($roleNames);
                $_SESSION['is_admin']      = in_array($_SESSION['primary_role'], ['super_admin','market_manager','accountant','inspector'], true);

                if ($hasProvisional) {
                    $_SESSION['provisional_banner'] = 'Your role is provisionally active pending final document approval.';
                } else {
                    unset($_SESSION['provisional_banner']);
                }

                logAudit($db,$user['user_id'],'User Login','users',$user['user_id'],null,null);
                recordLoginAttempt($db,$username,$ip,true);

                if (!empty($resubmitRows) || $docRejected) {
                    $targetRoleRequestId = null;
                    if (!empty($resubmitRows)) {
                        foreach ($resubmitRows as $rr) {
                            if (isset($rr['role_name']) && strtolower($rr['role_name']) === 'market_manager') {
                                $targetRoleRequestId = (int)$rr['user_role_id']; break;
                            }
                        }
                        if (!$targetRoleRequestId) {
                            $targetRoleRequestId = (int)$resubmitRows[0]['user_role_id'];
                        }
                        $_SESSION['rejected_role_request'] = [
                            'user_role_id' => $targetRoleRequestId,
                            'status'       => $resubmitRows[0]['status'] ?? 'rejected',
                            'instructions' => $resubmitRows[0]['instructions'] ?? ''
                        ];
                    } else {
                        $row = $db->fetch(
                            "SELECT ur.user_role_id, r.name AS role_name
                             FROM user_roles ur
                             JOIN roles r ON ur.role_id = r.role_id
                             JOIN user_role_documents d ON d.user_role_id = ur.user_role_id
                             WHERE ur.user_id = ? AND d.status='rejected'
                             ORDER BY ur.user_role_id DESC
                             LIMIT 1",
                            [$user['user_id']]
                        );
                        if ($row) {
                            $targetRoleRequestId = (int)$row['user_role_id'];
                            $_SESSION['rejected_role_request'] = [
                                'user_role_id' => $targetRoleRequestId,
                                'status'       => 'rejected',
                                'instructions' => 'Document-level rejection — please correct and resubmit.'
                            ];
                        }
                    }
                    if ($targetRoleRequestId) {
                        redirect('resubmit_role_request.php?user_role_id=' . $targetRoleRequestId);
                        exit;
                    }
                }

                redirect(getDashboardForRole($_SESSION['primary_role']));
            } else {
                if ($error === '') $error = 'Invalid username or password.';
                recordLoginAttempt($db,$username,$ip,false);
                logAudit($db,null,'Failed Login','users',null,null,null);
            }
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Login - <?php echo htmlspecialchars(APP_NAME); ?></title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    /* Small helper to make the eye button unobtrusive */
    .pw-toggle-btn { background: transparent; border: none; padding: 0.25rem; display:flex; align-items:center; justify-content:center; }
    .pw-toggle-btn svg { width: 1.25rem; height: 1.25rem; color: #6b7280; }
  </style>
</head>
<body class="bg-gradient-to-br from-blue-50 to-indigo-100 min-h-screen flex items-center justify-center p-4">
  <div class="w-full max-w-5xl mx-auto">
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-8 items-start">
      <div class="bg-white shadow-xl rounded-2xl p-8 lg:p-10">
        <div class="text-center mb-8">
          <div class="inline-block p-3 bg-blue-600 rounded-xl mb-4">
            <svg class="w-12 h-12 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"></path>
            </svg>
          </div>
          <h1 class="text-3xl font-bold text-gray-800"><?php echo htmlspecialchars(APP_NAME); ?></h1>
          <p class="text-sm text-gray-600 mt-1">Smart Market Stall Management</p>
        </div>

        <?php if (!empty($_GET['debug']) && $_GET['debug']==='1'): ?>
          <div class="bg-yellow-50 border-l-4 border-yellow-500 text-yellow-800 px-4 py-3 rounded mb-4">
            Debug mode ON — submit to view internal steps.
          </div>
        <?php endif; ?>

        <?php if ($error): ?>
          <div class="bg-red-50 border-l-4 border-red-500 text-red-700 px-4 py-3 rounded mb-6">
            <p class="font-medium">Error</p>
            <p class="text-sm"><?php echo htmlspecialchars($error); ?></p>
          </div>
        <?php endif; ?>

        <?php if ($success): ?>
          <div class="bg-green-50 border-l-4 border-green-500 text-green-700 px-4 py-3 rounded mb-6">
            <p class="text-sm"><?php echo htmlspecialchars($success); ?></p>
          </div>
        <?php endif; ?>

        <form method="post"
              action="login.php?debug=<?php echo (!empty($_GET['debug']) && $_GET['debug']==='1')?'1':'0'; ?>"
              autocomplete="off"
              class="space-y-5">
          <?php echo csrf_field(); ?>
          <input type="hidden" name="debug" value="<?php echo (!empty($_GET['debug']) && $_GET['debug']==='1')?'1':'0'; ?>">

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">Username</label>
            <input type="text" name="username" required
                   class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                   placeholder="Enter your username"
                   value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>">
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">Password</label>
            <div class="relative">
              <input id="passwordInput" type="password" name="password" required
                     class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition pr-12"
                     placeholder="Enter your password" autocomplete="current-password">
              <button type="button" id="togglePassword" class="pw-toggle-btn absolute right-3 top-1/2 -translate-y-1/2" aria-label="Show password" title="Show password">
                <!-- Eye / Eye-off SVG will be swapped by JS; start with eye -->
                <svg id="eyeIcon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M2.458 12C3.732 7.943 7.523 5 12 5c4.477 0 8.268 2.943 9.542 7-1.274 4.057-5.065 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                </svg>
              </button>
            </div>
          </div>

          <div class="flex items-center justify-between text-sm">
            <label class="flex items-center">
              <input type="checkbox" class="rounded border-gray-300 text-blue-600 focus:ring-blue-500">
              <span class="ml-2 text-gray-600">Remember me</span>
            </label>
            <a href="forgot_password.php" class="text-blue-600 hover:underline">Forgot password?</a>
          </div>

          <div class="flex items-center gap-3">
            <button type="submit"
                    class="w-full md:w-auto bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg shadow-md hover:shadow-lg">
              Sign In
            </button>
            <a href="forgot_password.php" class="hidden md:inline-block text-sm bg-gray-100 hover:bg-gray-200 text-gray-800 px-3 py-2 rounded">Forgot password?</a>
          </div>
        </form>

        <div class="mt-6 pt-6 border-t border-gray-200 text-center">
          <p class="text-sm text-gray-600">
            Don't have an account?
            <!-- Force vendor role -->
            <a href="register.php?role=vendor" class="text-blue-600 hover:underline font-semibold">Register as Vendor</a>
          </p>
        </div>
      </div>

      <div class="bg-white shadow-xl rounded-2xl p-8 lg:p-10">
        <h2 class="text-2xl font-bold text-gray-800 mb-2">Request Management Access</h2>
        <p class="text-sm text-gray-600 mb-4">
          Need elevated access? Request a Market Manager account. Admin approval is required.
        </p>
        <a href="register.php?role=market_manager"
           class="group block p-6 bg-gradient-to-br from-green-50 to-emerald-50 rounded-xl border-2 border-green-200
                  hover:border-green-400 hover:shadow-lg transition-all duration-200">
          <div class="flex items-center gap-4">
            <div class="flex-shrink-0">
              <div class="w-16 h-16 bg-gradient-to-br from-green-500 to-emerald-600 text-white rounded-xl
                          flex items-center justify-center shadow-md group-hover:scale-110 transition-transform">
                <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
            </div>
            <div class="flex-1">
              <h3 class="text-lg font-semibold text-gray-800 group-hover:text-green-700 transition">Market Manager</h3>
              <p class="text-xs text-gray-600 mt-1">Manage markets, stalls & vendors</p>
              <div class="mt-2 inline-flex items-center text-xs font-medium text-amber-700 bg-amber-100 px-3 py-1 rounded-full">
                <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                  <path fill-rule="evenodd"
                        d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z"
                        clip-rule="evenodd"></path>
                </svg>
                Requires Admin Approval
              </div>
            </div>
            <div class="flex-shrink-0">
              <svg class="w-6 h-6 text-green-500 group-hover:translate-x-1 transition-transform"
                   fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                      d="M9 5l7 7-7 7"></path>
              </svg>
            </div>
          </div>
        </a>

        <div class="bg-blue-50 border border-blue-200 rounded-xl p-4 mt-6">
          <div class="flex gap-3">
            <div class="flex-shrink-0">
              <svg class="w-5 h-5 text-blue-600" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd"
                      d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z"
                      clip-rule="evenodd"></path>
              </svg>
            </div>
            <div class="flex-1">
              <h4 class="text-sm font-semibold text-blue-900 mb-1">Account Review Process</h4>
              <p class="text-xs text-blue-700">
                Administrators verify your documents. You will receive notifications if corrections are needed or once approved.
              </p>
            </div>
          </div>
        </div>

      </div>
    </div>
    <div class="text-center mt-8 text-sm text-gray-600">
      &copy; <?php echo date('Y'); ?> <?php echo htmlspecialchars(APP_NAME); ?>. All rights reserved.
    </div>
  </div>

  <script>
    (function(){
      const pwdInput = document.getElementById('passwordInput');
      const toggleBtn = document.getElementById('togglePassword');
      const eyeIcon = document.getElementById('eyeIcon');

      if (!pwdInput || !toggleBtn || !eyeIcon) return;

      function setEye(isVisible){
        // Replace inner SVG path for eye / eye-off
        if (isVisible) {
          eyeIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.269-2.943-9.543-7a9.956 9.956 0 012.582-4.01m3.05-2.8A9.969 9.969 0 0112 5c4.478 0 8.269 2.943 9.543 7a9.97 9.97 0 01-1.573 3.103M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>';
          toggleBtn.setAttribute('aria-label','Hide password');
          toggleBtn.title = 'Hide password';
        } else {
          eyeIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.477 0 8.268 2.943 9.542 7-1.274 4.057-5.065 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />';
          toggleBtn.setAttribute('aria-label','Show password');
          toggleBtn.title = 'Show password';
        }
      }

      toggleBtn.addEventListener('click', function(e){
        e.preventDefault();
        const isPwd = pwdInput.type === 'password';
        pwdInput.type = isPwd ? 'text' : 'password';
        setEye(isPwd);
      });

      // Initialize to hidden state
      setEye(false);
    })();
  </script>
</body>
</html>