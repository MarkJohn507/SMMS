<?php
/**
 * register.php (Option A: Immediate Vendor Activation)
 *
 * This version is the original register.php with inline availability CSS and JS
 * for live "Available" / "Taken" indicators for username, email and contact number.
 *
 * - The availability endpoint expected is /check_availability.php (place that file in webroot).
 * - CSS is inlined right after includes/header.php so styles are available immediately.
 * - JS is inlined just before the footer include so it runs after the DOM is ready.
 *
 * NOTE: Keep the backend check_availability.php endpoint in place for the live checks.
 */

require_once 'config.php';
require_once 'includes/helpers.php';
require_once 'includes/csrf.php';
require_once 'includes/audit.php';
require_once 'includes/auth_roles.php';
require_once 'includes/mailer.php';
require_once 'includes/recaptcha.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

$page_title = 'Register Account';
$errors  = [];
$success = '';

$is_logged_in     = isLoggedIn();
$can_create_other = $is_logged_in && !empty($_SESSION['is_admin']); // Admin interface flag

try {
    $roles_list = $db->fetchAll("SELECT role_id, name FROM roles ORDER BY name") ?: [];
    $roles_by_name = [];
    foreach ($roles_list as $r) {
        $roles_by_name[strtolower($r['name'])] = $r;
    }
} catch (Throwable $e) {
    error_log("register: roles load failed: ".$e->getMessage());
    $roles_list     = [];
    $roles_by_name  = [];
}

/* Determine target role for public registration (only vendor or market_manager) */
$requested_public_role = 'vendor';
if (!$can_create_other) {
    $roleParam = strtolower(sanitize($_GET['role'] ?? $_POST['role'] ?? ''));
    if ($roleParam === 'market_manager') {
        $requested_public_role = 'market_manager';
    } else {
        $requested_public_role = 'vendor';
    }
}

/* Rate limit: max 5 attempts per IP per hour */
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$rate_ok = true;
try {
    $ra = $db->fetch("SELECT COUNT(*) c FROM register_attempts WHERE ip_address=? AND attempted_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)", [$ip]);
    if ((int)($ra['c'] ?? 0) >= 5) $rate_ok = false;
} catch (Throwable $e) {
    error_log("register: rate limit check failed: ".$e->getMessage());
}

/* Document rules */
$ROLE_DOC_RULES = [
    'market_manager' => ['required'=>['permit'], 'optional'=>['id']],
    'vendor'         => ['required'=>['permit'], 'optional'=>['id']],
];

$uploaded_permit = null;
$uploaded_id     = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_validate_request()) {
        $errors[] = 'Invalid CSRF token.';
    } else {
        /* reCAPTCHA */
        if (!empty(RECAPTCHA_SITE_KEY)) {
            $recaptchaToken = $_POST['g-recaptcha-response'] ?? '';
            if (!verifyRecaptcha($recaptchaToken, $_SERVER['REMOTE_ADDR'] ?? null)) {
                $errors[] = 'reCAPTCHA verification failed.';
            }
        }
        if (!$rate_ok) {
            $errors[] = 'Too many registration attempts. Please try again later.';
        } else {
            // Resolve role name
            $role_name = $can_create_other
                ? strtolower(sanitize($_POST['admin_role'] ?? 'vendor'))
                : $requested_public_role;

            // Restrict super_admin creation
            if ($can_create_other && $role_name === 'super_admin') {
                $errors[] = 'Cannot create super_admin via this form.';
                $role_name = 'vendor';
            }

            // Accept only valid roles for admin creation
            if ($can_create_other && !in_array($role_name, ['vendor','market_manager','accountant','inspector'], true)) {
                $role_name = 'vendor';
            }

            // Public only vendor or market_manager
            if (!$can_create_other && !in_array($role_name, ['vendor','market_manager'], true)) {
                $role_name = 'vendor';
            }

            $username         = sanitize($_POST['username'] ?? '');
            $full_name        = sanitize($_POST['full_name'] ?? '');
            $password         = $_POST['password'] ?? '';
            $password_confirm = $_POST['password_confirm'] ?? '';
            $email            = sanitize($_POST['email'] ?? '');
            $contact          = sanitize($_POST['contact_number'] ?? '');

            if ($username === '' || $full_name === '' || $password === '') {
                $errors[] = 'Username, full name, and password are required.';
            }
            if ($password !== $password_confirm) {
                $errors[] = 'Passwords do not match.';
            }
            if (strlen($password) < 8) {
                $errors[] = 'Password must be at least 8 characters.';
            }
            if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $errors[] = 'Invalid email address.';
            }
            if ($contact !== '') {
                $cleanContact = preg_replace('/[^\d\+]/', '', $contact);
                if (strlen($cleanContact) < 7) {
                    $errors[] = 'Invalid contact number.';
                }
            }

            $docRule      = $ROLE_DOC_RULES[$role_name] ?? ['required'=>['permit'], 'optional'=>['id']];
            $requiredDocs = $docRule['required'];
            $optionalDocs = $docRule['optional'];

            $validateUpload = function($field) {
                if (!isset($_FILES[$field]) || $_FILES[$field]['error'] !== UPLOAD_ERR_OK) return null;
                $f = $_FILES[$field];
                $maxBytes = 5 * 1024 * 1024;
                if ($f['size'] > $maxBytes) return ['error'=>"File '{$field}' exceeds 5MB."];
                try {
                    $finfo = new finfo(FILEINFO_MIME_TYPE);
                    $mime  = $finfo->file($f['tmp_name']);
                } catch (Throwable $e) {
                    $mime = null;
                }
                $allowed = ['image/jpeg'=>'jpg','image/png'=>'png'];
                if (!$mime || !isset($allowed[$mime])) return ['error'=>"File '{$field}' must be JPEG or PNG."];
                return [
                    'tmp_name'  => $f['tmp_name'],
                    'orig_name' => $f['name'],
                    'mime'      => $mime,
                    'ext'       => $allowed[$mime],
                    'size'      => $f['size']
                ];
            };

            if (in_array('permit', $requiredDocs, true)) {
                $meta = $validateUpload('document_permit');
                if ($meta === null) {
                    $errors[] = 'Permit is required.';
                } elseif (!empty($meta['error'])) {
                    $errors[] = $meta['error'];
                } else {
                    $uploaded_permit = $meta;
                }
            }

            if (in_array('id', $optionalDocs, true)) {
                $meta = $validateUpload('document_id');
                if ($meta && empty($meta['error'])) {
                    $uploaded_id = $meta;
                } elseif ($meta && !empty($meta['error'])) {
                    $errors[] = $meta['error'];
                }
            }

            // Uniqueness checks
            try {
                if ($username !== '') {
                    $exU = $db->fetch("SELECT 1 FROM users WHERE username=? LIMIT 1", [$username]);
                    if ($exU) $errors[] = 'Username already taken.';
                }
                if ($email !== '') {
                    $exE = $db->fetch("SELECT 1 FROM users WHERE email=? LIMIT 1", [$email]);
                    if ($exE) $errors[] = 'Email already used.';
                }
                if ($contact !== '') {
                    $exC = $db->fetch("SELECT 1 FROM users WHERE contact_number=? LIMIT 1", [$contact]);
                    if ($exC) $errors[] = 'Contact number already used.';
                }
            } catch (Throwable $e) {
                error_log("register uniqueness fail: ".$e->getMessage());
                $errors[] = 'Server error during validation.';
            }

            if (empty($errors)) {
                $hash               = password_hash($password, PASSWORD_DEFAULT);
                // OPTION A ACTIVATION LOGIC:
                // Admin-created: active
                // Public vendor: active immediately
                // Public market_manager: pending (requires admin review)
                if ($can_create_other) {
                    $user_status = 'active';
                } else {
                    $user_status = ($role_name === 'vendor') ? 'active' : 'pending';
                }

                $user_id_new      = null;
                $user_role_id_new = null;
                $tx_ok            = false;

                try {
                    if (method_exists($db,'beginTransaction')) $db->beginTransaction();

                    $db->query(
                        "INSERT INTO users (username,password,full_name,email,contact_number,role,status,created_at)
                         VALUES (?,?,?,?,?,?,?,NOW())",
                        [$username,$hash,$full_name,$email,$contact,$role_name,$user_status]
                    );
                    $user_id_new = (int)$db->lastInsertId();

                    if (isset($roles_by_name[$role_name])) {
                        $assigned_by  = $can_create_other ? ($_SESSION['user_id'] ?? null) : null;
                        $role_id_real = (int)$roles_by_name[$role_name]['role_id'];
                        $map_status   = $can_create_other
                            ? 'active'
                            : (($role_name === 'vendor') ? 'active' : 'pending');

                        $db->query(
                            "INSERT INTO user_roles (user_id,role_id,status,assigned_by,assigned_at)
                             VALUES (?,?,?,?,NOW())",
                            [$user_id_new,$role_id_real,$map_status,$assigned_by]
                        );
                        $user_role_id_new = (int)$db->lastInsertId();
                    }

                    // Save uploads
                    $baseDir = __DIR__.'/uploads/user_documents/'.$user_id_new.'/';
                    if (!is_dir($baseDir)) @mkdir($baseDir,0755,true);

                    $saveUpload = function($meta,$type,$uid) use ($db,$baseDir) {
                        $destName = time().'_'.bin2hex(random_bytes(8)).'.'.$meta['ext'];
                        $destPath = $baseDir.$destName;
                        $rel      = 'uploads/user_documents/'.$uid.'/'.$destName;
                        if (@move_uploaded_file($meta['tmp_name'],$destPath) ||
                            @rename($meta['tmp_name'],$destPath) ||
                            @copy($meta['tmp_name'],$destPath)) {
                            try {
                                $db->query(
                                    "INSERT INTO user_documents (user_id,file_path,file_name,file_type,uploaded_at)
                                     VALUES (?,?,?,?,NOW())",
                                    [$uid,$rel,$destName,$type]
                                );
                            } catch (Throwable $e) {
                                error_log("register: user_documents insert failed: ".$e->getMessage());
                            }
                            return $rel;
                        }
                        return null;
                    };

                    $permitPath = $uploaded_permit ? $saveUpload($uploaded_permit,'permit',$user_id_new) : null;
                    $idPath     = $uploaded_id     ? $saveUpload($uploaded_id,'id',$user_id_new)       : null;

                    if ($user_role_id_new) {
                        $docRows = [];
                        if ($permitPath) $docRows[] = ['doc_type'=>'permit','path'=>$permitPath,'orig'=>$uploaded_permit['orig_name']];
                        if ($idPath)     $docRows[] = ['doc_type'=>'id','path'=>$idPath,'orig'=>$uploaded_id['orig_name']];
                        foreach ($docRows as $d) {
                            try {
                                $db->query(
                                    "INSERT INTO user_role_documents
                                      (user_role_id,doc_type,file_path,original_filename,status,admin_notes,uploaded_at)
                                     VALUES (?,?,?,?, 'pending', ?, NOW())",
                                    [$user_role_id_new,$d['doc_type'],$d['path'],$d['orig'],
                                     "[Uploaded at ".date('Y-m-d H:i:s')."]"]
                                );
                            } catch (Throwable $e) {
                                error_log("register: user_role_documents insert failed: ".$e->getMessage());
                            }
                        }
                    }

                    // Email verification
                    if ($email !== '') {
                        try {
                            $token   = bin2hex(random_bytes(32));
                            $expires = date('Y-m-d H:i:s', time()+86400);
                            $db->query(
                                "INSERT INTO email_verifications (user_id,token,expires_at,created_at)
                                 VALUES (?,?,?,NOW())",
                                [$user_id_new,$token,$expires]
                            );
                            sendVerificationEmail($db,$user_id_new,$email,$full_name,$token);
                        } catch (Throwable $e) {
                            error_log("register: email verification insert failed: ".$e->getMessage());
                        }
                    }

                    // Log attempt
                    try {
                        $db->query("INSERT INTO register_attempts (ip_address,attempted_at) VALUES (?,NOW())",[$ip]);
                    } catch (Throwable $e) {
                        error_log("register: register_attempts insert failed: ".$e->getMessage());
                    }

                    // Notify super_admins for market_manager requests (still pending)
                    if (!$can_create_other && $role_name === 'market_manager') {
                        try {
                            $admins = $db->fetchAll("
                                SELECT u.user_id
                                FROM user_roles ur
                                JOIN roles r ON ur.role_id=r.role_id
                                JOIN users u ON u.user_id=ur.user_id
                                WHERE r.name='super_admin' AND ur.status='active'
                            ") ?: [];
                            foreach ($admins as $a) {
                                $msg = "User {$full_name} ({$username}) registered requesting Market Manager role. Review documents.";
                                $db->query(
                                    "INSERT INTO notifications (user_id,title,message,type,category,created_at)
                                     VALUES (?,?,?,'info','role_request',NOW())",
                                    [$a['user_id'],'Market Manager request pending',$msg]
                                );
                            }
                        } catch (Throwable $e) {
                            error_log("register: notification insert failed: ".$e->getMessage());
                        }
                    }

                    if (method_exists($db,'commit')) $db->commit();
                    $tx_ok = true;

                } catch (Throwable $e) {
                    if (method_exists($db,'rollBack')) $db->rollBack();

                    // Attempt to detect duplicate-key constraint violations (MySQL)
                    $errMsg = $e->getMessage();
                    $handled = false;

                    // If PDOException, we can inspect errorInfo if available
                    if ($e instanceof PDOException) {
                        $info = $e->errorInfo ?? null; // [SQLSTATE, driverCode, driverMessage]
                        if (is_array($info) && !empty($info[1])) {
                            $driverCode = (int)$info[1];
                            // 1062 is MySQL duplicate entry
                            if ($driverCode === 1062) {
                                // driverMessage contains "Duplicate entry '...' for key 'ux_users_email'" etc
                                if (stripos($errMsg, 'email') !== false) {
                                    $errors[] = 'Email already in use.';
                                } elseif (stripos($errMsg, 'contact_number') !== false || stripos($errMsg, 'contact') !== false) {
                                    $errors[] = 'Contact number already used.';
                                } elseif (stripos($errMsg, 'username') !== false) {
                                    $errors[] = 'Username already taken.';
                                } else {
                                    $errors[] = 'A duplicate value already exists (email/phone/username).';
                                }
                                $handled = true;
                            }
                        }
                    }

                    // Generic message parsing fallback (for other DB layers)
                    if (!$handled && stripos($errMsg, 'Duplicate entry') !== false) {
                        if (stripos($errMsg, 'email') !== false) {
                            $errors[] = 'Email already in use.';
                        } elseif (stripos($errMsg, 'contact_number') !== false || stripos($errMsg, 'contact') !== false) {
                            $errors[] = 'Contact number already used.';
                        } elseif (stripos($errMsg, 'username') !== false) {
                            $errors[] = 'Username already taken.';
                        } else {
                            $errors[] = 'A duplicate value already exists (email/phone/username).';
                        }
                        $handled = true;
                    }

                    if (!$handled) {
                        error_log("register: transaction failed: " . $e->getMessage());
                        $errors[] = 'Registration failed. Please try again later.';
                    }
                }

                if ($tx_ok) {
                    logAudit($db,$user_id_new,($can_create_other?'User Created by Admin':'User Registered'),
                        'users',$user_id_new,null,null);

                    if ($can_create_other) {
                        $success = 'Account created successfully.';
                    } else {
                        if ($role_name === 'market_manager') {
                            $success = 'Registration successful. Market Manager role is pending admin review.';
                        } else {
                            // Vendor immediate activation
                            $success = 'Registration successful. Your vendor account is active; you may log in now.';
                        }
                        $_POST = []; // clear form
                    }
                }
            }
        }
    }

    if (!empty($errors)) {
        // Clear uploaded meta on error to avoid confusion
        $uploaded_permit = null;
        $uploaded_id     = null;
    }
}

require_once 'includes/header.php';

?>
<!-- Inline availability CSS (small) -->
<style>
/* availability indicator styles */
.availability-status { font-weight: 600; font-size: 0.92rem; min-width:72px; display:inline-block; }
.av-checked { opacity: 0.9; transition: opacity 120ms ease-in-out; }
.av-checking { color: #6b7280; } /* gray */
.av-available { color: #16a34a; } /* green-600 */
.av-taken { color: #dc2626; } /* red-600 */
.av-error { color: #6b7280; }
.animate-pulse { opacity: 0.7; }
</style>

<div class="max-w-md mx-auto p-6 bg-white rounded shadow">
  <h2 class="text-xl font-bold mb-4"><?php echo htmlspecialchars($page_title); ?></h2>

  <?php if ($errors): ?>
    <div class="mb-4 text-red-600 space-y-1">
      <?php foreach ($errors as $e): ?>
        <div><?php echo htmlspecialchars($e); ?></div>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>

  <?php if ($success): ?>
    <div class="mb-4 text-green-600"><?php echo htmlspecialchars($success); ?></div>
  <?php endif; ?>

  <form method="POST" enctype="multipart/form-data" novalidate>
    <?php echo csrf_field(); ?>

    <?php if (!$can_create_other): ?>
      <input type="hidden" name="role" value="<?php echo htmlspecialchars($requested_public_role); ?>">
      <div class="mb-4 text-sm">
        You are registering as
        <span class="font-semibold">
          <?php echo $requested_public_role === 'market_manager'
              ? 'Market Manager (Pending Approval)'
              : 'Vendor (Active Immediately)'; ?>
        </span>.
        <?php if ($requested_public_role === 'market_manager'): ?>
          <span class="text-gray-600">Your account will become fully active after admin approval.</span>
        <?php else: ?>
          <span class="text-gray-600">You can log in right after completing this form.</span>
        <?php endif; ?>
      </div>
    <?php else: ?>
      <div class="mb-4">
        <label class="block text-sm font-medium mb-1">Assign Role (admin)</label>
        <select name="admin_role" class="w-full border px-3 py-2">
          <?php
            $sel = strtolower($_POST['admin_role'] ?? 'vendor');
            foreach ($roles_list as $r) {
                $lower = strtolower($r['name']);
                if ($lower === 'super_admin') continue; // block super admin
                echo '<option value="'.htmlspecialchars($lower).'" '.($lower===$sel?'selected':'').'>'
                     .htmlspecialchars(ucwords(str_replace('_',' ',$r['name']))).'</option>';
            }
          ?>
        </select>
      </div>
    <?php endif; ?>

    <div class="mb-3">
      <label class="block text-sm font-medium">Username *</label>
      <div class="flex items-center gap-3">
        <input id="username" name="username" required class="w-full border px-3 py-2"
               value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>">
        <span id="status_username" class="availability-status" data-status-for="username"></span>
      </div>
    </div>

    <div class="mb-3">
      <label class="block text-sm font-medium">Full Name *</label>
      <input name="full_name" required class="w-full border px-3 py-2"
         value="<?php echo htmlspecialchars($_POST['full_name'] ?? ''); ?>">
    </div>

    <div class="mb-3">
        <label class="block text-sm font-medium">Email</label>
        <div class="flex items-center gap-3">
            <input id="email" name="email" type="email" class="w-full border px-3 py-2"
                value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>">
            <span id="status_email" class="availability-status" data-status-for="email"></span>
        </div>
    </div>

    <div class="mb-3">
        <label class="block text-sm font-medium">Contact Number</label>
        <div class="flex items-center gap-3">
            <input id="contact_number" name="contact_number" class="w-full border px-3 py-2"
                value="<?php echo htmlspecialchars($_POST['contact_number'] ?? ''); ?>">
            <span id="status_contact_number" class="availability-status" data-status-for="contact_number"></span>
        </div>
    </div>

    <div class="mb-3">
    <label class="block text-sm font-medium">Password *</label>
      <input name="password" type="password" required minlength="8"
             class="w-full border px-3 py-2">
    </div>

    <div class="mb-4">
      <label class="block text-sm font-medium">Confirm Password *</label>
      <input name="password_confirm" type="password" required minlength="8"
             class="w-full border px-3 py-2">
    </div>

    <div class="mb-3">
      <label class="block text-sm font-medium">
        Permit (Mayor / Business Permit) — REQUIRED
      </label>
      <input type="file" name="document_permit" accept="image/jpeg,image/png"
             class="w-full border px-3 py-2">
      <p class="text-xs text-gray-500 mt-1">Upload a clear image (JPEG/PNG ≤5MB).</p>
    </div>

    <div class="mb-4">
      <label class="block text-sm font-medium">
        Government ID (OPTIONAL)
      </label>
      <input type="file" name="document_id" accept="image/jpeg,image/png"
             class="w-full border px-3 py-2">
      <p class="text-xs text-gray-500 mt-1">Optional but may speed up verification.</p>
    </div>

    <?php if (!empty(RECAPTCHA_SITE_KEY)): ?>
      <div class="mb-4">
        <div class="g-recaptcha" data-sitekey="<?php echo htmlspecialchars(RECAPTCHA_SITE_KEY); ?>"></div>
      </div>
      <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <?php endif; ?>

    <div class="flex gap-2">
      <button class="bg-blue-600 text-white px-4 py-2 rounded">
        <?php echo $can_create_other ? 'Create Account' : 'Register'; ?>
      </button>
      <a href="login.php" class="px-4 py-2 bg-gray-200 rounded">Back to login</a>
    </div>
  </form>
</div>

<!-- Inline availability JS (runs after DOM) -->
<script>
(function(){
  const ENDPOINT = 'check_availability.php'; // ensure this endpoint exists
  const debounce = (fn, wait) => {
    let t = null;
    return (...args) => {
      if (t) clearTimeout(t);
      t = setTimeout(()=> fn(...args), wait);
    };
  };

  const show = (el, text, state) => {
    el.classList.remove('av-checked','av-checking','av-available','av-taken','av-error','animate-pulse');
    el.textContent = text || '';
    if (state === 'checking') {
      el.classList.add('av-checked','av-checking','animate-pulse');
    } else if (state === 'available') {
      el.classList.add('av-checked','av-available');
    } else if (state === 'taken') {
      el.classList.add('av-checked','av-taken');
    } else {
      el.classList.add('av-checked','av-error');
    }
  };

  const check = async (field, value, statusEl) => {
    if (!value || value.trim() === '') {
      show(statusEl, '', ''); return;
    }
    show(statusEl, 'Checking…', 'checking');
    try {
      const url = `${ENDPOINT}?field=${encodeURIComponent(field)}&value=${encodeURIComponent(value)}`;
      const res = await fetch(url, { method: 'GET', credentials: 'same-origin' });
      if (!res.ok) {
        show(statusEl, 'Error', 'error'); return;
      }
      const json = await res.json();
      if (!json || !json.ok) {
        show(statusEl, 'Error', 'error'); return;
      }
      if (json.available) {
        show(statusEl, 'Available', 'available');
      } else {
        show(statusEl, 'Taken', 'taken');
      }
    } catch (err) {
      console.error('availability check failed', err);
      show(statusEl, 'Error', 'error');
    }
  };

  const attach = (inputId, fieldName) => {
    const input = document.getElementById(inputId);
    if (!input) return;
    const statusEl = document.getElementById('status_'+inputId);
    if (!statusEl) return;
    const debounced = debounce((v)=> check(fieldName, v, statusEl), 450);
    input.addEventListener('input', (e) => debounced(e.target.value));
    input.addEventListener('blur', (e) => debounced(e.target.value));
    // run initial check if value present (helpful when returning with errors)
    if (input.value && input.value.trim() !== '') {
      setTimeout(()=> debounced(input.value), 200);
    }
  };

  document.addEventListener('DOMContentLoaded', function(){
    attach('username','username');
    attach('email','email');
    attach('contact_number','contact_number');
  });
})();
</script>

<?php include 'includes/footer.php'; ?>