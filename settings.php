<?php
error_log("php now: " . date('Y-m-d H:i:s'));
/**
 * settings.php
 * - Account settings with phone/email change flows using verification codes.
 * - Stores request timestamps using DB NOW() to avoid PHP/MySQL clock skew.
 * - Robust verification handlers with debug logging and preserved UI state.
 * - Availability checks via check_availability.php.
 *
 * Fixes included:
 * - Prevent re-upload when a document (Permit or ID) is already submitted and in 'pending' state.
 *   Per doc-type locking: if Permit is pending/approved, hide its input; same for ID.
 *   Server-side enforcement added to block uploads for locked doc types.
 * - Avatar circle turns GREEN when the account has a vendor role, otherwise BLUE.
 * - Replaced the "Account" text badge with the user's primary role label.
 * - Permit/ID "Approved" badge color: GREEN for vendor, BLUE for market_manager/accountant/inspector/others.
 */

require_once 'config.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';
require_once 'includes/csrf.php';
require_once 'includes/notifications.php';
require_once 'includes/helpers.php';
require_once __DIR__ . '/API/send_sms.php';
require_once __DIR__ . '/tools/send_confirmation_immediate.php';

if (!isLoggedIn()) {
    $_SESSION['intended_url'] = $_SERVER['REQUEST_URI'] ?? '/';
    redirect('login.php?timeout=1');
}
if (function_exists('refreshSessionRoles')) refreshSessionRoles($db);

$page_title = 'Account Settings';

$errors = [];
$profile_success  = '';
$password_success = '';
$email_success    = '';
$doc_success      = '';

$show_phone_panel = false;
$show_phone_verify = false;
$show_email_panel = false;
$show_email_verify = false;
$open_profile_section = false;

$user_id = getCurrentUserId();
if (!$user_id) redirect('login.php?timeout=1');

/* ----- Roles ----- */
$roleNames = [];
try {
    if (function_exists('_fetchUserRoleNames')) {
        $roleNames = _fetchUserRoleNames($user_id, $db) ?: [];
    } elseif (!empty($_SESSION['roles'])) {
        $roleNames = $_SESSION['roles'];
    }
} catch (Throwable $e) {
    error_log("settings: roles load fail: ".$e->getMessage());
    $roleNames = $_SESSION['roles'] ?? [];
}
$is_super_admin    = in_array('super_admin', $roleNames, true);
$is_vendor         = in_array('vendor', $roleNames, true);
$is_market_manager = in_array('market_manager', $roleNames, true);
$is_accountant     = in_array('accountant', $roleNames, true);
$is_inspector      = in_array('inspector', $roleNames, true);

$show_system_settings = ($is_super_admin || $is_market_manager || $is_accountant || isAdmin());
$showVerificationUI   = !$is_super_admin;

/* ----- Utility Functions ----- */
function normalize_phone_e164(string $raw, string $default_country = '+63'): ?string {
    $s = trim($raw);
    if ($s === '') return null;
    $digits = preg_replace('/[^\d+]/', '', $s);
    if ($digits === '') return null;
    if (strpos($digits, '+') === 0) return '+' . preg_replace('/[^\d]/', '', substr($digits, 1));
    if (strpos($digits, '00') === 0) return '+' . ltrim($digits, '0');
    if (strpos($digits, '0') === 0) {
        $n = ltrim($digits, '0');
        $cc = preg_replace('/[^\d]/', '', $default_country);
        return '+' . $cc . $n;
    }
    $cc = preg_replace('/[^\d]/', '', $default_country);
    return '+' . $cc . preg_replace('/[^\d]/', '', $digits);
}
function password_is_strong(string $pwd): array {
    $min = defined('PASSWORD_MIN_LENGTH') ? (int)PASSWORD_MIN_LENGTH : 10;
    if (strlen($pwd) < $min) return [false, "Password must be at least {$min} characters."];
    if (!preg_match('/[A-Z]/', $pwd)) return [false, "Include an uppercase letter."];
    if (!preg_match('/[a-z]/', $pwd)) return [false, "Include a lowercase letter."];
    if (!preg_match('/[0-9]/', $pwd)) return [false, "Include a number."];
    if (!preg_match('/[^A-Za-z0-9]/', $pwd)) return [false, "Include a special character."];
    return [true, ""];
}
function generate_token(int $length = 48): string {
    try { return bin2hex(random_bytes($length)); } catch (Throwable $e) { return bin2hex(openssl_random_pseudo_bytes($length)); }
}
function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES|ENT_SUBSTITUTE); }

/* ----- Load User ----- */
try {
    $user = $db->fetch("SELECT * FROM users WHERE user_id=? LIMIT 1", [$user_id]);
    if (!$user) {
        $errors[]='Account not found.';
        $user=['full_name'=>'','username'=>'','email'=>'','contact_number'=>'','created_at'=>null,'password'=>''];
    }
} catch (Throwable $e) {
    $errors[]='Failed to load account.';
    $user=['full_name'=>'','username'=>'','email'=>'','contact_number'=>'','created_at'=>null,'password'=>''];
}

/* ----- Pending email columns? ----- */
$users_has_pending_columns = false;
try {
    $col1 = $db->fetch("SHOW COLUMNS FROM users LIKE 'pending_email'");
    $col2 = $db->fetch("SHOW COLUMNS FROM users LIKE 'pending_email_token'");
    $col3 = $db->fetch("SHOW COLUMNS FROM users LIKE 'pending_email_requested_at'");
    if ($col1 && $col2) $users_has_pending_columns = true;
} catch (Throwable $e) {}

/* ----- Document States (pending = under review) ----- */
$docState = ['permit'=>'missing', 'id'=>'missing'];
if ($showVerificationUI) {
    try {
        $rows = $db->fetchAll("
            SELECT d.doc_type, LOWER(d.status) AS status
            FROM user_role_documents d
            JOIN user_roles ur ON d.user_role_id=ur.user_role_id
            JOIN roles r ON ur.role_id=r.role_id
            WHERE ur.user_id=?
        ", [$user_id]) ?: [];
        foreach ($rows as $r) {
            $t = strtolower($r['doc_type'] ?? '');
            $s = strtolower($r['status'] ?? '');
            if ($t === 'permit') {
                if     ($s === 'approved') $docState['permit'] = 'approved';
                elseif ($s === 'rejected') $docState['permit'] = 'rejected';
                elseif (!in_array($docState['permit'], ['approved','rejected'], true)) $docState['permit'] = 'pending';
            }
            if ($t === 'id') {
                if     ($s === 'approved') $docState['id'] = 'approved';
                elseif ($s === 'rejected') $docState['id'] = 'rejected';
                elseif (!in_array($docState['id'], ['approved','rejected'], true)) $docState['id'] = 'pending';
            }
        }
    } catch (Throwable $e) {
        error_log("settings: doc status fetch failed: ".$e->getMessage());
    }
} else {
    $docState['permit']='approved';
    $docState['id']='approved';
}

/* ---- Role-based UI: Avatar color and display role ---- */
$avatarGradientClass = $is_vendor
  ? 'from-green-500 to-emerald-600'   // vendor -> green circle
  : 'from-blue-500 to-indigo-600';    // non-vendor -> blue/indigo circle

// Choose a single display role to show in the badge instead of the static "Account" text
$displayRole = 'Account';
if (!empty($roleNames) && is_array($roleNames)) {
  if ($is_vendor) {
    $displayRole = 'Vendor';
  } elseif ($is_market_manager) {
    $displayRole = 'Market Manager';
  } elseif ($is_super_admin) {
    $displayRole = 'Super Admin';
  } elseif ($is_accountant) {
    $displayRole = 'Accountant';
  } elseif ($is_inspector) {
    $displayRole = 'Inspector';
  } else {
    $first = (string)($roleNames[0] ?? 'Account');
    $displayRole = ucfirst(str_replace('_', ' ', strtolower($first)));
  }
}

/* ---- NEW: Role-aware badge helper for Permit/ID statuses ---- */
function docBadgeRoleAware(string $state, bool $isVendor): string {
    switch (strtolower($state)) {
        case 'approved':
            // Vendor approved = GREEN, Others = BLUE
            return $isVendor
                ? 'bg-green-100 text-green-700'
                : 'bg-blue-100 text-blue-700';
        case 'pending':
            return 'bg-amber-100 text-amber-700';
        case 'rejected':
            return 'bg-red-100 text-red-700';
        case 'missing':
        default:
            return 'bg-gray-100 text-gray-700';
    }
}

/* ---- NEW: Per-document upload permission flags (lock if pending/approved) ---- */
$allowPermitUpload = in_array($docState['permit'], ['missing','rejected'], true);
$allowIdUpload     = in_array($docState['id'], ['missing','rejected'], true);
$anyUploadAllowed  = ($allowPermitUpload || $allowIdUpload);

/* -----------------------------------------------------------------
   Phone / Email change flows
   -----------------------------------------------------------------*/
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    /* Initiate phone change */
    if (isset($_POST['initiate_phone_change'])) {
        if (!csrf_validate_request()) {
            $errors[] = 'Invalid CSRF token.';
            $show_phone_panel = true;
            $open_profile_section = true;
        } else {
            $new_phone_raw = sanitize($_POST['new_phone'] ?? '');
            $new_phone = $new_phone_raw !== '' ? normalize_phone_e164($new_phone_raw, defined('DEFAULT_COUNTRY_CODE')?DEFAULT_COUNTRY_CODE:'+63') : null;
            if (empty($new_phone)) {
                $errors[] = 'Enter a valid phone number.';
                $show_phone_panel = true;
                $open_profile_section = true;
            } else {
                $digits = preg_replace('/\D+/', '', $new_phone);
                try {
                    $row = $db->fetch("
                        SELECT 1 FROM users
                        WHERE REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(contact_number, ' ', ''), '+', ''), '-', ''), '(', ''), ')', '') = ?
                          AND user_id != ?
                        LIMIT 1
                    ", [$digits, $user_id]);
                    if ($row) {
                        $errors[] = 'Phone number is already in use.';
                        $show_phone_panel = true;
                        $open_profile_section = true;
                    } else {
                        $db->query("CREATE TABLE IF NOT EXISTS phone_change_requests (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            user_id INT NOT NULL,
                            new_phone VARCHAR(64) NOT NULL,
                            code VARCHAR(32) NOT NULL,
                            requested_at DATETIME NOT NULL,
                            expires_at DATETIME NULL
                        )");

                        $phone_code = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);

                        $db->query(
                          "INSERT INTO phone_change_requests (user_id, new_phone, code, requested_at, expires_at)
                           VALUES (?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 15 MINUTE))",
                          [$user_id, $new_phone, $phone_code]
                        );

                        $smsOk = send_confirmation_code_sms($db, $user_id, $new_phone, $phone_code, 'phone_change');
                        if ($smsOk) {
                            $profile_success .= 'A confirmation code was sent to the new phone. Enter the code below to verify and apply the change.';
                            $show_phone_panel = true;
                            $show_phone_verify = true;
                            $open_profile_section = true;
                        } else {
                            $errors[] = 'Failed to send SMS to the new phone number. Please try again later.';
                            $show_phone_panel = true;
                            $open_profile_section = true;
                        }
                    }
                } catch (Throwable $e) {
                    error_log("initiate_phone_change failed: " . $e->getMessage());
                    $errors[] = 'Failed to initiate phone change.';
                    $show_phone_panel = true;
                    $open_profile_section = true;
                }
            }
        }
    }

    /* Verify phone code */
    if (isset($_POST['verify_phone_code'])) {
        if (!csrf_validate_request()) {
            $errors[] = 'Invalid CSRF token.';
            $show_phone_panel = true;
            $show_phone_verify = true;
            $open_profile_section = true;
        } else {
            $code = trim((string)($_POST['phone_code'] ?? ''));
            error_log("verify_phone attempt: user={$user_id} posted_code=[" . $code . "]");
            if ($code === '') {
                $errors[] = 'Enter the verification code.';
                $show_phone_panel = true;
                $show_phone_verify = true;
                $open_profile_section = true;
            } else {
                try {
                    $req = $db->fetch(
                        "SELECT *, TIMESTAMPDIFF(SECOND, NOW(), expires_at) AS expires_in
                         FROM phone_change_requests
                         WHERE user_id = ? AND code = ? AND expires_at >= NOW()
                         ORDER BY requested_at DESC LIMIT 1",
                        [$user_id, $code]
                    );
                    if (!$req) {
                        $padded = str_pad($code, 6, '0', STR_PAD_LEFT);
                        $req = $db->fetch(
                            "SELECT *, TIMESTAMPDIFF(SECOND, NOW(), expires_at) AS expires_in
                             FROM phone_change_requests
                             WHERE user_id = ? AND code = ? AND expires_at >= NOW()
                             ORDER BY requested_at DESC LIMIT 1",
                            [$user_id, $padded]
                        );
                        if ($req) error_log("verify_phone: matched using padded code");
                    }

                    if (!$req) {
                        $errors[] = 'Invalid or expired code.';
                        $show_phone_panel = true;
                        $show_phone_verify = true;
                        $open_profile_section = true;
                    } else {
                        $new_phone = $req['new_phone'];
                        $digits = preg_replace('/\D+/', '', $new_phone);
                        $row = $db->fetch("
                            SELECT 1 FROM users
                            WHERE REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(contact_number, ' ', ''), '+', ''), '-', ''), '(', ''), ')', '') = ?
                              AND user_id != ?
                            LIMIT 1
                        ", [$digits, $user_id]);
                        if ($row) {
                            $errors[] = 'Phone number is already in use.';
                            $show_phone_panel = true;
                            $show_phone_verify = true;
                            $open_profile_section = true;
                        } else {
                            $db->query("UPDATE users SET contact_number = ?, updated_at = NOW() WHERE user_id = ?", [$new_phone, $user_id]);
                            $db->query("DELETE FROM phone_change_requests WHERE id = ?", [$req['id']]);
                            $profile_success .= 'Phone number updated successfully.';
                            logAudit($db, $user_id, 'Phone changed via verification', 'users', $user_id, null, $new_phone);
                            $user = $db->fetch("SELECT * FROM users WHERE user_id=? LIMIT 1", [$user_id]);
                        }
                    }
                } catch (Throwable $e) {
                    error_log("verify_phone_code failed: " . $e->getMessage());
                    $errors[] = 'Failed to verify phone code.';
                    $show_phone_panel = true;
                    $show_phone_verify = true;
                    $open_profile_section = true;
                }
            }
        }
    }

    /* Initiate email change */
    if (isset($_POST['initiate_email_change'])) {
        if (!csrf_validate_request()) {
            $errors[] = 'Invalid CSRF token.';
            $show_email_panel = true;
            $open_profile_section = true;
        } else {
            $new_email = sanitize($_POST['new_email'] ?? '');
            if ($new_email === '' || !filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
                $errors[] = 'Enter a valid email address.';
                $show_email_panel = true;
                $open_profile_section = true;
            } else {
                try {
                    $exists = $db->fetch("SELECT user_id FROM users WHERE email = ? AND user_id != ? LIMIT 1", [$new_email, $user_id]);
                    if ($exists) {
                        $errors[] = 'Email already in use.';
                        $show_email_panel = true;
                        $open_profile_section = true;
                    } else {
                        $email_code = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);

                        $db->query("CREATE TABLE IF NOT EXISTS email_change_requests (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            user_id INT,
                            new_email VARCHAR(255),
                            code VARCHAR(32),
                            requested_at DATETIME NOT NULL,
                            expires_at DATETIME NULL
                        )");

                        $db->query(
                          "INSERT INTO email_change_requests (user_id, new_email, code, requested_at, expires_at)
                           VALUES (?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 15 MINUTE))",
                          [$user_id, $new_email, $email_code]
                        );

                        $current_phone = $user['contact_number'] ?? '';
                        if (!empty($current_phone)) {
                            $smsOk = send_confirmation_code_sms($db, $user_id, $current_phone, $email_code, 'email_change');
                            if ($smsOk) {
                                $email_success = 'A confirmation code was sent via SMS to your current phone. Enter it below to confirm the new email.';
                                $show_email_panel = true;
                                $show_email_verify = true;
                                $open_profile_section = true;
                            } else {
                                send_email_change_confirmation($db, $user_id, $new_email, $email_code);
                                $email_success = 'SMS delivery failed; a confirmation link/code was sent to the new email instead.';
                                $show_email_panel = true;
                                $open_profile_section = true;
                            }
                        } else {
                            send_email_change_confirmation($db, $user_id, $new_email, $email_code);
                            $email_success = 'Confirmation link/code sent to the new email address.';
                            $show_email_panel = true;
                            $open_profile_section = true;
                        }
                    }
                } catch (Throwable $e) {
                    error_log("initiate_email_change failed: " . $e->getMessage());
                    $errors[] = 'Failed to initiate email change.';
                    $show_email_panel = true;
                    $open_profile_section = true;
                }
            }
        }
    }

    /* Verify email code */
    if (isset($_POST['verify_email_code'])) {
        if (!csrf_validate_request()) {
            $errors[] = 'Invalid CSRF token.';
            $show_email_panel = true;
            $show_email_verify = true;
            $open_profile_section = true;
        } else {
            $code = trim((string)($_POST['email_code'] ?? ''));
            error_log("verify_email attempt: user={$user_id} posted_code=[" . $code . "]");
            if ($code === '') {
                $errors[] = 'Enter the verification code.';
                $show_email_panel = true;
                $show_email_verify = true;
                $open_profile_section = true;
            } else {
                try {
                    $req = $db->fetch(
                        "SELECT *, TIMESTAMPDIFF(SECOND, NOW(), expires_at) AS expires_in
                         FROM email_change_requests
                         WHERE user_id = ? AND code = ? AND expires_at >= NOW()
                         ORDER BY requested_at DESC LIMIT 1",
                        [$user_id, $code]
                    );
                    if (!$req) {
                        $padded = str_pad($code, 6, '0', STR_PAD_LEFT);
                        $req = $db->fetch(
                            "SELECT *, TIMESTAMPDIFF(SECOND, NOW(), expires_at) AS expires_in
                             FROM email_change_requests
                             WHERE user_id = ? AND code = ? AND expires_at >= NOW()
                             ORDER BY requested_at DESC LIMIT 1",
                            [$user_id, $padded]
                        );
                        if ($req) error_log("verify_email: matched using padded code");
                    }

                    if (!$req) {
                        $errors[] = 'Invalid or expired code.';
                        $show_email_panel = true;
                        $show_email_verify = true;
                        $open_profile_section = true;
                    } else {
                        $new_email = $req['new_email'];
                        $exists = $db->fetch("SELECT user_id FROM users WHERE email = ? AND user_id != ? LIMIT 1", [$new_email, $user_id]);
                        if ($exists) {
                            $errors[] = 'Email already in use.';
                            $show_email_panel = true;
                            $show_email_verify = true;
                            $open_profile_section = true;
                        } else {
                            $db->query("UPDATE users SET email = ?, updated_at = NOW() WHERE user_id = ?", [$new_email, $user_id]);
                            $db->query("DELETE FROM email_change_requests WHERE id = ?", [$req['id']]);
                            $email_success = 'Email updated successfully.';
                            logAudit($db, $user_id, 'Email changed via verification', 'users', $user_id, null, $new_email);
                            $user = $db->fetch("SELECT * FROM users WHERE user_id=? LIMIT 1", [$user_id]);
                        }
                    }
                } catch (Throwable $e) {
                    error_log("verify_email_code failed: " . $e->getMessage());
                    $errors[] = 'Failed to verify email code.';
                    $show_email_panel = true;
                    $show_email_verify = true;
                    $open_profile_section = true;
                }
            }
        }
    }
}

/* ----- PROFILE UPDATE ----- */
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['update_profile'])) {
    if (!csrf_validate_request()) {
        $errors[]='Invalid CSRF token.';
    } else {
        $full_name   = sanitize($_POST['full_name'] ?? '');
        $email_input = sanitize($_POST['email'] ?? '');
        $contact_raw = sanitize($_POST['contact_number'] ?? '');

        if ($full_name==='') $errors[]='Full name is required.';
        if ($email_input!=='' && !filter_var($email_input,FILTER_VALIDATE_EMAIL)) $errors[]='Invalid email address.';

        $email_changed=false;
        if ($email_input!=='' && $email_input!==($user['email']??'') && empty($errors)) {
            try {
                $exists=$db->fetch("SELECT user_id FROM users WHERE email=? AND user_id!=? LIMIT 1",[$email_input,$user_id]);
                if ($exists) $errors[]='Email already in use.'; else $email_changed=true;
            } catch(Throwable $e){ $errors[]='Email uniqueness check failed.'; }
        }

        $normalized_contact=null;
        if ($contact_raw!=='') {
            $normalized_contact=normalize_phone_e164($contact_raw, defined('DEFAULT_COUNTRY_CODE')?DEFAULT_COUNTRY_CODE:'+63');
            if ($normalized_contact===null) $errors[]='Contact number could not be normalized.';
        }

        if (empty($errors)) {
            try {
                $db->query("UPDATE users SET full_name=?, contact_number=?, updated_at=NOW() WHERE user_id=?",
                    [$full_name, $normalized_contact ?? $contact_raw, $user_id]);

                $_SESSION['full_name']=$full_name;
                $changed=[];
                if (($user['full_name']??'') !== $full_name) $changed[]='Full name';
                if (($user['contact_number']??'') !== ($normalized_contact ?? $contact_raw)) $changed[]='Contact number';

                if ($email_changed) {
                    $token=generate_token(24);
                    if ($users_has_pending_columns) {
                        try {
                            $db->query("UPDATE users SET pending_email=?, pending_email_token=?, pending_email_requested_at=NOW() WHERE user_id=?",
                                [$email_input,$token,$user_id]);
                            send_email_change_confirmation($db,$user_id,$email_input,$token);
                            $email_success='Confirmation link sent to new email.';
                            $changed[]='Email (pending)';
                        } catch(Throwable $e){
                            $db->query("UPDATE users SET email=?, updated_at=NOW() WHERE user_id=?",[$email_input,$user_id]);
                            $email_success='Email changed immediately.';
                            $changed[]='Email';
                        }
                    } else {
                        try {
                            $db->query("CREATE TABLE IF NOT EXISTS email_change_requests (
                                id INT AUTO_INCREMENT PRIMARY KEY,
                                user_id INT,
                                new_email VARCHAR(255),
                                token VARCHAR(128),
                                requested_at DATETIME NOT NULL,
                                expires_at DATETIME NULL
                            )");
                            $db->query("INSERT INTO email_change_requests (user_id,new_email,token,requested_at,expires_at) VALUES (?,?,?,NOW(),DATE_ADD(NOW(), INTERVAL 24 HOUR))",
                                [$user_id,$email_input,$token]);
                            send_email_change_confirmation($db,$user_id,$email_input,$token);
                            $email_success='Confirmation link sent to new email.';
                            $changed[]='Email (pending)';
                        } catch(Throwable $e){
                            $db->query("UPDATE users SET email=?, updated_at=NOW() WHERE user_id=?",[$email_input,$user_id]);
                            $email_success='Email changed immediately.';
                            $changed[]='Email';
                        }
                    }
                }

                $user=$db->fetch("SELECT * FROM users WHERE user_id=? LIMIT 1",[$user_id]);
                $profile_success = $changed ? ('Profile updated: '.implode(', ',$changed)) : 'Profile updated.';
                logAudit($db,$user_id,'Profile Updated','users',$user_id,null,json_encode(['changed'=>$changed]));
            } catch (Throwable $e){
                $errors[]='Failed to update profile.';
            }
        }
    }
}

/* ----- PASSWORD CHANGE ----- */
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['change_password'])) {
    if (!csrf_validate_request()) {
        $errors[]='Invalid CSRF token.';
    } else {
        $current=$_POST['current_password']??'';
        $new=$_POST['new_password']??'';
        $confirm=$_POST['confirm_password']??'';
        if ($current===''||$new===''||$confirm==='') $errors[]='All password fields are required.';
        elseif ($new!==$confirm) $errors[]='New passwords do not match.';
        else {
            [$ok,$msg]=password_is_strong($new);
            if(!$ok) $errors[]=$msg;
            elseif (empty($user['password']) || !password_verify($current,$user['password'])) $errors[]='Current password incorrect.';
            else {
                try {
                    $hash=password_hash($new,PASSWORD_DEFAULT);
                    $db->query("UPDATE users SET password=?, updated_at=NOW() WHERE user_id=?",[$hash,$user_id]);
                    session_regenerate_id(true);
                    try { $db->query("DELETE FROM sessions WHERE user_id=? AND session_id!=?",[$user_id,session_id()]); } catch(Throwable $e){}
                    if(function_exists('createNotification')){
                        createNotification($db,$user_id,'Password Changed','Password changed successfully.','info','security',$user_id,'users');
                    }
                    logAudit($db,$user_id,'Password Changed','users',$user_id,null,null);
                    $password_success='Password changed successfully.';
                } catch(Throwable $e){
                    $errors[]='Failed to change password.';
                }
            }
        }
    }
}

/* ----- Role helper functions ----- */
function ensure_vendor_user_role($db, int $user_id, bool $create = false): ?int {
    $role = $db->fetch("
        SELECT ur.user_role_id
        FROM user_roles ur
        JOIN roles r ON ur.role_id=r.role_id
        WHERE ur.user_id=? AND LOWER(r.name)='vendor' LIMIT 1
    ", [$user_id]);
    if ($role && isset($role['user_role_id'])) return (int)$role['user_role_id'];
    if (!$create) return null;
    $vendorRole = $db->fetch("SELECT role_id FROM roles WHERE name='vendor' LIMIT 1");
    if ($vendorRole && isset($vendorRole['role_id'])) {
        $db->query("INSERT INTO user_roles (user_id,role_id,status,assigned_at) VALUES (?,?, 'pending', NOW())",
            [$user_id,(int)$vendorRole['role_id']]);
        return (int)$db->lastInsertId();
    }
    return null;
}
function get_user_role_id_by_name($db, int $user_id, string $role_name): ?int {
    $role_name_l = strtolower(trim($role_name));
    if ($role_name_l === '') return null;
    try {
        $r = $db->fetch("
            SELECT ur.user_role_id
            FROM user_roles ur
            JOIN roles r ON ur.role_id=r.role_id
            WHERE ur.user_id = ? AND LOWER(r.name) = ?
            LIMIT 1
        ", [$user_id, $role_name_l]);
        if ($r && !empty($r['user_role_id'])) return (int)$r['user_role_id'];
    } catch (Throwable $e) {
        error_log("get_user_role_id_by_name error: " . $e->getMessage());
    }
    return null;
}

/* ----- Document Upload Handler (with new pending lock) ----- */
if ($showVerificationUI && $_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['upload_documents'])) {
    if (!csrf_validate_request()) {
        $errors[]='Invalid CSRF token.';
    } else {
        // Apply per-document upload permission
        $hasPermit = $allowPermitUpload && !empty($_FILES['permit_file']) && $_FILES['permit_file']['error'] === UPLOAD_ERR_OK;
        $hasId     = $allowIdUpload     && !empty($_FILES['id_file'])     && $_FILES['id_file']['error'] === UPLOAD_ERR_OK;

        if (!$hasPermit && !$hasId) {
            $errors[] = 'No eligible documents selected (pending/approved documents are locked).';
        } else {
            $allowedPermit = ['application/pdf'=>'pdf','image/jpeg'=>'jpg','image/png'=>'png'];
            $allowedId     = ['image/jpeg'=>'jpg','image/png'=>'png'];
            $max = 5*1024*1024;

            $user_role_id = null;
            if ($is_market_manager) $user_role_id = get_user_role_id_by_name($db, $user_id, 'market_manager');
            if (!$user_role_id && $is_vendor)     $user_role_id = get_user_role_id_by_name($db, $user_id, 'vendor');
            if (!$user_role_id && $is_inspector) {
                $user_role_id = get_user_role_id_by_name($db, $user_id, 'inspector');
                if (!$user_role_id) {
                    try {
                        $inspectorRole = $db->fetch("SELECT role_id FROM roles WHERE LOWER(name) = 'inspector' LIMIT 1");
                        if ($inspectorRole && !empty($inspectorRole['role_id'])) {
                            $db->query("INSERT INTO user_roles (user_id, role_id, status, assigned_at) VALUES (?,?, 'pending', NOW())",
                                [$user_id, (int)$inspectorRole['role_id']]);
                            $user_role_id = (int)$db->lastInsertId();
                        }
                    } catch (Throwable $e) {
                        error_log("settings: failed to create inspector user_role for user {$user_id}: " . $e->getMessage());
                        $user_role_id = null;
                    }
                }
            }

            if (!$user_role_id) {
                $errors[] = 'No appropriate role found to attach documents.';
            } else {
                $save_and_insert = function($file, $docType, $allowed, $user_role_id) use ($db, $user_id, $max, $docState) {
                    // Server-side lock double check
                    if (!in_array($docState[$docType] ?? 'missing', ['missing','rejected'], true)) {
                        return ['error'=> ucfirst($docType) . ' upload locked (already submitted).'];
                    }
                    if (empty($file) || $file['error'] !== UPLOAD_ERR_OK) return ['error'=>'No file or upload error'];
                    if ($file['size'] > $max) return ['error'=>'File exceeds 5MB'];
                    try {
                        $fi = new finfo(FILEINFO_MIME_TYPE);
                        $mime = $fi->file($file['tmp_name']);
                    } catch (Throwable $e) { $mime = null; }
                    if (!$mime || !isset($allowed[$mime])) return ['error'=>'Invalid file type'];
                    $ext = $allowed[$mime];
                    $dir = __DIR__.'/uploads/user_documents/'.$user_id.'/';
                    if (!is_dir($dir) && !@mkdir($dir,0755,true)) return ['error'=>'Failed to create upload directory'];
                    $name = time().'_'.bin2hex(random_bytes(6)).'.'.$ext;
                    $full = $dir.$name; $rel = 'uploads/user_documents/'.$user_id.'/'.$name;
                    if (!@move_uploaded_file($file['tmp_name'],$full) && !@rename($file['tmp_name'],$full) && !@copy($file['tmp_name'],$full)) {
                        return ['error'=>'Failed to store file'];
                    }
                    try {
                        $db->query("INSERT INTO user_documents (user_id,file_path,file_name,file_type,uploaded_at)
                                    VALUES (?,?,?,?,NOW())", [$user_id,$rel,$name,$docType]);
                    } catch (Throwable $e) {
                        error_log("user_documents insert fail: ".$e->getMessage());
                    }
                    try {
                        $db->query("INSERT INTO user_role_documents
                            (user_role_id,doc_type,file_path,original_filename,status,admin_notes,uploaded_at)
                            VALUES (?,?,?,?, 'pending', ?, NOW())",
                            [$user_role_id, $docType, $rel, $file['name'], "[Uploaded at ".date('Y-m-d H:i:s')."]"]);
                    } catch (Throwable $e) {
                        return ['error'=>'Database insert failed: '.$e->getMessage()];
                    }
                    return ['success'=>true];
                };

                if ($hasPermit) {
                    $res = $save_and_insert($_FILES['permit_file'],'permit',$allowedPermit,$user_role_id);
                    if (!empty($res['error'])) $errors[] = 'Permit: '.$res['error'];
                    elseif (!empty($res['success'])) {
                        $doc_success .= 'Permit uploaded (pending review). ';
                        $docState['permit'] = 'pending';
                        $allowPermitUpload = false;
                    }
                }
                if ($hasId) {
                    $res = $save_and_insert($_FILES['id_file'],'id',$allowedId,$user_role_id);
                    if (!empty($res['error'])) $errors[] = 'ID: '.$res['error'];
                    elseif (!empty($res['success'])) {
                        $doc_success .= 'ID uploaded (pending review). ';
                        $docState['id'] = 'pending';
                        $allowIdUpload = false;
                    }
                }

                if (empty($errors)) {
                    logAudit($db,$user_id,'Documents Uploaded','user_role_documents',null,null,json_encode(['user_role_id'=>$user_role_id]));
                }
            }
        }
    }
}

/* ----- Audit view ----- */
logAudit($db,$user_id,'View Settings','users',$user_id,null,null);

/* ----- View ----- */
require_once 'includes/header.php';
refreshSessionRoles($db);
$roleNames = $_SESSION['roles'] ?? [];
if (shouldUseAdminSidebar($roleNames)) {
    require_once 'includes/admin_sidebar.php';
} else {
    require_once 'includes/vendor_sidebar.php';
}
?>
<section class="max-w-7xl mx-auto p-6">

  <!-- Header Card -->
  <div class="bg-white rounded-xl shadow p-6 mb-6 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
    <div class="flex items-center gap-5">
      <!-- Avatar circle: GREEN if vendor, else BLUE -->
      <div class="w-20 h-20 rounded-full bg-gradient-to-br <?php echo $avatarGradientClass; ?> flex items-center justify-center text-white text-2xl font-bold">
        <?php echo strtoupper(substr(($user['full_name'] ?? $user['username'] ?? ''),0,2)); ?>
      </div>
      <div>
        <h1 class="text-xl font-bold text-gray-800"><?php echo h($user['full_name'] ?? ''); ?></h1>
        <p class="text-sm text-gray-600">@<?php echo h($user['username'] ?? ''); ?></p>

        <div class="mt-2 flex flex-wrap gap-2">
          <!-- Role badge (replaces static "Account") -->
          <span class="px-2 py-1 <?php echo $is_vendor ? 'bg-green-100 text-green-700' : 'bg-blue-100 text-blue-700'; ?> rounded text-xs font-medium">
            <?php echo h($displayRole); ?>
          </span>

          <?php if ($showVerificationUI): ?>
            <!-- Permit/ID status badges, role-aware "approved" color -->
            <span class="px-2 py-1 text-xs font-medium rounded <?php echo docBadgeRoleAware($docState['permit'], $is_vendor); ?>">
              Permit: <?php echo ucfirst($docState['permit']); ?>
            </span>
            <span class="px-2 py-1 text-xs font-medium rounded <?php echo docBadgeRoleAware($docState['id'], $is_vendor); ?>">
              ID: <?php echo ucfirst($docState['id']); ?>
            </span>
          <?php else: ?>
            <span class="px-2 py-1 bg-green-100 text-green-700 rounded text-xs font-medium">Verification Exempt</span>
          <?php endif; ?>
        </div>

        <div class="mt-3 text-xs text-gray-500">
          Member since:
          <span class="font-semibold text-gray-700">
            <?php echo !empty($user['created_at']) ? date('M j, Y', strtotime($user['created_at'])) : '-'; ?>
          </span>
        </div>
      </div>
    </div>

    <div class="flex flex-col sm:flex-row gap-3">
      <button type="button" class="px-4 py-2 bg-blue-600 text-white rounded text-sm font-medium"
              onclick="toggleSection('profileSection')">Edit Profile</button>
      <button type="button" class="px-4 py-2 bg-indigo-600 text-white rounded text-sm font-medium"
              onclick="toggleSection('passwordSection')">Change Password</button>
      <?php if ($showVerificationUI): ?>
        <button type="button" class="px-4 py-2 bg-amber-600 text-white rounded text-sm font-medium"
                onclick="toggleSection('documentsSection')">Document Verification</button>
      <?php endif; ?>
      <?php if ($show_system_settings): ?>
        <button type="button" class="px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-800 rounded text-sm font-medium"
                onclick="toggleSection('systemSection')">System Overview</button>
      <?php endif; ?>
    </div>
  </div>

  <!-- Feedback Messages -->
  <?php if ($errors): ?>
    <div class="mb-4 bg-red-50 border border-red-200 text-red-700 rounded p-4 space-y-1">
      <?php foreach ($errors as $e) echo '<div>'.h($e).'</div>'; ?>
    </div>
  <?php endif; ?>
  <?php if ($profile_success): ?>
    <div class="mb-4 bg-green-50 border border-green-200 text-green-700 rounded p-4"><?php echo h($profile_success); ?></div>
  <?php endif; ?>
  <?php if ($email_success): ?>
    <div class="mb-4 bg-blue-50 border border-blue-200 text-blue-700 rounded p-4"><?php echo h($email_success); ?></div>
  <?php endif; ?>
  <?php if ($password_success): ?>
    <div class="mb-4 bg-green-50 border border-green-200 text-green-700 rounded p-4"><?php echo h($password_success); ?></div>
  <?php endif; ?>
  <?php if ($doc_success): ?>
    <div class="mb-4 bg-amber-50 border border-amber-200 text-amber-800 rounded p-4"><?php echo h($doc_success); ?></div>
  <?php endif; ?>

  <!-- Profile Section -->
  <div id="profileSection" class="hidden mb-8">
    <div class="bg-white rounded-xl shadow p-6">
      <h2 class="text-lg font-semibold mb-4">Edit Profile</h2>

      <form method="POST" class="mb-6">
        <?php echo csrf_field(); ?>
        <input type="hidden" name="update_profile" value="1">
        <div class="grid md:grid-cols-2 gap-4">
          <div>
            <label class="block text-sm font-medium mb-1">Full Name *</label>
            <input type="text" name="full_name" required value="<?php echo h($user['full_name'] ?? ''); ?>"
                   class="w-full border rounded px-3 py-2 focus:ring-2 focus:ring-blue-500">
          </div>

          <div>
            <label class="block text-sm font-medium mb-1">Contact Number (current)</label>
            <div class="flex items-center gap-3">
              <input type="text" disabled value="<?php echo h($user['contact_number'] ?? ''); ?>" class="w-full border rounded px-3 py-2 bg-gray-100">
              <button type="button" id="startPhoneChangeBtn" class="px-3 py-2 bg-yellow-500 text-white rounded text-sm">Change</button>
            </div>
          </div>

          <div class="md:col-span-2">
            <label class="block text-sm font-medium mb-1">Email (current)</label>
            <div class="flex items-center gap-3">
              <input type="text" disabled value="<?php echo h($user['email'] ?? ''); ?>" class="w-full border rounded px-3 py-2 bg-gray-100">
              <button type="button" id="startEmailChangeBtn" class="px-3 py-2 bg-yellow-500 text-white rounded text-sm">Change</button>
            </div>
          </div>
        </div>

        <div class="mt-4">
          <button class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded">Save Basic</button>
        </div>
      </form>

      <!-- Phone change panel -->
      <div id="phoneChangePanel" class="hidden border rounded p-4 mb-4">
        <h3 class="font-medium mb-2">Change Phone Number</h3>
        <div class="mb-3 text-sm text-gray-600">Enter the new phone number. A verification code will be sent to the new number.</div>

        <div class="grid md:grid-cols-3 gap-2 items-end">
          <div>
            <label class="text-xs mb-1 block">New Phone</label>
            <input id="newPhoneInput" type="text" name="new_phone" class="w-full border rounded px-3 py-2 text-sm" placeholder="+639...">
          </div>
          <div>
            <label class="text-xs mb-1 block">Availability</label>
            <span id="phoneAvailability" class="text-sm"></span>
          </div>
          <div>
            <button id="sendPhoneCodeBtn" class="px-3 py-2 bg-amber-600 text-white rounded text-sm">Send Code</button>
          </div>
        </div>

        <form id="verifyPhoneForm" method="POST" class="mt-3 hidden">
          <?php echo csrf_field(); ?>
          <input type="hidden" name="verify_phone_code" value="1">
          <label class="text-xs mb-1 block">Enter Code</label>
          <div class="flex gap-2">
            <input type="text" name="phone_code" maxlength="6" class="border rounded px-3 py-2 w-32">
            <button class="px-3 py-2 bg-green-600 text-white rounded">Verify Code</button>
          </div>
        </form>
      </div>

      <!-- Email change panel -->
      <div id="emailChangePanel" class="hidden border rounded p-4">
        <h3 class="font-medium mb-2">Change Email</h3>
        <div class="mb-3 text-sm text-gray-600">Enter the new email. A verification code will be sent to your current phone (if available) else a link/code to the new email.</div>

        <div class="grid md:grid-cols-3 gap-2 items-end">
          <div>
            <label class="text-xs mb-1 block">New Email</label>
            <input id="newEmailInput" type="email" name="new_email" class="w-full border rounded px-3 py-2 text-sm" placeholder="you@example.com">
          </div>
          <div>
            <label class="text-xs mb-1 block">Availability</label>
            <span id="emailAvailability" class="text-sm"></span>
          </div>
          <div>
            <button id="sendEmailCodeBtn" class="px-3 py-2 bg-amber-600 text-white rounded text-sm">Send Code / Link</button>
          </div>
        </div>

        <form id="verifyEmailForm" method="POST" class="mt-3 hidden">
          <?php echo csrf_field(); ?>
          <input type="hidden" name="verify_email_code" value="1">
          <label class="text-xs mb-1 block">Enter Code</label>
          <div class="flex gap-2">
            <input type="text" name="email_code" maxlength="6" class="border rounded px-3 py-2 w-32">
            <button class="px-3 py-2 bg-green-600 text-white rounded">Verify Code</button>
          </div>
        </form>
      </div>

    </div>
  </div>

  <!-- Password Section -->
  <div id="passwordSection" class="hidden mb-8">
    <div class="bg-white rounded-xl shadow p-6">
      <h2 class="text-lg font-semibold mb-4">Change Password</h2>
      <form method="POST">
        <?php echo csrf_field(); ?>
        <input type="hidden" name="change_password" value="1">
        <div class="grid md:grid-cols-3 gap-4">
          <div>
            <label class="block text-sm font-medium mb-1">Current Password *</label>
            <input type="password" name="current_password" required class="w-full border rounded px-3 py-2">
          </div>
          <div>
            <label class="block text-sm font-medium mb-1">New Password *</label>
            <input type="password" name="new_password" required minlength="<?php echo defined('PASSWORD_MIN_LENGTH')?PASSWORD_MIN_LENGTH:10;?>"
                   class="w-full border rounded px-3 py-2">
            <p class="text-xs text-gray-500 mt-1">Include upper, lower, number & symbol.</p>
          </div>
          <div>
            <label class="block text-sm font-medium mb-1">Confirm New Password *</label>
            <input type="password" name="confirm_password" required minlength="<?php echo defined('PASSWORD_MIN_LENGTH')?PASSWORD_MIN_LENGTH:10;?>"
                   class="w-full border rounded px-3 py-2">
          </div>
        </div>
        <div class="mt-4">
          <button class="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded">Change Password</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Documents Section -->
  <?php if ($showVerificationUI): ?>
  <div id="documentsSection" class="hidden mb-8">
    <div class="bg-white rounded-xl shadow p-6 space-y-8">
      <h2 class="text-lg font-semibold mb-2">Document Verification</h2>
      <div class="border rounded p-4">
        <h3 class="font-medium mb-2">Status</h3>
        <!-- Permit Status -->
        <?php if ($docState['permit']==='approved'): ?>
          <p class="text-sm <?php echo $is_vendor ? 'text-green-700' : 'text-blue-700'; ?> mb-2">Permit verified.</p>
        <?php elseif ($docState['permit']==='pending'): ?>
          <p class="text-sm text-amber-700 mb-2">Permit pending review. Upload locked.</p>
        <?php elseif ($docState['permit']==='rejected'): ?>
          <p class="text-sm text-red-700 mb-2">Permit rejected. Please upload a corrected document.</p>
        <?php else: ?>
          <p class="text-sm text-gray-700 mb-2">Permit missing. Please upload it.</p>
        <?php endif; ?>

        <!-- ID Status -->
        <?php if ($docState['id']==='approved'): ?>
          <p class="text-sm <?php echo $is_vendor ? 'text-green-700' : 'text-blue-700'; ?> mb-2">ID verified.</p>
        <?php elseif ($docState['id']==='pending'): ?>
          <p class="text-sm text-amber-700 mb-2">ID pending review. Upload locked.</p>
        <?php elseif ($docState['id']==='rejected'): ?>
          <p class="text-sm text-red-700 mb-2">ID rejected. Please upload a clearer valid image.</p>
        <?php else: ?>
          <p class="text-sm text-gray-700 mb-2">ID missing. Please upload it.</p>
        <?php endif; ?>

        <hr class="my-4">

        <h3 class="font-medium mb-2">Upload</h3>
        <?php if ($anyUploadAllowed): ?>
          <form method="POST" enctype="multipart/form-data" class="space-y-4">
            <?php echo csrf_field(); ?>
            <input type="hidden" name="upload_documents" value="1">

            <?php if ($allowPermitUpload): ?>
              <div>
                <label class="text-xs font-medium block mb-1">Permit (PDF/JPG/PNG, ≤5MB)</label>
                <input type="file" name="permit_file" accept=".pdf,image/jpeg,image/png"
                       class="w-full border rounded px-3 py-2 text-sm">
              </div>
            <?php else: ?>
              <div class="text-xs text-gray-500">Permit upload locked (<?php echo h($docState['permit']); ?>).</div>
            <?php endif; ?>

            <?php if ($allowIdUpload): ?>
              <div>
                <label class="text-xs font-medium block mb-1">Government ID (JPG/PNG, ≤5MB)</label>
                <input type="file" name="id_file" accept="image/jpeg,image/png"
                       class="w-full border rounded px-3 py-2 text-sm">
              </div>
            <?php else: ?>
              <div class="text-xs text-gray-500">ID upload locked (<?php echo h($docState['id']); ?>).</div>
            <?php endif; ?>

            <button class="bg-amber-600 hover:bg-amber-700 text-white px-4 py-2 rounded text-sm">Submit Documents</button>
          </form>
        <?php else: ?>
          <p class="text-sm text-green-700">All documents already submitted and awaiting review or approved. No uploads currently allowed.</p>
        <?php endif; ?>
      </div>
    </div>
  </div>
  <?php endif; ?>

  <!-- System Section -->
  <?php if ($show_system_settings): ?>
    <div id="systemSection" class="hidden mb-8">
      <div class="bg-white rounded-xl shadow p-6">
        <h2 class="text-lg font-semibold mb-4">System Overview</h2>
        <p class="text-sm text-gray-600">
          (Add system metrics or summaries here. Hidden until toggled.)
        </p>
      </div>
    </div>
  <?php endif; ?>

</section>

<script>
/* Section toggling */
if (typeof window.toggleSection !== 'function') {
  window.toggleSection = function(id) {
    try {
      var target = document.getElementById(id);
      if (!target) return;
      var ids = ['profileSection','passwordSection','documentsSection','systemSection'];
      ids.forEach(function(secId){
        var el = document.getElementById(secId);
        if (el && !el.classList.contains('hidden')) el.classList.add('hidden');
      });
      target.classList.remove('hidden');
      try { target.scrollIntoView({behavior:'smooth', block:'start'}); } catch(e){}
    } catch(e){}
  };
}

/* Bind change panels and availability checks */
const startPhoneChangeBtn = document.getElementById('startPhoneChangeBtn');
const phonePanel = document.getElementById('phoneChangePanel');
const sendPhoneCodeBtn = document.getElementById('sendPhoneCodeBtn');
const verifyPhoneForm = document.getElementById('verifyPhoneForm');
const newPhoneInput = document.getElementById('newPhoneInput');
const phoneAvailability = document.getElementById('phoneAvailability');

const startEmailChangeBtn = document.getElementById('startEmailChangeBtn');
const emailPanel = document.getElementById('emailChangePanel');
const sendEmailCodeBtn = document.getElementById('sendEmailCodeBtn');
const verifyEmailForm = document.getElementById('verifyEmailForm');
const newEmailInput = document.getElementById('newEmailInput');
const emailAvailability = document.getElementById('emailAvailability');

if (startPhoneChangeBtn) {
  startPhoneChangeBtn.addEventListener('click', ()=> {
    if (phonePanel) {
      phonePanel.classList.toggle('hidden');
      const vf = document.getElementById('verifyPhoneForm');
      if (vf) vf.classList.add('hidden');
    }
    if (newPhoneInput && !phonePanel.classList.contains('hidden')) newPhoneInput.focus();
  });
}
if (startEmailChangeBtn) {
  startEmailChangeBtn.addEventListener('click', ()=> {
    if (emailPanel) {
      emailPanel.classList.toggle('hidden');
      const vf = document.getElementById('verifyEmailForm');
      if (vf) vf.classList.add('hidden');
    }
    if (newEmailInput && !emailPanel.classList.contains('hidden')) newEmailInput.focus();
  });
}

const ENDPOINT = 'check_availability.php';
function debounce(fn, wait=400){
  let t = null;
  return (...args) => { if (t) clearTimeout(t); t = setTimeout(()=> fn(...args), wait); };
}
async function checkAvailability(field, value, el){
  if (!el) return;
  if (!value || value.trim() === '') { el.textContent = ''; el.style.color = ''; return; }
  el.textContent = 'Checking…';
  el.style.color = '#6b7280';
  try {
    const url = `${ENDPOINT}?field=${encodeURIComponent(field)}&value=${encodeURIComponent(value)}`;
    const res = await fetch(url, { method: 'GET', credentials: 'same-origin' });
    if (!res.ok) { el.textContent='Error'; el.style.color = ''; return; }
    const js = await res.json();
    if (!js || !js.ok) { el.textContent='Error'; el.style.color = ''; return; }
    el.textContent = js.available ? 'Available' : 'Taken';
    el.style.color = js.available ? '#16a34a' : '#dc2626';
  } catch (e) {
    console.error('availability check failed', e);
    el.textContent = 'Error';
    el.style.color = '';
  }
}
let debPhone = null, debEmail = null;
if (newPhoneInput && phoneAvailability) {
  debPhone = debounce(()=> checkAvailability('contact_number', newPhoneInput.value, phoneAvailability), 500);
  newPhoneInput.addEventListener('input', ()=> {
    phoneAvailability.textContent = '';
    debPhone();
  });
}
if (newEmailInput && emailAvailability) {
  debEmail = debounce(()=> checkAvailability('email', newEmailInput.value, emailAvailability), 500);
  newEmailInput.addEventListener('input', ()=> {
    emailAvailability.textContent = '';
    debEmail();
  });
}

/* Submit helpers for initiating phone/email change */
function postForm(params){
  const f = document.createElement('form');
  f.method = 'POST';
  f.style.display = 'none';
  document.body.appendChild(f);
  for (const k in params) {
    const i = document.createElement('input');
    i.type = 'hidden';
    i.name = k;
    i.value = params[k];
    f.appendChild(i);
  }
  let csrfEl = document.querySelector('input[type="hidden"][name*="csrf"]');
  if (!csrfEl) {
    csrfEl = document.querySelector('meta[name="csrf-token"]');
    if (csrfEl) {
      const c = document.createElement('input');
      c.type = 'hidden';
      c.name = 'csrf_token';
      c.value = csrfEl.getAttribute('content') || '';
      f.appendChild(c);
    }
  } else {
    const c = document.createElement('input');
    c.type = 'hidden';
    c.name = csrfEl.name;
    c.value = csrfEl.value;
    f.appendChild(c);
  }
  f.submit();
}
if (sendPhoneCodeBtn) {
  sendPhoneCodeBtn.addEventListener('click', (e)=>{
    e.preventDefault();
    const val = newPhoneInput ? newPhoneInput.value.trim() : '';
    if (!val) { alert('Enter a phone number'); return; }
    postForm({initiate_phone_change: '1', new_phone: val});
  });
}
if (sendEmailCodeBtn) {
  sendEmailCodeBtn.addEventListener('click', (e)=>{
    e.preventDefault();
    const val = newEmailInput ? newEmailInput.value.trim() : '';
    if (!val) { alert('Enter an email address'); return; }
    postForm({initiate_email_change: '1', new_email: val});
  });
}
</script>

<?php include 'includes/footer.php'; ?>