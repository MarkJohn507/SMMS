<?php
/**
 * resubmit_role_request.php (Document-level + minimal doc set)
 *
 * Minimal document rules:
 *   super_admin / market_manager: required ['permit'], optional ['id']
 *   vendor: required ['id']
 *   fallback: required ['id','permit']
 *
 * Resubmission allowed if:
 *   - role status in (rejected, revoked, denied, declined)
 *   - OR (pending AND resubmission_reason not null)
 *   - OR any required document is rejected
 *
 * After successful resubmission, recompute:
 *   ANY required rejected => role.status='rejected'
 *   ALL required approved => role.status='active'
 *   SOME required approved (none rejected) => 'provisional_active'
 *   ELSE => 'under_review'
 */

require_once 'config.php';
require_once 'includes/helpers.php';
require_once 'includes/csrf.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
if (!function_exists('isLoggedIn') || !isLoggedIn()) redirect('login.php');

$user_id = (int)($_SESSION['user_id'] ?? 0);
if ($user_id <= 0) redirect('login.php');

$page_title = 'Resubmit Role Documents';
$errors = [];
$success = '';

$user_role_id = isset($_REQUEST['user_role_id'])
    ? (int)$_REQUEST['user_role_id']
    : (int)($_SESSION['rejected_role_request']['user_role_id'] ?? 0);

if ($user_role_id <= 0) $errors[] = 'Invalid role request ID.';

$ROLE_DOC_RULES = [
    'super_admin'    => ['required'=>['permit'],'optional'=>['id']],
    'market_manager' => ['required'=>['permit'],'optional'=>['id']],
    'vendor'         => ['required'=>['id'],'optional'=>[]],
];

$has_resubmission_reason = false;
try {
    $cols = $db->fetchAll("SHOW COLUMNS FROM user_roles") ?: [];
    foreach ($cols as $c) {
        $f = is_array($c) ? ($c['Field'] ?? $c['field'] ?? '') : '';
        if (strtolower($f) === 'resubmission_reason') { $has_resubmission_reason = true; break; }
    }
} catch (Throwable $e) {}

function loadRoleRequest($db,$id,$hasReason) {
    if ($hasReason) {
        return $db->fetch(
            "SELECT ur.user_role_id, ur.user_id, ur.role_id,
                    LOWER(TRIM(COALESCE(ur.status,''))) AS status,
                    ur.admin_notes, ur.resubmission_reason,
                    r.name AS role_name, r.description AS role_description
             FROM user_roles ur
             JOIN roles r ON ur.role_id = r.role_id
             WHERE ur.user_role_id = ?
             LIMIT 1",
            [$id]
        );
    }
    $row = $db->fetch(
        "SELECT ur.user_role_id, ur.user_id, ur.role_id,
                LOWER(TRIM(COALESCE(ur.status,''))) AS status,
                ur.admin_notes,
                r.name AS role_name, r.description AS role_description
         FROM user_roles ur
         JOIN roles r ON ur.role_id = r.role_id
         WHERE ur.user_role_id = ?
         LIMIT 1",
        [$id]
    );
    if ($row) $row['resubmission_reason'] = null;
    return $row;
}

$roleRequest = null;
if (empty($errors)) {
    try {
        $roleRequest = loadRoleRequest($db,$user_role_id,$has_resubmission_reason);
        if (!$roleRequest) {
            $errors[] = 'Role request not found.';
        } elseif ((int)$roleRequest['user_id'] !== $user_id) {
            $errors[] = 'This role request does not belong to your account.';
        }
    } catch (Throwable $e) {
        error_log("resubmit load roleRequest fail: ".$e->getMessage());
        $errors[] = 'Failed to load role request.';
    }
}

$docRows = [];
if (empty($errors)) {
    try {
        $docRows = $db->fetchAll(
            "SELECT user_role_document_id, doc_type, status, file_path, original_filename, admin_notes, uploaded_at
             FROM user_role_documents
             WHERE user_role_id = ?
             ORDER BY user_role_document_id DESC",
            [$user_role_id]
        ) ?: [];
    } catch (Throwable $e) { error_log("resubmit load docs fail: ".$e->getMessage()); }
}

$canResubmit = false;
if (empty($errors) && $roleRequest) {
    $status = $roleRequest['status'] ?? '';
    $reason = trim((string)($roleRequest['resubmission_reason'] ?? ''));
    $rejectedLike = ['rejected','revoked','denied','declined'];
    $anyRejectedDoc = false;
    foreach ($docRows as $dr) if ($dr['status'] === 'rejected') { $anyRejectedDoc = true; break; }

    if (in_array($status,$rejectedLike,true)) $canResubmit = true;
    elseif ($status === 'pending' && $has_resubmission_reason && $reason !== '') $canResubmit = true;
    elseif ($anyRejectedDoc) $canResubmit = true;
    if ($status === 'active') $canResubmit = $anyRejectedDoc;
}

if (!empty($_GET['ok']) && $_GET['ok']==='1') {
    $success = 'Your documents were submitted. Status recalculated.';
    $canResubmit = false;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $canResubmit && empty($errors)) {
    if (!csrf_validate_request()) {
        $errors[]='Invalid CSRF token.';
    } else {
        $maxBytes = 5 * 1024 * 1024;
        $allowedMimes = ['image/jpeg'=>'jpg','image/png'=>'png'];

        $roleNameKey = strtolower(trim((string)$roleRequest['role_name']));
        $docRule = $ROLE_DOC_RULES[$roleNameKey] ?? ['required'=>['id','permit'],'optional'=>[]];
        $requiredDocs = $docRule['required'];
        $optionalDocs = $docRule['optional'];

        // Gather uploads
        $incomingMap = [
            'document_id'     => 'id',
            'document_permit' => 'permit',
        ];
        $userNote = trim(sanitize($_POST['resubmit_note'] ?? ''));
        $uploads = [];

        foreach ($incomingMap as $fieldName => $docType) {
            if (!isset($_FILES[$fieldName]) || $_FILES[$fieldName]['error'] !== UPLOAD_ERR_OK) continue;
            $f = $_FILES[$fieldName];
            if (!is_uploaded_file($f['tmp_name'])) { $errors[]="Invalid upload for $docType."; continue; }
            if ($f['size'] > $maxBytes) { $errors[]=ucfirst($docType)." exceeds 5MB."; continue; }
            $mime = (new finfo(FILEINFO_MIME_TYPE))->file($f['tmp_name']);
            if (!isset($allowedMimes[$mime])) { $errors[]=ucfirst($docType)." must be JPG or PNG."; continue; }
            $uploads[$docType] = [
                'tmp_name' => $f['tmp_name'],
                'orig_name'=> $f['name'],
                'ext'      => $allowedMimes[$mime],
                'mime'     => $mime
            ];
        }

        // Build current status map
        $currentMap = [];
        foreach ($docRows as $dr) $currentMap[$dr['doc_type']] = $dr['status'];

        if (empty($uploads)) {
            $missingRequired = false;
            foreach ($requiredDocs as $req) {
                if (!isset($currentMap[$req]) || $currentMap[$req] === 'rejected') { $missingRequired = true; break; }
            }
            if ($missingRequired) {
                $errors[] = 'Upload at least one required document: '.implode(', ', $requiredDocs).'.';
            }
        }

        if (empty($errors)) {
            $txOk=false;
            try {
                if (method_exists($db,'beginTransaction')) $db->beginTransaction();

                $baseDir = __DIR__.'/uploads/user_documents/'.$user_id.'/';
                if (!is_dir($baseDir)) @mkdir($baseDir,0755,true);

                $savedTypes=[];
                foreach ($uploads as $docType=>$meta) {
                    $destName = time().'_'.bin2hex(random_bytes(8)).'.'.$meta['ext'];
                    $destPath = $baseDir.$destName;
                    $relPath  = 'uploads/user_documents/'.$user_id.'/'.$destName;

                    if (!@move_uploaded_file($meta['tmp_name'],$destPath)) {
                        if (!@rename($meta['tmp_name'],$destPath)) {
                            if (!@copy($meta['tmp_name'],$destPath)) {
                                throw new RuntimeException("Failed storing file for $docType.");
                            }
                        }
                    }

                    $savedTypes[]=$docType;
                    // Update existing rejected row OR insert new
                    $existing = null;
                    foreach ($docRows as $dr) if ($dr['doc_type']===$docType) { $existing=$dr; break; }

                    if ($existing && $existing['status']==='rejected') {
                        $db->query(
                            "UPDATE user_role_documents
                             SET file_path=?, original_filename=?, status='pending',
                                 admin_notes = CONCAT(COALESCE(admin_notes,''), ?),
                                 uploaded_at=NOW(), reviewed_at=NULL, reviewed_by=NULL
                             WHERE user_role_document_id=?",
                            [$relPath,$meta['orig_name'],"\n[Resubmitted ".date('Y-m-d H:i:s')."]",$existing['user_role_document_id']]
                        );
                    } else {
                        $db->query(
                            "INSERT INTO user_role_documents
                             (user_role_id, doc_type, file_path, original_filename, status, admin_notes, uploaded_at)
                             VALUES (?,?,?,?, 'pending', ?, NOW())",
                            [$user_role_id,$docType,$relPath,$meta['orig_name'],"[Uploaded ".date('Y-m-d H:i:s')."]"]
                        );
                    }
                }

                $appendNote = "[User Resubmission ".date('Y-m-d H:i:s')."]";
                if ($savedTypes) $appendNote .= " Docs: ".implode(',',$savedTypes).".";
                if ($userNote!=='') $appendNote .= " Note: ".$userNote;

                // Recompute required doc statuses
                $docsNow = $db->fetchAll("SELECT doc_type,status FROM user_role_documents WHERE user_role_id=?",[$user_role_id]) ?: [];
                $mapNow=[];
                foreach ($docsNow as $dn) $mapNow[strtolower($dn['doc_type'])] = strtolower($dn['status']);

                $anyRejectedRequired=false;
                $allRequiredApproved=true;
                $anyRequiredApproved=false;
                foreach ($requiredDocs as $req) {
                    $st=$mapNow[$req] ?? null;
                    if ($st==='rejected') $anyRejectedRequired=true;
                    if ($st!=='approved') $allRequiredApproved=false;
                    if ($st==='approved') $anyRequiredApproved=true;
                }

                if ($anyRejectedRequired)       $newStatus='rejected';
                elseif ($allRequiredApproved)   $newStatus='active';
                elseif ($anyRequiredApproved)   $newStatus='provisional_active';
                else                            $newStatus='under_review';

                if ($has_resubmission_reason) {
                    $db->query(
                        "UPDATE user_roles
                         SET status=?, admin_notes=CONCAT(COALESCE(admin_notes,''), ?), resubmission_reason=NULL
                         WHERE user_role_id=?",
                        [$newStatus,"\n".$appendNote,$user_role_id]
                    );
                } else {
                    $db->query(
                        "UPDATE user_roles
                         SET status=?, admin_notes=CONCAT(COALESCE(admin_notes,''), ?)
                         WHERE user_role_id=?",
                        [$newStatus,"\n".$appendNote,$user_role_id]
                    );
                }

                // Notify admins if under_review / provisional / active
                if (in_array($newStatus,['under_review','provisional_active','active'],true)) {
                    try {
                        $admins=$db->fetchAll("
                            SELECT DISTINCT u.user_id
                            FROM user_roles x
                            JOIN roles r2 ON x.role_id=r2.role_id
                            JOIN users u ON x.user_id=u.user_id
                            WHERE LOWER(r2.name) IN ('municipal_admin','super_admin','issuer_admin')
                              AND x.status='active'
                            LIMIT 100
                        ") ?: [];
                        $notifyMsg="User ".htmlspecialchars($_SESSION['full_name'] ?? $_SESSION['username'] ?? 'user',ENT_QUOTES)
                                ." resubmitted documents for role request ID ".$user_role_id." (status now: $newStatus).";
                        foreach ($admins as $a) {
                            $db->query(
                                "INSERT INTO notifications (user_id, title, message, type, category, created_at)
                                 VALUES (?, 'Role resubmission', ?, 'info', 'role_request', NOW())",
                                [$a['user_id'],$notifyMsg]
                            );
                        }
                    } catch (Throwable $e) { error_log("resubmit notify admins fail: ".$e->getMessage()); }
                }

                if (method_exists($db,'commit')) $db->commit();
                logAudit($db,$user_id,'Resubmitted role documents','user_roles',$user_role_id,null,$newStatus);
                header('Location: resubmit_role_request.php?user_role_id='.(int)$user_role_id.'&ok=1');
                exit;
            } catch (Throwable $e) {
                if (method_exists($db,'rollBack')) $db->rollBack();
                error_log("resubmit transaction error: ".$e->getMessage());
                $errors[]='Failed to process resubmission.';
            }
        }
    }
}

// Reload doc rows post operation
if (empty($errors)) {
    try {
        $docRows = $db->fetchAll(
            "SELECT user_role_document_id, doc_type, status, file_path, original_filename, admin_notes, uploaded_at
             FROM user_role_documents
             WHERE user_role_id = ?
             ORDER BY user_role_document_id DESC",
            [$user_role_id]
        ) ?: [];
    } catch (Throwable $e) {}
}

require_once 'includes/header.php';
?>
<section class="max-w-5xl mx-auto p-6">
  <h1 class="text-2xl font-bold mb-4">Resubmit Documents for <?php echo htmlspecialchars($roleRequest['role_name'] ?? 'Requested Role'); ?></h1>

  <?php if ($errors): ?>
    <div class="mb-4 space-y-2">
      <?php foreach ($errors as $e): ?>
        <div class="bg-red-100 border border-red-300 text-red-800 px-4 py-2 rounded"><?php echo htmlspecialchars($e); ?></div>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>

  <?php if ($success): ?>
    <div class="mb-4 bg-green-100 border border-green-300 text-green-800 px-4 py-2 rounded">
      <?php echo htmlspecialchars($success); ?>
    </div>
  <?php endif; ?>

  <?php if ($roleRequest): ?>
    <div class="bg-white rounded shadow p-4 mb-6">
      <h3 class="font-semibold mb-2">Admin Instructions / Reason</h3>
      <div class="text-sm text-gray-700 whitespace-pre-wrap">
        <?php
          $show = trim((string)($roleRequest['resubmission_reason'] ?? ''));
          if ($show === '') $show = trim((string)($roleRequest['admin_notes'] ?? ''));
          echo htmlspecialchars($show !== '' ? $show : 'No instructions provided.');
        ?>
      </div>
      <div class="text-xs text-gray-500 mt-2">
        Role status:
        <span class="font-semibold"><?php echo htmlspecialchars($roleRequest['status'] ?? ''); ?></span>
      </div>
    </div>
  <?php endif; ?>

  <div class="bg-white rounded shadow p-4 mb-6">
    <h3 class="font-semibold mb-3">Role-Level Documents</h3>
    <?php if (empty($docRows)): ?>
      <p class="text-sm text-gray-600">No role documents uploaded yet.</p>
    <?php else: ?>
      <table class="w-full text-sm">
        <thead>
          <tr class="bg-gray-50 text-left">
            <th class="px-3 py-2">Type</th>
            <th class="px-3 py-2">Status</th>
            <th class="px-3 py-2">Uploaded</th>
            <th class="px-3 py-2">File</th>
            <th class="px-3 py-2">Notes</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach ($docRows as $dr): ?>
            <?php
              $st = strtolower($dr['status']);
              $color = $st==='approved'?'green':($st==='rejected'?'red':($st==='pending'?'amber':'gray'));
            ?>
            <tr class="border-t">
              <td class="px-3 py-2 capitalize font-medium"><?php echo htmlspecialchars($dr['doc_type']); ?></td>
              <td class="px-3 py-2">
                <span class="inline-block px-2 py-1 rounded text-xs bg-<?php echo $color; ?>-100 text-<?php echo $color; ?>-700">
                  <?php echo htmlspecialchars($st); ?>
                </span>
              </td>
              <td class="px-3 py-2 text-xs text-gray-500"><?php echo htmlspecialchars($dr['uploaded_at']); ?></td>
              <td class="px-3 py-2">
                <?php if ($dr['file_path']): ?>
                  <a href="<?php echo htmlspecialchars($dr['file_path']); ?>" target="_blank" class="text-blue-600 underline text-xs">View</a>
                <?php else: ?>
                  <span class="text-gray-400 text-xs">No file</span>
                <?php endif; ?>
              </td>
              <td class="px-3 py-2 text-xs whitespace-pre-wrap"><?php echo htmlspecialchars($dr['admin_notes'] ?? ''); ?></td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>
  </div>

  <?php
    $roleNameKey = strtolower(trim((string)($roleRequest['role_name'] ?? '')));
    $docRule = $ROLE_DOC_RULES[$roleNameKey] ?? ['required'=>['id','permit'],'optional'=>[]];
    $requiredDocs = $docRule['required'];
    $optionalDocs = $docRule['optional'];
  ?>

  <?php if ($canResubmit): ?>
    <form method="POST" enctype="multipart/form-data" class="bg-white rounded shadow p-4">
      <?php echo csrf_field(); ?>
      <input type="hidden" name="user_role_id" value="<?php echo (int)$user_role_id; ?>">

      <h3 class="font-semibold mb-3">Upload Replacement Documents</h3>
      <p class="text-xs text-gray-600 mb-4">
        Required: <?php echo htmlspecialchars(implode(', ', $requiredDocs)); ?>.
        Optional: <?php echo htmlspecialchars(implode(', ', $optionalDocs)); ?>.
        Each file must be a JPG or PNG ≤5MB.
      </p>

      <div class="mb-4">
        <label class="block text-sm font-medium">
          Permit (<?php echo in_array('permit', $optionalDocs, true) ? 'OPTIONAL' : 'REQUIRED'; ?>, JPEG/PNG &le;5MB)
        </label>
        <input type="file" name="document_permit" accept="image/jpeg,image/png" class="text-sm">
        <p class="text-xs text-gray-500 mt-1">Mayor's / Business Permit.</p>
      </div>

      <div class="mb-4">
        <label class="block text-sm font-medium">
          Government ID (<?php echo in_array('id',$optionalDocs,true)?'OPTIONAL':'REQUIRED'; ?>, JPEG/PNG ≤5MB)
        </label>
        <input type="file" name="document_id" accept="image/jpeg,image/png" class="text-sm">
        <p class="text-xs text-gray-500 mt-1">Upload if requested or to expedite verification.</p>
      </div>

      <div class="mb-4">
        <label class="block text-sm font-medium">Notes to Reviewer (optional)</label>
        <textarea name="resubmit_note" rows="3" class="w-full border rounded p-2 text-sm" placeholder="Clarifications..."><?php echo htmlspecialchars($_POST['resubmit_note'] ?? ''); ?></textarea>
      </div>

      <div class="flex gap-2">
        <button type="submit" class="px-5 py-2 bg-green-600 hover:bg-green-700 text-white rounded text-sm">Submit Resubmission</button>
        <a href="vendor_dashboard.php" class="px-5 py-2 bg-gray-200 rounded text-sm">Back to Dashboard</a>
      </div>
    </form>
  <?php else: ?>
    <div class="bg-white rounded shadow p-4">
      <p class="text-sm text-gray-700">
        <?php if (!empty($roleRequest) && $roleRequest['status'] === 'under_review'): ?>
          Your submission is under review. You cannot resubmit unless a document is rejected.
        <?php elseif (!empty($roleRequest) && $roleRequest['status'] === 'active'): ?>
          Your role request is fully approved.
        <?php else: ?>
          This role request is not currently marked for resubmission.
        <?php endif; ?>
      </p>
      <div class="mt-3">
        <a href="vendor_dashboard.php" class="px-4 py-2 bg-gray-200 rounded text-sm">Back to Dashboard</a>
      </div>
    </div>
  <?php endif; ?>
</section>

<?php include 'includes/footer.php'; ?>