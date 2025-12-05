<?php
/**
 * manage_users.php
 *
 * Robust Manage User page.
 * - Normalizes role- and identity-document rows.
 * - Surfaces user_documents and identity_documents as fallbacks for required/optional doc types.
 * - Orders role documents by known columns present in the schema to avoid "Unknown column" SQL errors.
 * - Approve/Reject forms send both user_role_document_id and identity_id so handlers can choose.
 * - Restores account activate/deactivate toggle, visible only to super_admins.
 *
 * Fix: Do not show the Approve button for documents that are already rejected.
 * Previously, canApproveDoc allowed ['pending','rejected'], which let admins approve
 * a rejected document without any resubmission. We now allow Approve ONLY when status is 'pending'.
 */

require_once 'config.php';
require_once 'includes/helpers.php';
require_once 'includes/csrf.php';
require_once 'includes/auth_roles.php';
require_once 'includes/audit.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
requireAdmin();

$page_title = 'Manage User';
$error = '';
$success = '';

$user_id = isset($_GET['user_id']) ? (int)$_GET['user_id'] : 0;
if ($user_id <= 0) { http_response_code(400); echo "Invalid user id."; exit; }

if (!empty($_SESSION['manage_user_msg'])) {
    $success = $_SESSION['manage_user_msg']; unset($_SESSION['manage_user_msg']);
}
if (!empty($_SESSION['manage_user_error'])) {
    $error = $_SESSION['manage_user_error']; unset($_SESSION['manage_user_error']);
}

/* ----- Load user ----- */
try {
    $user = $db->fetch("SELECT * FROM users WHERE user_id=? LIMIT 1", [$user_id]);
    if (!$user) { http_response_code(404); echo "User not found."; exit; }
} catch (Throwable $e) {
    error_log("manage_users load user fail: ".$e->getMessage());
    http_response_code(500); echo "Server error"; exit;
}

/* ----- Load user_roles ----- */
try {
    $user_roles = $db->fetchAll(
        "SELECT ur.*, r.name AS role_name, r.description AS role_description
         FROM user_roles ur
         JOIN roles r ON ur.role_id = r.role_id
         WHERE ur.user_id = ?
         ORDER BY ur.user_role_id DESC",
        [$user_id]
    ) ?: [];
} catch (Throwable $e) {
    error_log("manage_users load roles fail: ".$e->getMessage());
    $user_roles = [];
}

/* ----- Helpers & State ----- */
$hasSuperAdminRole = false;
foreach ($user_roles as $urTmp) {
    if (strtolower($urTmp['role_name'] ?? '') === 'super_admin') {
        $hasSuperAdminRole = true;
        break;
    }
}

// Determine whether the current logged-in admin is a super admin (controls toggle visibility)
$current_is_super = in_array('super_admin', array_map('strtolower', (array)($_SESSION['roles'] ?? [])), true);

$effectiveActive = (strtolower(trim((string)($user['status'] ?? ''))) === 'active');
foreach ($user_roles as $ur) {
    $st = strtolower(trim((string)$ur['status']));
    if ($st === 'active' || $st === 'provisional_active') { $effectiveActive = true; break; }
}

$ROLE_DOC_RULES = [
    'super_admin'    => ['required'=>[],               'optional'=>[]],
    'market_manager' => ['required'=>['permit'],       'optional'=>['id']],
    'vendor'         => ['required'=>['permit','id'],  'optional'=>[]],
    'inspector'      => ['required'=>['id'],           'optional'=>['permit']],
    'accountant'     => ['required'=>['id'],           'optional'=>['permit']],
];

function normalize_doc_type(string $raw): string {
    $t = strtolower(trim($raw));
    if ($t === '') return $t;
    $map = [
        'government_id'   => 'id',
        'gov_id'          => 'id',
        'government id'   => 'id',
        'id'              => 'id',
        'permit'          => 'permit',
        'business_permit' => 'permit',
        'business permit' => 'permit',
        'mayor_permit'    => 'permit',
        'business-permit' => 'permit',
        'other'           => 'other',
    ];
    return $map[$t] ?? $t;
}
function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE); }

/* --------------------- identity_documents (fallback) --------------------- */
$identityDocsMap = [];
try {
    $idRows = $db->fetchAll("SELECT * FROM identity_documents WHERE user_id = ? ORDER BY uploaded_at DESC", [$user_id]) ?: [];
    foreach ($idRows as $ir) {
        $identity_id = $ir['identity_id'] ?? $ir['identity_document_id'] ?? $ir['document_id'] ?? $ir['id'] ?? null;
        $doc_type = $ir['doc_type'] ?? $ir['document_type'] ?? ($ir['type'] ?? '');
        $status   = strtolower(trim((string)($ir['status'] ?? $ir['doc_status'] ?? '')));
        $file_path = $ir['storage_url'] ?? $ir['storage_path'] ?? $ir['file_path'] ?? null;
        $original_filename = $ir['original_filename'] ?? $ir['file_name'] ?? null;
        $uploaded_at = $ir['uploaded_at'] ?? ($ir['created_at'] ?? null);

        $k = normalize_doc_type((string)($doc_type ?? ''));
        if ($k === '') continue;
        if ($status === '') $status = 'pending';

        if (!isset($identityDocsMap[$k])) {
            $identityDocsMap[$k] = [
                'identity_id'       => (int)($identity_id ?? 0),
                'user_id'           => $ir['user_id'] ?? $user_id,
                'doc_type'          => $k,
                'status'            => $status,
                'file_path'         => $file_path,
                'original_filename' => $original_filename,
                'uploaded_at'       => $uploaded_at,
            ];
        }
    }
} catch (Throwable $e) {
    error_log("manage_users identity_documents fetch: " . $e->getMessage());
}

/* --------------------- user_documents (fallback) --------------------- */
$userDocsMap = [];
try {
    $udRows = $db->fetchAll("SELECT * FROM user_documents WHERE user_id = ? ORDER BY uploaded_at DESC", [$user_id]) ?: [];
    foreach ($udRows as $u) {
        $docTypeRaw = $u['file_type'] ?? ($u['doc_type'] ?? '');
        $k = normalize_doc_type((string)$docTypeRaw);
        if ($k === '') continue;
        if (!isset($userDocsMap[$k])) {
            $userDocsMap[$k] = [
                'user_document_id' => (int)($u['id'] ?? $u['user_document_id'] ?? 0),
                'doc_type'         => $k,
                'file_path'        => $u['file_path'] ?? null,
                'original_filename'=> $u['file_name'] ?? null,
                'uploaded_at'      => $u['uploaded_at'] ?? $u['created_at'] ?? null,
            ];
        }
    }
} catch (Throwable $e) {
    error_log("manage_users user_documents fetch: " . $e->getMessage());
}

/* --------------------- user_role_documents (role-level) --------------------- */
$documents_by_role = [];
if ($user_roles) {
    try {
        $roleIds = array_column($user_roles, 'user_role_id');
        if ($roleIds) {
            $ph = implode(',', array_fill(0, count($roleIds), '?'));

            $docRows = $db->fetchAll(
                "SELECT d.* FROM user_role_documents d
                 WHERE d.user_role_id IN ($ph)
                 ORDER BY COALESCE(d.user_role_document_id, 0) DESC, COALESCE(d.uploaded_at, d.reviewed_at, '') DESC",
                $roleIds
            ) ?: [];

            foreach ($docRows as $raw) {
                $roleDocId = $raw['user_role_document_id'] ?? $raw['id'] ?? $raw['doc_id'] ?? 0;
                $roleIdRef  = $raw['user_role_id'] ?? $raw['user_role_ref'] ?? null;

                $docTypeRaw = $raw['doc_type'] ?? $raw['document_type'] ?? $raw['type'] ?? '';
                $statusRaw  = $raw['status'] ?? $raw['doc_status'] ?? $raw['state'] ?? '';
                $filePath   = $raw['file_path'] ?? $raw['storage_path'] ?? $raw['storage_url'] ?? null;
                $origName   = $raw['original_filename'] ?? $raw['file_name'] ?? null;
                $uploadedAt = $raw['uploaded_at'] ?? $raw['reviewed_at'] ?? null;
                $identityId = $raw['identity_id'] ?? null;

                $docTypeN = normalize_doc_type((string)$docTypeRaw);
                $statusN  = strtolower(trim((string)$statusRaw));
                if ($statusN === '') $statusN = 'pending';

                $mapped = [
                    'user_role_document_id' => (int)$roleDocId,
                    'user_role_id'         => (int)$roleIdRef,
                    'doc_type'             => $docTypeN,
                    'status'               => $statusN,
                    'file_path'            => $filePath,
                    'original_filename'    => $origName,
                    'admin_notes'          => $raw['admin_notes'] ?? '',
                    'uploaded_at'          => $uploadedAt,
                    'identity_id'          => (int)($identityId ?? 0),
                ];

                $documents_by_role[(int)$mapped['user_role_id']][] = $mapped;
            }
        }
    } catch (Throwable $e) {
        error_log("manage_users load role documents fail: ".$e->getMessage());
    }
}

/* ----- Render view ----- */
require_once 'includes/header.php';
require_once 'includes/admin_sidebar.php';
?>
<section class="max-w-6xl mx-auto p-6">
  <div class="mb-6 flex flex-wrap items-start justify-between gap-4">
    <div>
      <h1 class="text-2xl font-bold"><?php echo h($user['full_name'] ?? $user['username']); ?></h1>
      <p class="text-sm text-gray-600">@<?php echo h($user['username']); ?></p>
      <p class="text-xs text-gray-500">User ID: <?php echo (int)$user['user_id']; ?></p>
      <?php if ($hasSuperAdminRole): ?>
        <p class="mt-2 text-xs px-2 py-1 inline-block bg-green-100 text-green-700 rounded">
          Super Admin (protected)
        </p>
      <?php endif; ?>
    </div>

    <div class="text-right">
      <p class="text-xs text-gray-500">Account status</p>
      <?php
        $badgeColor = $effectiveActive ? 'green' : 'gray';
        $badgeText  = $effectiveActive ? 'active' : (h($user['status']) ?: 'inactive');
      ?>
      <div class="mt-1 inline-block px-2 py-1 rounded bg-<?php echo $badgeColor; ?>-100 text-<?php echo $badgeColor; ?>-800 font-semibold">
        <?php echo $badgeText; ?>
      </div>

      <?php
        // Determine whether the target user is a super_admin (double-check against user_roles + users.role)
        $targetIsSuper = $hasSuperAdminRole;
        try {
            $col = $db->fetch("SHOW COLUMNS FROM users LIKE 'role'");
            if ($col && !empty($user['role']) && strtolower($user['role']) === 'super_admin') $targetIsSuper = true;
        } catch (Throwable $e) { /* ignore */ }
      ?>

      <div class="mt-3">
        <?php if (!$current_is_super): ?>
          <span class="text-xs text-gray-500 italic">Only Super Admins can toggle account status.</span>
        <?php elseif ($targetIsSuper): ?>
          <span class="text-xs text-gray-500 italic">Super Admin account state cannot be changed here.</span>
        <?php else: ?>
          <form method="POST" action="manage_users_action.php" class="inline-block">
            <?php echo csrf_field(); ?>
            <input type="hidden" name="action" value="set_status">
            <input type="hidden" name="user_id" value="<?php echo (int)$user['user_id']; ?>">
            <input type="hidden" name="status" value="<?php echo $effectiveActive ? 'inactive' : 'active'; ?>">
            <button class="px-4 py-2 rounded <?php echo $effectiveActive ? 'bg-yellow-500 hover:bg-yellow-600 text-white':'bg-green-600 hover:bg-green-700 text-white'; ?>">
              <?php echo $effectiveActive ? 'Deactivate Account' : 'Activate Account'; ?>
            </button>
          </form>
        <?php endif; ?>
      </div>
    </div>
  </div>

  <?php if ($error): ?>
    <div class="mb-4 text-red-700 bg-red-100 p-3 rounded"><?php echo h($error); ?></div>
  <?php endif; ?>
  <?php if ($success): ?>
    <div class="mb-4 text-green-700 bg-green-100 p-3 rounded"><?php echo h($success); ?></div>
  <?php endif; ?>

  <div class="bg-white rounded shadow p-6 mb-10">
    <h3 class="text-lg font-semibold mb-4">Roles & Document Verification</h3>

    <?php if (empty($user_roles)): ?>
      <p class="text-sm text-gray-600">No role requests or assignments found.</p>
    <?php else: ?>
      <div class="space-y-6">
        <?php foreach ($user_roles as $ur): ?>
          <?php
            $roleId     = (int)$ur['user_role_id'];
            $roleName   = h($ur['role_name']);
            $roleKey    = strtolower($ur['role_name']);
            $roleStatus = strtolower(trim((string)$ur['status']));
            $statusBadgeColor = match($roleStatus) {
                'active'             => 'green',
                'provisional_active' => 'amber',
                'under_review'       => 'indigo',
                'rejected'           => 'red',
                'pending'            => 'gray',
                default              => 'gray'
            };

            $docList = $documents_by_role[$roleId] ?? [];
            $docMap = [];
            foreach ($docList as $dr) {
                $k = strtolower(normalize_doc_type((string)$dr['doc_type']));
                $docMap[$k] = strtolower((string)$dr['status']);
            }

            $docRule = $ROLE_DOC_RULES[$roleKey] ?? ['required'=>[], 'optional'=>[]];
            $requiredNorm = array_map('strtolower', array_map('normalize_doc_type', (array)$docRule['required']));
            $optionalNorm = array_map('strtolower', array_map('normalize_doc_type', (array)$docRule['optional']));

            // Attach user_documents and identity_documents fallbacks for required and optional types
            foreach (array_merge($requiredNorm, $optionalNorm) as $type) {
                if (!isset($docMap[$type])) {
                    if (isset($userDocsMap[$type])) {
                        $ud = $userDocsMap[$type];
                        $mapped = [
                            'user_role_document_id' => 0,
                            'user_role_id'         => $roleId,
                            'doc_type'             => $type,
                            'status'               => 'pending',
                            'file_path'            => $ud['file_path'] ?? null,
                            'original_filename'    => $ud['original_filename'] ?? null,
                            'admin_notes'          => '',
                            'uploaded_at'          => $ud['uploaded_at'] ?? null,
                            'identity_id'          => 0,
                        ];
                        $docList[] = $mapped;
                        $docMap[$type] = $mapped['status'];
                        continue;
                    }
                    if (isset($identityDocsMap[$type])) {
                        $ir = $identityDocsMap[$type];
                        $mapped = [
                            'user_role_document_id' => 0,
                            'user_role_id'         => $roleId,
                            'doc_type'             => $type,
                            'status'               => strtolower((string)($ir['status'] ?? 'pending')),
                            'file_path'            => $ir['file_path'] ?? null,
                            'original_filename'    => $ir['original_filename'] ?? null,
                            'admin_notes'          => '',
                            'uploaded_at'          => $ir['uploaded_at'] ?? null,
                            'identity_id'          => (int)($ir['identity_id'] ?? 0),
                        ];
                        $docList[] = $mapped;
                        $docMap[$type] = $mapped['status'];
                    }
                }
            }

            $missingRequired = [];
            foreach ($requiredNorm as $reqType) {
                if (!isset($docMap[$reqType])) $missingRequired[] = $reqType;
            }

            $isSuperAdminRole = ($roleKey === 'super_admin');
          ?>

          <div class="border rounded-lg p-5">
            <div class="flex flex-wrap items-start justify-between gap-4">
              <div>
                <div class="flex items-center gap-3">
                  <h4 class="text-base font-semibold"><?php echo $roleName; ?></h4>
                  <span class="text-xs px-2 py-1 rounded bg-<?php echo $statusBadgeColor; ?>-100 text-<?php echo $statusBadgeColor; ?>-700 font-medium capitalize">
                    <?php echo h($roleStatus ?: 'unknown'); ?>
                  </span>
                  <?php if ($isSuperAdminRole): ?>
                    <span class="text-[10px] px-2 py-1 rounded bg-green-100 text-green-700 font-semibold">Protected</span>
                  <?php endif; ?>
                </div>

                <?php if ($missingRequired): ?>
                  <div class="mt-2 text-xs bg-red-50 border border-red-200 text-red-700 px-2 py-1 rounded">
                    Missing required: <?php echo h(implode(', ', $missingRequired)); ?>
                  </div>
                <?php elseif ($isSuperAdminRole): ?>
                  <div class="mt-2 text-xs bg-gray-50 border border-gray-200 text-gray-600 px-2 py-1 rounded">
                    No document requirements for Super Admin.
                  </div>
                <?php endif; ?>

                <div class="mt-2 text-xs">
                  <?php if ($requiredNorm || $optionalNorm): ?>
                    <strong>Docs:</strong>
                    <?php foreach ($requiredNorm as $rd): $rdKey = strtolower($rd); ?>
                      <span class="inline-block px-2 py-0.5 rounded <?php echo isset($docMap[$rdKey])?'bg-green-100 text-green-700':'bg-gray-100 text-gray-600'; ?>">
                        <?php echo h($rd); ?><?php echo isset($docMap[$rdKey])?'':' (missing)'; ?>
                      </span>
                    <?php endforeach; ?>
                    <?php foreach ($optionalNorm as $od): $odKey = strtolower($od); ?>
                      <span class="inline-block px-2 py-0.5 rounded <?php echo isset($docMap[$odKey])?'bg-blue-100 text-blue-700':'bg-gray-50 text-gray-500'; ?>">
                        <?php echo h($od); ?><?php echo isset($docMap[$odKey])?'':' (not uploaded)'; ?>
                      </span>
                    <?php endforeach; ?>
                  <?php else: ?>
                    <span class="inline-block px-2 py-0.5 rounded bg-gray-100 text-gray-600">None defined</span>
                  <?php endif; ?>
                </div>

                <?php if (!empty($ur['resubmission_reason'])): ?>
                  <div class="mt-2 text-xs bg-amber-50 border border-amber-200 text-amber-800 px-2 py-1 rounded">
                    <strong>Resubmission reason:</strong> <?php echo h($ur['resubmission_reason']); ?>
                  </div>
                <?php endif; ?>
                <?php if (!empty($ur['admin_notes'])): ?>
                  <div class="mt-2 text-xs bg-gray-50 border border-gray-200 text-gray-700 px-2 py-1 rounded whitespace-pre-line">
                    <strong>Admin notes:</strong> <?php echo h($ur['admin_notes']); ?>
                  </div>
                <?php endif; ?>
              </div>
            </div>

            <div class="mt-5">
              <h5 class="text-sm font-semibold mb-3">Documents (Role-Level)</h5>
              <p class="text-xs text-gray-600 mb-2">
                <?php if ($isSuperAdminRole): ?>
                  Super Admin role documents (if any) are display-only.
                <?php else: ?>
                  Once a required document is approved for an active role, it becomes locked. Optional docs can be updated.
                <?php endif; ?>
              </p>

              <?php if (empty($docList)): ?>
                <p class="text-xs text-gray-600">No role or fallback documents uploaded.</p>
              <?php else: ?>
                <div class="overflow-x-auto">
                  <table class="w-full text-xs">
                    <thead>
                      <tr class="bg-gray-50 text-left">
                        <th class="px-3 py-2">Type</th>
                        <th class="px-3 py-2">Status</th>
                        <th class="px-3 py-2">Uploaded</th>
                        <th class="px-3 py-2">File</th>
                        <th class="px-3 py-2">Notes</th>
                        <th class="px-3 py-2">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      <?php foreach ($docList as $dr): ?>
                        <?php
                          $docStatus = strtolower(trim((string)($dr['status'] ?? 'pending')));
                          if ($docStatus === '') $docStatus = 'pending';
                          $docType = normalize_doc_type((string)($dr['doc_type'] ?? 'other'));

                          $docBadgeColor = match($docStatus) {
                              'approved' => 'green',
                              'rejected' => 'red',
                              'pending'  => 'amber',
                              default    => 'gray'
                          };

                          $docIsRequired = in_array(strtolower($docType), $requiredNorm, true);
                          $docLocked = (!$isSuperAdminRole && $roleStatus === 'active' && $docIsRequired && $docStatus === 'approved');

                          // FIX: Only allow Approve when status is 'pending' (not 'rejected')
                          $canApproveDoc = (!$isSuperAdminRole && !$docLocked && $docStatus === 'pending');

                          // Reject allowed only when pending (no action on already approved/rejected)
                          $canRejectDoc  = (!$isSuperAdminRole && !$docLocked && $docStatus === 'pending');

                          $roleDocId = (int)($dr['user_role_document_id'] ?? 0);
                          $identityId = (int)($dr['identity_id'] ?? 0);
                          $docFormId = $roleDocId ?: $identityId;
                        ?>
                        <tr class="border-t">
                          <td class="px-3 py-2 font-medium capitalize"><?php echo h($dr['doc_type'] ?? $docType); ?></td>
                          <td class="px-3 py-2">
                            <span class="inline-block px-2 py-1 rounded bg-<?php echo $docBadgeColor; ?>-100 text-<?php echo $docBadgeColor; ?>-700 font-semibold">
                              <?php echo h($docStatus); ?>
                            </span>
                            <?php if ($docIsRequired): ?>
                              <span class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-700">required</span>
                            <?php else: ?>
                              <span class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-blue-50 text-blue-700">optional</span>
                            <?php endif; ?>
                          </td>
                          <td class="px-3 py-2 text-gray-500"><?php echo h($dr['uploaded_at'] ?? ''); ?></td>
                          <td class="px-3 py-2">
                            <?php if (!empty($dr['file_path'])): ?>
                              <a href="<?php echo h($dr['file_path']); ?>" target="_blank" class="text-blue-600 hover:underline">View</a>
                            <?php else: ?>
                              <span class="text-gray-400">No file</span>
                            <?php endif; ?>
                          </td>
                          <td class="px-3 py-2 whitespace-pre-wrap"><?php echo h($dr['admin_notes'] ?? ''); ?></td>
                          <td class="px-3 py-2">
                            <?php if ($isSuperAdminRole): ?>
                              <span class="text-[10px] text-gray-400 italic">Protected</span>
                            <?php elseif ($docLocked): ?>
                              <span class="text-[10px] text-gray-400 italic">Locked</span>
                            <?php else: ?>
                              <div class="flex flex-wrap gap-2">
                                <?php if ($canApproveDoc): ?>
                                  <form method="POST" action="approve_role_document.php" class="m-0 inline-block">
                                    <?php echo csrf_field(); ?>
                                    <input type="hidden" name="user_role_document_id" value="<?php echo $roleDocId; ?>">
                                    <input type="hidden" name="identity_id" value="<?php echo $identityId; ?>">
                                    <button type="submit" class="px-2 py-1 bg-green-600 hover:bg-green-700 text-white rounded" title="Approve document">Approve</button>
                                  </form>
                                <?php endif; ?>
                                <?php if ($canRejectDoc): ?>
                                  <button type="button" class="px-2 py-1 bg-red-600 hover:bg-red-700 text-white rounded"
                                          data-doc-id="<?php echo $docFormId; ?>"
                                          data-role-doc-id="<?php echo $roleDocId; ?>"
                                          data-identity-id="<?php echo $identityId; ?>"
                                          data-doc-type="<?php echo h($dr['doc_type'] ?? $docType); ?>"
                                          onclick="openRejectDocModal(this)">
                                    Reject
                                  </button>
                                <?php endif; ?>
                              </div>
                            <?php endif; ?>
                          </td>
                        </tr>
                      <?php endforeach; ?>
                    </tbody>
                  </table>
                </div>
              <?php endif; ?>

            </div>
          </div>

        <?php endforeach; ?>
      </div>
    <?php endif; ?>
  </div>
</section>

<!-- Reject Document Modal -->
<div id="rejectDocModal" class="hidden fixed inset-0 z-50 flex items-center justify-center p-4 bg-black bg-opacity-50">
  <div class="bg-white rounded-lg w-full max-w-lg p-6 shadow-lg">
    <h3 class="text-lg font-semibold mb-2">Reject Document</h3>
    <p id="rejectDocModalLabel" class="text-sm text-gray-600 mb-4"></p>
    <form method="POST" action="reject_role_document.php">
      <?php echo csrf_field(); ?>
      <input type="hidden" name="user_role_document_id" id="reject_doc_id">
      <input type="hidden" name="identity_id" id="reject_identity_id">
      <div class="mb-4">
        <label class="block text-sm font-medium mb-2">Reason (required)</label>
        <textarea name="reason" rows="4" required class="w-full border p-3 rounded"
                  placeholder="Describe the issue (e.g. 'Blurry ID photo', 'Permit expired')."></textarea>
        <p class="text-xs text-gray-500 mt-1">User will see this reason when resubmitting.</p>
      </div>
      <div class="flex justify-end gap-2">
        <button type="button" onclick="closeRejectDocModal()" class="px-4 py-2 bg-gray-200 rounded">Cancel</button>
        <button type="submit" class="px-4 py-2 bg-red-600 text-white rounded">Reject Document</button>
      </div>
    </form>
  </div>
</div>

<script>
function openRejectDocModal(btn){
  const roleDocId = btn.getAttribute('data-role-doc-id') || '';
  const identityId = btn.getAttribute('data-identity-id') || '';
  const docId = btn.getAttribute('data-doc-id') || '';
  const docType = btn.getAttribute('data-doc-type') || '';

  document.getElementById('reject_doc_id').value = roleDocId || docId || '';
  document.getElementById('reject_identity_id').value = identityId || '';

  const displayId = roleDocId || identityId || docId || 'unknown';
  document.getElementById('rejectDocModalLabel').textContent =
    "Reject '" + docType + "' document (ID #" + displayId + ").";
  document.getElementById('rejectDocModal').classList.remove('hidden');
}
function closeRejectDocModal(){
  document.getElementById('rejectDocModal').classList.add('hidden');
  document.getElementById('reject_doc_id').value='';
  document.getElementById('reject_identity_id').value='';
}
document.addEventListener('click',function(e){
  const dm=document.getElementById('rejectDocModal');
  if (dm && e.target===dm) closeRejectDocModal();
});
document.addEventListener('keydown',function(e){
  if (e.key==='Escape') {
    const dm=document.getElementById('rejectDocModal');
    if (dm && !dm.classList.contains('hidden')) closeRejectDocModal();
  }
});
</script>

<?php include 'includes/footer.php'; ?>