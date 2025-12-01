<?php
// includes/header.php
// Minimal top-level layout header partial.
// Request: remove display of user name / role such as "Market Manager".
// NOTE: The original header you provided did NOT actually render the user's name or role;
// those labels appear in sidebar files (e.g. admin_sidebar.php / vendor_sidebar.php).
// This version keeps only essential elements and a neutral <title>,
// unless a page explicitly sets $page_title (it will still show, but you can force a generic title
// by unsetting $page_title before including this file or by setting $USE_GENERIC_TITLE = true).

if (!defined('INCLUDED_HEADER')) define('INCLUDED_HEADER', true);

// Cronless billing enforcement (ensure monthly invoices, grace handling, auto-termination, reminders)
require_once __DIR__ . '/billing_bootstrap.php';

// If you want to globally force a neutral title (removing any role text that might be stored in $page_title),
// set $USE_GENERIC_TITLE = true before including this header.
$USE_GENERIC_TITLE = $USE_GENERIC_TITLE ?? false;
$effectiveTitle = ($USE_GENERIC_TITLE || empty($page_title))
  ? 'SMMS'
  : preg_replace('/\b(Market Manager|Vendor|Super Admin|Municipal Admin|Issuer Admin|Accountant|Inspector)\b/i', 'SMMS', $page_title);

?><!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title><?php echo htmlspecialchars($effectiveTitle); ?></title>

  <!-- CSRF meta (for AJAX) -->
  <meta name="csrf-token" content="<?php echo htmlspecialchars(function_exists('csrf_get_token') ? csrf_get_token() : ''); ?>">
  <meta name="viewport" content="width=device-width,initial-scale=1">

  <!-- Tailwind (consider self-hosting in production) -->
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">

  <style>
    body {font-family:Inter,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial}
  </style>

  <script>
    // CSRF helper
    window.SMMS = window.SMMS || {};
    window.SMMS.csrfToken = (document.querySelector('meta[name="csrf-token"]')||{}).content || '';
    window.SMMS.getCsrfFormField = function() {
      return {
        name: '<?php echo htmlspecialchars(function_exists('csrf_get_name') ? csrf_get_name() : 'csrf_token'); ?>',
        value: window.SMMS.csrfToken
      };
    };
  </script>
</head>
<body class="bg-gray-100 min-h-screen">