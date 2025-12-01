<?php
// snippet to add to public/gateway_webhook.php (place near other helpers)

function normalize_ph_number(string $n): ?string {
    $s = preg_replace('/[^\d\+]/', '', trim($n));
    if (preg_match('/^\+63([0-9]{10})$/', $s, $m)) return '+63' . $m[1];
    if (preg_match('/^63([0-9]{10})$/', $s, $m)) return '+63' . $m[1];
    if (preg_match('/^0([0-9]{10})$/', $s, $m)) return '+63' . $m[1];
    return null;
}

// ... later, before inserting inbound message:
$fromRaw = $payload['phoneNumber'] ?? $payload['from'] ?? null;
$from = $fromRaw ? normalize_ph_number((string)$fromRaw) ?? $fromRaw : null;
// now use $from when inserting in DB