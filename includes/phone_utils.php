<?php
// includes/phone_utils.php
// Phone number normalization and validation helpers (Philippines focused)

// Normalize PH number to +63XXXXXXXXXX or return null if invalid.
function normalize_ph_number(string $n): ?string {
    $s = trim($n);
    if ($s === '') return null;
    // strip spaces, dashes, parentheses, and other non-digit/non-plus chars
    $s = preg_replace('/[^\d\+]/', '', $s);

    // +63XXXXXXXXXX
    if (preg_match('/^\+63([0-9]{10})$/', $s, $m)) {
        return '+63' . $m[1];
    }
    // 63XXXXXXXXXX (no plus)
    if (preg_match('/^63([0-9]{10})$/', $s, $m)) {
        return '+63' . $m[1];
    }
    // 0XXXXXXXXXX (local format e.g. 09171234567)
    if (preg_match('/^0([0-9]{10})$/', $s, $m)) {
        return '+63' . $m[1];
    }
    // optionally accept plain 10-digit local without leading 0? (not recommended)
    return null;
}

// True if input is a PH number in accepted input forms (before normalization)
function is_ph_number(string $n): bool {
    $s = trim($n);
    if ($s === '') return false;
    $s = preg_replace('/[^\d\+]/', '', $s);
    return (bool)preg_match('/^(?:\+63|63|0)[0-9]{10}$/', $s);
}

// Normalize an array of numbers; returns an associative array: ['valid' => [...normalized...], 'invalid' => [...original...]]
function normalize_list_ph(array $numbers): array {
    $valid = [];
    $invalid = [];
    foreach ($numbers as $n) {
        $norm = normalize_ph_number((string)$n);
        if ($norm === null) $invalid[] = (string)$n;
        else $valid[] = $norm;
    }
    return ['valid' => $valid, 'invalid' => $invalid];
}