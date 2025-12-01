<?php
// tools/send_confirmation_immediate.php
// Try immediate send using sendSMS(); on success record sent row, on failure fall back to queue.
// Include from settings.php:
//   require_once __DIR__ . '/tools/send_confirmation_immediate.php';
//
// $db is expected to be your application's DB wrapper (->query / ->fetch / ->fetchAll / ->lastInsertId).
// This file is safe to include in web SAPI and will attempt a background spawn on Windows when enqueueing.

if (!function_exists('send_confirmation_code_sms')) {
    function send_confirmation_code_sms($db, int $user_id, string $to, string $code, string $purpose = 'email_change'): bool {
        $to = trim($to);
        if ($to === '') return false;

        if ($purpose === 'email_change') {
            $msg = "Your confirmation code to change email is: {$code}. It expires in 15 minutes.";
        } elseif ($purpose === 'phone_change') {
            $msg = "Your confirmation code to update phone is: {$code}. It expires in 15 minutes.";
        } else {
            $msg = "Your confirmation code is: {$code}. It expires in 15 minutes.";
        }

        // Ensure sms_queue table exists (safe)
        try {
            $db->query("CREATE TABLE IF NOT EXISTS sms_queue (
                id INT AUTO_INCREMENT PRIMARY KEY,
                recipient VARCHAR(64) NOT NULL,
                body TEXT NOT NULL,
                status ENUM('queued','sending','sent','failed') NOT NULL DEFAULT 'queued',
                attempts INT NOT NULL DEFAULT 0,
                last_error TEXT NULL,
                provider_response TEXT NULL,
                external_id VARCHAR(255) NULL,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NULL,
                priority ENUM('low','normal','high') NOT NULL DEFAULT 'normal',
                sim_number INT NULL
            )");
        } catch (Throwable $e) {
            error_log("send_confirmation_code_sms: create table failed: " . $e->getMessage());
            // continue - insertion may still fail and handled below
        }

        // If sendSMS() exists, prefer immediate send
        if (function_exists('sendSMS')) {
            try {
                $res = sendSMS($to, $msg);
                error_log("send_confirmation_code_sms web send attempt: to={$to} ok=" . (!empty($res['ok']) ? '1' : '0') . " http=" . ($res['http'] ?? '0') . " err=" . ($res['error'] ?? ''));
                $ok = !empty($res['ok']);
                $raw = $res['raw'] ?? (is_scalar($res['error']) ? (string)$res['error'] : json_encode($res));
                $mid = $res['message_id'] ?? $res['id'] ?? null;

                try {
                    if ($ok) {
                        // record as sent for history (attempts=1)
                        $db->query(
                            "INSERT INTO sms_queue (recipient, body, status, attempts, provider_response, external_id, created_at, updated_at)
                             VALUES (?, ?, 'sent', 1, ?, ?, NOW(), NOW())",
                            [$to, $msg, $raw, $mid]
                        );
                        if (function_exists('createNotification')) {
                            try { createNotification($db, $user_id, 'Code sent', 'A confirmation code was sent to your phone.', 'info', 'verification', $user_id, 'users'); } catch (Throwable $e) {}
                        }
                        return true;
                    } else {
                        // immediate send failed — queue for retry
                        $db->query(
                            "INSERT INTO sms_queue (recipient, body, status, attempts, provider_response, external_id, created_at)
                             VALUES (?, ?, 'queued', 0, ?, ?, NOW())",
                            [$to, $msg, $raw, $mid]
                        );
                        return false;
                    }
                } catch (Throwable $e) {
                    error_log("send_confirmation_code_sms: DB insert after sendSMS failed: " . $e->getMessage());
                    return $ok;
                }
            } catch (Throwable $e) {
                error_log("send_confirmation_code_sms: sendSMS() threw: " . $e->getMessage());
                // fall through to queue fallback
            }
        }

        // Fallback: enqueue the message so the worker can pick it up later
        try {
            $db->query(
                "INSERT INTO sms_queue (recipient, body, status, attempts, created_at)
                 VALUES (?, ?, 'queued', 0, NOW())",
                [$to, $msg]
            );

            if (function_exists('createNotification')) {
                try { createNotification($db, $user_id, 'Confirmation queued', 'A confirmation code was queued for sending to your phone.', 'info', 'verification', $user_id, 'users'); } catch (Throwable $e) {}
            }

            // Windows non-blocking spawn — robust helper
            // Try multiple spawn methods since environments vary (IIS app pool permissions, disabled functions, etc.)
            $php = PHP_BINARY ?: 'php';
            $worker = realpath(__DIR__ . '/../process_queue.php');

            // Log what we'll attempt
            error_log("send_confirmation_code_sms: spawn attempt, PHP_BINARY=" . $php . " worker=" . ($worker ?: 'NOT_FOUND'));

            if ($worker) {
                $spawnOk = false;
                $tried = [];

                // Build escaped command pieces
                $cmdPhpEsc = escapeshellarg($php);
                $cmdWorkerEsc = escapeshellarg($worker);

                // 1) popen + start (Windows)
                if (function_exists('popen')) {
                    try {
                        $cmd = sprintf('start "" /B %s %s', $cmdPhpEsc, $cmdWorkerEsc);
                        $tried[] = $cmd;
                        @pclose(@popen($cmd, 'r'));
                        // We can't reliably confirm start succeeded, but record the attempt
                        $spawnOk = true;
                    } catch (Throwable $e) {
                        $tried[] = 'popen failed: ' . $e->getMessage();
                    }
                }

                // 2) shell_exec fallback
                if (!$spawnOk && function_exists('shell_exec')) {
                    try {
                        $cmd = sprintf('start "" /B %s %s', $cmdPhpEsc, $cmdWorkerEsc);
                        $tried[] = $cmd;
                        @shell_exec($cmd);
                        $spawnOk = true;
                    } catch (Throwable $e) {
                        $tried[] = 'shell_exec failed: ' . $e->getMessage();
                    }
                }

                // 3) proc_open fallback (best-effort)
                if (!$spawnOk && function_exists('proc_open')) {
                    try {
                        $cmd = sprintf('%s %s', $cmdPhpEsc, $cmdWorkerEsc);
                        $tried[] = 'proc_open: ' . $cmd;
                        $des = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
                        $proc = @proc_open($cmd, $des, $pipes);
                        if ($proc !== false) {
                            // close pipes and let process detach
                            if (is_resource($pipes[0])) @fclose($pipes[0]);
                            if (is_resource($pipes[1])) @fclose($pipes[1]);
                            if (is_resource($pipes[2])) @fclose($pipes[2]);
                            @proc_close($proc);
                            $spawnOk = true;
                        } else {
                            $tried[] = 'proc_open returned false';
                        }
                    } catch (Throwable $e) {
                        $tried[] = 'proc_open failed: ' . $e->getMessage();
                    }
                }

                // Final logging of attempts
                if ($spawnOk) {
                    error_log('send_confirmation_code_sms: spawn attempted (success candidate); attempts=' . json_encode($tried));
                } else {
                    error_log('send_confirmation_code_sms: spawn worker failed; attempts=' . json_encode($tried) . ' php=' . $php . ' worker=' . $worker);
                }
            } else {
                error_log('send_confirmation_code_sms: worker not found at expected path: ' . __DIR__ . '/../process_queue.php');
            }

            return true;
        } catch (Throwable $e) {
            error_log("send_confirmation_code_sms enqueue failed: " . $e->getMessage());
            return false;
        }
    }
}