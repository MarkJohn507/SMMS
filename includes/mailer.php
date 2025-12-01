<?php
// Mailer wrapper: uses PHPMailer if available (Composer). Falls back to PHP mail() if not.
//
// If you want full, reliable SMTP (recommended), install PHPMailer with Composer:
//   composer require phpmailer/phpmailer
//
// Configuration constants expected in config.php:
//   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_FROM, MAIL_FROM_NAME, APP_URL
//

if (!function_exists('sendMail')) {
    // Try to load Composer autoloader (PHPMailer)
    $autoloadPath = __DIR__ . '/../vendor/autoload.php';
    $usePHPMailer = false;

    if (file_exists($autoloadPath)) {
        require_once $autoloadPath;
        // Ensure PHPMailer class exists after autoload
        if (class_exists(\PHPMailer\PHPMailer\PHPMailer::class)) {
            $usePHPMailer = true;
        }
    } else {
        error_log("Mailer: composer autoload not found at {$autoloadPath}. Falling back to mail().");
    }

    if ($usePHPMailer) {
        // PHPMailer-based implementation
        function sendMail(string $to, string $subject, string $htmlBody, string $plainBody = ''): bool {
            try {
                $mail = new \PHPMailer\PHPMailer\PHPMailer(true);
                // Server settings - use SMTP if SMTP_HOST is set
                if (!empty(SMTP_HOST)) {
                    $mail->isSMTP();
                    $mail->Host       = SMTP_HOST;
                    $mail->SMTPAuth   = true;
                    $mail->Username   = SMTP_USER;
                    $mail->Password   = SMTP_PASS;
                    // allow TLS if port indicates it; you may want to make SMPT_SECURE configurable
                    $mail->SMTPSecure = \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
                    $mail->Port       = SMTP_PORT;
                }
                $mail->setFrom(MAIL_FROM, MAIL_FROM_NAME ?? MAIL_FROM);
                $mail->addAddress($to);
                $mail->isHTML(true);
                $mail->Subject = $subject;
                $mail->Body    = $htmlBody;
                $mail->AltBody = $plainBody ?: strip_tags($htmlBody);
                $mail->send();
                return true;
            } catch (\PHPMailer\PHPMailer\Exception $e) {
                error_log("PHPMailer error sending to {$to}: " . $e->getMessage());
                return false;
            } catch (\Throwable $e) {
                error_log("Mailer unexpected error: " . $e->getMessage());
                return false;
            }
        }

        function sendVerificationEmail($db, int $user_id, string $email, string $full_name, string $token): bool {
            $host = rtrim(APP_URL ?? ($_SERVER['HTTP_HOST'] ?? ''), '/');
            $verifyUrl = $host . '/verify_email.php?token=' . urlencode($token);
            $subject = (defined('APP_NAME') ? APP_NAME : 'Application') . ' — Verify your email';
            $html = "<p>Hi " . htmlspecialchars($full_name) . ",</p>";
            $html .= "<p>Please verify your email by clicking the link below:</p>";
            $html .= "<p><a href=\"" . htmlspecialchars($verifyUrl) . "\">Verify my email</a></p>";
            $html .= "<p>If you did not register, please ignore this message.</p>";
            $plain = "Hi {$full_name},\n\nVisit the following link to verify your email:\n{$verifyUrl}\n\nIf you did not register, ignore this message.";

            $sent = sendMail($email, $subject, $html, $plain);
            if (!$sent) {
                error_log("Failed to send verification mail to {$email} (user_id={$user_id})");
            } else {
                try { if (function_exists('logAudit')) logAudit($db, $user_id, 'Sent verification email', 'users', $user_id, null, null); } catch (Throwable $e) { error_log($e->getMessage()); }
            }
            return $sent;
        }

    } else {
        // Fallback implementation that uses PHP mail()
        function sendMail(string $to, string $subject, string $htmlBody, string $plainBody = ''): bool {
            // Build headers
            $from = MAIL_FROM ?? 'no-reply@localhost';
            $fromName = MAIL_FROM_NAME ?? '';
            $headers  = "MIME-Version: 1.0\r\n";
            $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
            $headers .= "From: " . ($fromName ? ($fromName . " <{$from}>") : $from) . "\r\n";
            // Additional headers (Return-Path etc.) could be added here.

            // mail() returns true if accepted by local MTA; doesn't guarantee delivery
            $body = $htmlBody;
            $plain = $plainBody ?: strip_tags($htmlBody);
            // Some mail systems expect CRLF; PHP handles that internally.
            $ok = @mail($to, $subject, $body, $headers);
            if (!$ok) error_log("Fallback mail() failed to send to {$to}.");
            return (bool)$ok;
        }

        function sendVerificationEmail($db, int $user_id, string $email, string $full_name, string $token): bool {
            $host = rtrim(APP_URL ?? ($_SERVER['HTTP_HOST'] ?? ''), '/');
            $verifyUrl = $host . '/verify_email.php?token=' . urlencode($token);
            $subject = (defined('APP_NAME') ? APP_NAME : 'Application') . ' — Verify your email';
            $html = "<p>Hi " . htmlspecialchars($full_name) . ",</p>";
            $html .= "<p>Please verify your email by clicking the link below:</p>";
            $html .= "<p><a href=\"" . htmlspecialchars($verifyUrl) . "\">Verify my email</a></p>";
            $html .= "<p>If you did not register, please ignore this message.</p>";
            $plain = "Hi {$full_name},\n\nVisit the following link to verify your email:\n{$verifyUrl}\n\nIf you did not register, ignore this message.";

            $sent = sendMail($email, $subject, $html, $plain);
            if (!$sent) {
                error_log("Fallback: failed to send verification mail to {$email} (user_id={$user_id}). Consider installing PHPMailer (composer require phpmailer/phpmailer).");
            } else {
                try { if (function_exists('logAudit')) logAudit($db, $user_id, 'Sent verification email (fallback)', 'users', $user_id, null, null); } catch (Throwable $e) { error_log($e->getMessage()); }
            }
            return $sent;
        }
    }
}