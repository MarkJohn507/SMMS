<?php
// includes/mail.php
// Simple Mailer wrapper. Uses PHPMailer if available (recommended), otherwise falls back to PHP mail().
// Configure SMTP via environment variables or edit the defaults below.

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

if (!function_exists('send_email')) {
    /**
     * send_email(array $opts)
     * Required keys: to (email), subject, html (body)
     * Optional: from, from_name, alt (plain text), attachments (array of file paths)
     */
    function send_email($opts) {
        $to = $opts['to'] ?? null;
        $subject = $opts['subject'] ?? '';
        $html = $opts['html'] ?? '';
        $alt = $opts['alt'] ?? '';
        $from = $opts['from'] ?? getenv('MAIL_FROM') ?: 'no-reply@localhost';
        $from_name = $opts['from_name'] ?? getenv('MAIL_FROM_NAME') ?: 'SMMS';
        $attachments = $opts['attachments'] ?? [];

        if (empty($to) || empty($subject) || empty($html)) {
            return ['ok' => false, 'error' => 'missing_parameters'];
        }

        // If PHPMailer is available, use it
        if (class_exists('\PHPMailer\PHPMailer\PHPMailer')) {
            try {
                $mail = new PHPMailer(true);

                $mail->isSMTP();
                $mail->Host = getenv('SMTP_HOST') ?: 'localhost';
                $mail->SMTPAuth = filter_var(getenv('SMTP_AUTH') ?: false, FILTER_VALIDATE_BOOLEAN);
                if ($mail->SMTPAuth) {
                    $mail->Username = getenv('SMTP_USER') ?: '';
                    $mail->Password = getenv('SMTP_PASS') ?: '';
                    $mail->SMTPSecure = getenv('SMTP_SECURE') ?: ''; // 'ssl' or 'tls'
                    $mail->Port = (int)(getenv('SMTP_PORT') ?: 587);
                } else {
                    // If no auth, still set port if provided
                    $port = getenv('SMTP_PORT');
                    if ($port) $mail->Port = (int)$port;
                }

                $mail->setFrom($from, $from_name);
                $mail->addAddress($to);
                $mail->isHTML(true);
                $mail->Subject = $subject;
                $mail->Body = $html;
                if (!empty($alt)) $mail->AltBody = $alt;

                foreach ($attachments as $a) {
                    if (is_file($a)) $mail->addAttachment($a);
                }

                $mail->send();
                return ['ok' => true];
            } catch (Exception $e) {
                error_log("PHPMailer send error: " . $e->getMessage());
                // fallthrough to mail() fallback
            }
        }

        // Fallback to PHP mail()
        $boundary = md5(time());
        $headers = "From: " . $from_name . " <{$from}>\r\n";
        $headers .= "MIME-Version: 1.0\r\n";
        $headers .= "Content-Type: multipart/alternative; boundary=\"{$boundary}\"\r\n";

        $body = "--{$boundary}\r\n";
        $body .= "Content-Type: text/plain; charset=UTF-8\r\n\r\n";
        $body .= ($alt ?: strip_tags($html)) . "\r\n\r\n";
        $body .= "--{$boundary}\r\n";
        $body .= "Content-Type: text/html; charset=UTF-8\r\n\r\n";
        $body .= $html . "\r\n\r\n";
        $body .= "--{$boundary}--";

        $sent = mail($to, $subject, $body, $headers);
        if ($sent) return ['ok' => true];
        return ['ok' => false, 'error' => 'mail_failed'];
    }
}