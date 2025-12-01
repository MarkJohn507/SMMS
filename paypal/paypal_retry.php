<?php
// paypal/paypal_retry.php
// Helper to execute PayPal SDK requests with retries and exponential backoff.
// Place this in paypal/ directory and require it where needed.

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

/**
 * Execute a PayPal SDK HTTP request with retry/backoff for transient errors.
 *
 * @param PayPalCheckoutSdk\Core\PayPalHttpClient $client
 * @param object $request     SDK request object (e.g. OrdersCreateRequest)
 * @param int $maxAttempts    Max attempts (default 4)
 * @param float $initialDelay Initial delay in seconds (default 0.5)
 *
 * @return mixed              SDK response on success
 *
 * @throws Throwable on permanent failure or when retries exhausted
 */
function paypalExecuteWithRetry($client, $request, $maxAttempts = 4, $initialDelay = 0.5) {
    $attempt = 0;
    while (true) {
        $attempt++;
        try {
            // Attempt the SDK call
            return $client->execute($request);
        } catch (\PayPalHttp\HttpException $ph) {
            // Try to determine status code (SDK exposes statusCode on the exception)
            $status = $ph->statusCode ?? $ph->getCode();
            // Consider 429 and 5xx transient
            $isTransient = ($status === 429) || ($status >= 500 && $status < 600);

            // Attempt to read Retry-After header if present
            $retryAfter = null;
            if (method_exists($ph, 'getHeaders')) {
                try {
                    $headers = $ph->getHeaders();
                    if (!empty($headers['retry-after'])) {
                        $retryAfter = (int) $headers['retry-after'];
                    } elseif (!empty($headers['Retry-After'])) {
                        $retryAfter = (int) $headers['Retry-After'];
                    }
                } catch (\Throwable $e) {
                    // ignore header parsing errors
                }
            }

            if (!$isTransient || $attempt >= $maxAttempts) {
                // Permanent or out of retries — rethrow
                throw $ph;
            }

            // Sleep: honor Retry-After if provided, otherwise exponential backoff + jitter
            if (!empty($retryAfter) && is_numeric($retryAfter)) {
                $sleep = max(0.5, (float)$retryAfter);
            } else {
                // exponential backoff with jitter
                $base = $initialDelay * pow(2, $attempt - 1);
                $jitter = (random_int(0, 1000) / 1000) * 0.5; // up to +0.5s
                $sleep = $base + $jitter;
            }

            // Log and wait then retry
            error_log(sprintf('paypalExecuteWithRetry: transient error (status=%s), attempt %d/%d, sleeping %.2fs; message=%s',
                $status, $attempt, $maxAttempts, $sleep, $ph->getMessage()));
            usleep((int)($sleep * 1e6));
            continue;
        } catch (\Throwable $e) {
            // Non-PayPal HTTP exceptions: treat as transient for first attempts, else rethrow
            if ($attempt >= $maxAttempts) throw $e;
            $base = $initialDelay * pow(2, $attempt - 1);
            $jitter = (random_int(0, 1000) / 1000) * 0.5;
            $sleep = $base + $jitter;
            error_log(sprintf('paypalExecuteWithRetry: non-HTTP exception, attempt %d/%d, sleeping %.2fs; message=%s',
                $attempt, $maxAttempts, $sleep, $e->getMessage()));
            usleep((int)($sleep * 1e6));
            continue;
        }
    }
}