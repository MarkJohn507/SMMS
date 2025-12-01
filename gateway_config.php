<?php
// gateway_config.php
// Configuration for the SMS gateway for Cloud mode (https://api.sms-gate.app).
// Prefer environment variables for credentials. Edit only if you must hardcode.

// Basic auth credentials (cloud mode). Ideally set these in env vars and do NOT commit.
if (!defined('GATEWAY_BASE'))      define('GATEWAY_BASE', 'https://api.sms-gate.app/3rdparty/v1');
if (!defined('GATEWAY_AUTH_TYPE')) define('GATEWAY_AUTH_TYPE', 'basic');
if (!defined('GATEWAY_USERNAME'))  define('GATEWAY_USERNAME', 'SRL0FM');          // replace if different
if (!defined('GATEWAY_PASSWORD'))  define('GATEWAY_PASSWORD', 'zqyqzqrmmp1acp');

// Use basic auth for cloud mode
if (!defined('GATEWAY_AUTH_TYPE')) define('GATEWAY_AUTH_TYPE', 'basic');

// Bearer/token settings are preserved for reference but not used in Basic auth mode.
if (!defined('GATEWAY_TOKEN')) define('GATEWAY_TOKEN', '');

// Payload style: cloud expects textMessage object for text messages
if (!defined('GATEWAY_PAYLOAD_STYLE')) define('GATEWAY_PAYLOAD_STYLE', 'textMessage');

// If you want to allow non-PH numbers when normalizer rejects, set false.
if (!defined('ALLOW_ONLY_PH_NUMBERS')) define('ALLOW_ONLY_PH_NUMBERS', true);

// HTTP timeout for gateway calls (seconds)
if (!defined('GATEWAY_HTTP_TIMEOUT')) define('GATEWAY_HTTP_TIMEOUT', 60);

// Force sync behaviors (leave as-is unless you know what you need)
if (!defined('GATEWAY_FORCE_SYNC')) define('GATEWAY_FORCE_SYNC', true);

// Webhook settings - optional
if (!defined('GATEWAY_WEBHOOK_SECRET')) define('GATEWAY_WEBHOOK_SECRET', '');
if (!defined('GATEWAY_WEBHOOK_PASSPHRASE')) define('GATEWAY_WEBHOOK_PASSPHRASE', '');
if (!defined('GATEWAY_WEBHOOK_HMAC_ALGO')) define('GATEWAY_WEBHOOK_HMAC_ALGO', 'sha256');
if (!defined('GATEWAY_WEBHOOK_SIG_HEADER')) define('GATEWAY_WEBHOOK_SIG_HEADER', 'X-Gateway-Signature');
if (!defined('GATEWAY_WEBHOOK_TS_HEADER')) define('GATEWAY_WEBHOOK_TS_HEADER', 'X-Gateway-Timestamp');