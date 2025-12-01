<?php
// config.php - core configuration and DB connection
// BACKUP your original file before replacing.

// ----------------------------
// Basic PHP settings & timezone
// ----------------------------
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Ensure default timezone is set (adjust as needed)
if (!ini_get('date.timezone')) {
    date_default_timezone_set('UTC');
}

// ----------------------------
// Application constants
// ----------------------------
if (!defined('APP_NAME')) define('APP_NAME', 'SMMS');
if (!defined('APP_VERSION')) define('APP_VERSION', '0.1');

// URL used to build absolute links (verification emails etc.)
if (!defined('APP_URL')) {
    // Update to your dev URL. For XAMPP on localhost adjust if your project lives in a subfolder.
    define('APP_URL', 'http://localhost/NEW');
}

// ----------------------------
// Session cookie params & start session
// Safe: only when no session already active, on web SAPI, and before headers have been sent.
// This avoids "headers already sent" warnings when running CLI/debug scripts.
// ----------------------------
if (php_sapi_name() !== 'cli' && session_status() === PHP_SESSION_NONE && !headers_sent()) {
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (isset($_SERVER['SERVER_PORT']) && (string)$_SERVER['SERVER_PORT'] === '443');

    // determine cookie domain from APP_URL if available
    $cookieDomain = '';
    $hostFromAppUrl = parse_url(APP_URL, PHP_URL_HOST);
    if ($hostFromAppUrl) $cookieDomain = $hostFromAppUrl;

    if (defined('PHP_VERSION_ID') && PHP_VERSION_ID >= 70300) {
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'domain' => $cookieDomain,
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
    } else {
        session_set_cookie_params(0, '/', $cookieDomain, $secure, true);
    }

    session_start();
}

// ----------------------------
// Optional service configuration
// ----------------------------

// reCAPTCHA (leave empty to disable on dev)
if (!defined('RECAPTCHA_SITE_KEY')) define('RECAPTCHA_SITE_KEY', '');
if (!defined('RECAPTCHA_SECRET')) define('RECAPTCHA_SECRET', '');

// Mail / SMTP settings (used by includes/mailer.php)
if (!defined('SMTP_HOST')) define('SMTP_HOST', '');
if (!defined('SMTP_PORT')) define('SMTP_PORT', 587);
if (!defined('SMTP_USER')) define('SMTP_USER', '');
if (!defined('SMTP_PASS')) define('SMTP_PASS', '');
if (!defined('MAIL_FROM')) define('MAIL_FROM', 'no-reply@localhost');
if (!defined('MAIL_FROM_NAME')) define('MAIL_FROM_NAME', APP_NAME);

// ----------------------------
// Database connection (adjust host/user/password)
// ----------------------------
define('DB_DSN', 'mysql:host=127.0.0.1;dbname=smms_db;charset=utf8mb4');
define('DB_USER', 'root');
define('DB_PASS', ''); // set your password

//Supports an optional cooldown window if you want to allow re-application after N days.
define('REAPPLY_AFTER_TERMINATION_DAYS', 30);
// ----------------------------
// PayPal configuration (example placeholders — replace if needed)
// ----------------------------
if (!defined('PAYPAL_CLIENT_ID')) define('PAYPAL_CLIENT_ID', 'AVVDRiM8N3_TLTi1EMg6gJYUMgK36K8p05bl_9fyENJlUkqKNcNKIocb0aGIWnyZZIfzb5kaIE9-Ecru');
if (!defined('PAYPAL_CLIENT_SECRET')) define('PAYPAL_CLIENT_SECRET', 'EEoJsymasagGNkJTSrJSpagHLmg7q6-8uaOj20f-bO-kRjX3i9AP3N8xpDfH2aNDjkbPLbY4Ear_TvTL');
if (!defined('PAYPAL_MODE')) define('PAYPAL_MODE', 'sandbox');
if (!defined('PAYPAL_WEBHOOK_ID')) define('PAYPAL_WEBHOOK_ID', '');

// ----------------------------
// Application / Phone rules
// ----------------------------
// Enforce PH-only recipients across the send API. Set to false if you later want to allow other countries.
if (!defined('ALLOW_ONLY_PH_NUMBERS')) define('ALLOW_ONLY_PH_NUMBERS', true);

// PH number normalization/validation constants (accepted input forms)
if (!defined('PH_NUMBER_REGEX')) define('PH_NUMBER_REGEX', '/^(?:\+63|63|0)[0-9]{10}$/'); // accepted input forms: +63XXXXXXXXXX, 63XXXXXXXXXX, 0XXXXXXXXXX
if (!defined('PH_NORMALIZE_PREFIX')) define('PH_NORMALIZE_PREFIX', '+63'); // normalized output prefix

// ----------------------------
// Attempt to load Composer autoload (required for some SDKs)
// ----------------------------
$composerAutoload = __DIR__ . '/vendor/autoload.php';
if (file_exists($composerAutoload)) {
    require_once $composerAutoload;
}

// ----------------------------
// Simple DB wrapper using PDO with fetch / fetchAll helpers
// ----------------------------
class DB {
    private $pdo;
    public function __construct($dsn, $user, $pass) {
        $opt = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ];
        $this->pdo = new PDO($dsn, $user, $pass, $opt);
    }
    public function fetch($sql, $params = []) {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetch();
    }
    public function fetchAll($sql, $params = []) {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }
    public function query($sql, $params = []) {
        $stmt = $this->pdo->prepare($sql);
        return $stmt->execute($params);
    }
    public function lastInsertId() {
        return $this->pdo->lastInsertId();
    }
    public function pdo() { return $this->pdo; }

    // Optional transaction convenience methods
    public function beginTransaction() { return $this->pdo->beginTransaction(); }
    public function commit() { return $this->pdo->commit(); }
    public function rollBack() { return $this->pdo->rollBack(); }
}

try {
    $db = new DB(DB_DSN, DB_USER, DB_PASS);
} catch (Exception $e) {
    // In production you may want to log and show a friendly message instead
    http_response_code(500);
    echo "Database connection failed: " . htmlspecialchars($e->getMessage());
    exit;
}

// ----------------------------
// Load core helpers
// ----------------------------
require_once __DIR__ . '/includes/helpers.php';

// Load phone helpers (normalization + validation) if present
if (file_exists(__DIR__ . '/includes/phone_utils.php')) {
    require_once __DIR__ . '/includes/phone_utils.php';
}