<?php
if (!defined('APP_ROOT')) {
    define('APP_ROOT', __DIR__);
}

// === DATABASE ===
define('DB_HOST', 'localhost');
define('DB_NAME', 'wp_6898bf45252005f2');
define('DB_USER', 'wp-6898bf4525200');
define('DB_PASS', 'D0qXRZ6z');
define('DB_CHARSET', 'utf8mb4');

// === APP AUTH ===
define('APP_PASSWORD', 'eduardomartinezmarin'); // Contraseña para acceder a la app
define('APP_SESSION_KEY', 'wpsa_auth');

// === APP INFO ===
define('APP_NAME', 'WP Security Analyzer');
define('APP_VERSION', '1.1.1');

// === SCANNER SETTINGS ===
define('SCAN_TIMEOUT', 8);
define('MAX_REDIRECTS', 5);
define('REPORTS_DIR', APP_ROOT . '/reports/');

// === TABLE PREFIX (different from WP tables) ===
define('TBL_SCANS', 'wpsa_scans');
define('TBL_VULNS', 'wpsa_vulnerabilities');
define('TBL_LOGS',  'wpsa_logs');
