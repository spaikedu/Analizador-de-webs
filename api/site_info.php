<?php
session_start();
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/Auth.php';

if (!Auth::check()) { http_response_code(403); exit(json_encode(['error' => 'Unauthorized'])); }
session_write_close();

header('Content-Type: application/json');
header('Cache-Control: no-cache, no-store');

$url = trim($_GET['url'] ?? '');
if (!$url || !filter_var($url, FILTER_VALIDATE_URL)) {
    http_response_code(400);
    exit(json_encode(['error' => 'URL inválida']));
}

$isHttps = str_starts_with($url, 'https://');

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL            => $url,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HEADER         => true,
    CURLOPT_TIMEOUT        => 10,
    CURLOPT_CONNECTTIMEOUT => 5,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS      => 3,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_CERTINFO       => true,
    CURLOPT_USERAGENT      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36',
]);
$raw    = curl_exec($ch);
$info   = curl_getinfo($ch);
$hsz    = (int)($info['header_size'] ?? 0);
$status = (int)($info['http_code'] ?? 0);
$ip     = $info['primary_ip'] ?? null;
$certs  = curl_getinfo($ch, CURLINFO_CERTINFO) ?: [];
curl_close($ch);

$rawHeaders = $raw !== false ? substr($raw, 0, $hsz) : '';
$body       = $raw !== false ? substr($raw, $hsz, 2000) : '';

// Parse headers
$headers = [];
foreach (explode("\r\n", $rawHeaders) as $line) {
    if (strpos($line, ':') !== false) {
        [$k, $v] = explode(':', $line, 2);
        $headers[strtolower(trim($k))] = trim($v);
    }
}

// SSL cert info
$sslDaysLeft = null;
$sslIssuer   = null;
if ($isHttps && !empty($certs)) {
    foreach ($certs as $cert) {
        if (!empty($cert['Expire date'])) {
            try {
                $exp = new DateTime($cert['Expire date']);
                $now = new DateTime();
                $sslDaysLeft = (int)$now->diff($exp)->days;
                if ($exp < $now) $sslDaysLeft = -$sslDaysLeft;
            } catch (Exception $e) {}
        }
        if (!empty($cert['Issuer'])) {
            // Extract O= (organization) from issuer string like "C = US, O = Let's Encrypt, CN = R12"
            if (preg_match('/O\s*=\s*([^,]+)/i', $cert['Issuer'], $m)) {
                $sslIssuer = trim($m[1]);
            } else {
                $sslIssuer = $cert['Issuer'];
            }
        }
        break; // First cert (leaf)
    }
}

// WP version from body (meta generator or REST API generator)
$wpVersion = null;
if (preg_match('/<meta name="generator"\s+content="WordPress ([0-9.]+)"/i', $body, $m)) {
    $wpVersion = $m[1];
}

echo json_encode([
    'status'    => $status,
    'ip'        => $ip ?: null,
    'server'    => $headers['server'] ?? null,
    'headers'   => $headers,
    'ssl'       => [
        'enabled'  => $isHttps && $status > 0,
        'days_left'=> $sslDaysLeft,
        'issuer'   => $sslIssuer,
    ],
    'wp_version_hint' => $wpVersion,
    'snippet'   => $body,
]);
