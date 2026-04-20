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

$scheme = parse_url($url, PHP_URL_SCHEME);
if (!in_array($scheme, ['http', 'https'], true)) {
    http_response_code(400);
    exit(json_encode(['error' => 'Protocolo no permitido']));
}

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL            => $url,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HEADER         => true,
    CURLOPT_NOBODY         => false,
    CURLOPT_TIMEOUT        => 5,
    CURLOPT_CONNECTTIMEOUT => 3,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS      => 3,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_USERAGENT      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36',
]);
$raw    = curl_exec($ch);
$status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
$hsz    = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
$final  = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) ?? $url;
curl_close($ch);

$rawHeaders = $raw !== false ? substr($raw, 0, $hsz) : '';
$body       = $raw !== false ? substr($raw, $hsz, 512) : '';

// Parse response headers into key→value map
$headers = [];
foreach (explode("\r\n", $rawHeaders) as $line) {
    if (strpos($line, ':') !== false) {
        [$k, $v] = explode(':', $line, 2);
        $headers[strtolower(trim($k))] = trim($v);
    }
}

echo json_encode(['status' => $status, 'url' => $final, 'snippet' => $body, 'headers' => $headers]);
