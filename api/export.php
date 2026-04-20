<?php
session_start();
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/Auth.php';

Auth::requireLogin();

$id   = (int)($_GET['id'] ?? 0);
$scan = DB::fetch("SELECT report_text, url, created_at FROM " . TBL_SCANS . " WHERE id=? AND status='completed'", [$id]);

if (!$scan || empty($scan['report_text'])) {
    http_response_code(404);
    echo 'Informe no encontrado.';
    exit;
}

$host     = parse_url($scan['url'], PHP_URL_HOST) ?? 'report';
$date     = date('Ymd', strtotime($scan['created_at']));
$filename = "WPSecAnalyzer_{$host}_{$date}.txt";

header('Content-Type: text/plain; charset=utf-8');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Content-Length: ' . strlen($scan['report_text']));
header('Cache-Control: no-cache');

echo $scan['report_text'];
