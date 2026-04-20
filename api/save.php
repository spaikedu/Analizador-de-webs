<?php
session_start();
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/Auth.php';
require_once dirname(__DIR__) . '/includes/ReportGenerator.php';

if (!Auth::check()) { http_response_code(403); exit(json_encode(['error' => 'Unauthorized'])); }
session_write_close();

header('Content-Type: application/json');

$raw  = file_get_contents('php://input');
$data = json_decode($raw, true);

if (!$data || empty($data['url'])) {
    http_response_code(400);
    exit(json_encode(['error' => 'Datos inválidos o URL vacía']));
}

$url    = $data['url'];
$type   = $data['type']    ?? 'unauth';
$results = $data['results'] ?? [];
$vulns  = $data['vulns']   ?? [];
$risk   = $results['risk'] ?? ['level' => 'unknown', 'counts' => []];
$counts = $risk['counts']  ?? [];

try {
    $scanId = DB::insert(
        "INSERT INTO " . TBL_SCANS . " (url, scan_type, status, started_at) VALUES (?, ?, 'running', NOW())",
        [$url, $type]
    );

    $data['scan_time'] = date('Y-m-d H:i:s');
    $reportText = ReportGenerator::generateText($data);
    $reportFile = REPORTS_DIR . 'scan_' . $scanId . '_' . date('Ymd_His') . '.txt';
    if (!is_dir(REPORTS_DIR)) mkdir(REPORTS_DIR, 0755, true);
    @file_put_contents($reportFile, $reportText);

    DB::query(
        "UPDATE " . TBL_SCANS . " SET
            status='completed', completed_at=NOW(),
            risk_level=?, wp_version=?, theme_name=?, server_ip=NULL,
            total_vulns=?, critical_count=?, high_count=?, medium_count=?, low_count=?,
            scan_data=?, report_text=?, report_file=?
         WHERE id=?",
        [
            $risk['level'],
            $results['wp_version']['version'] ?? null,
            array_key_first($results['themes'] ?? []) ?? null,
            count($vulns),
            $counts['critical'] ?? 0, $counts['high'] ?? 0,
            $counts['medium'] ?? 0,  $counts['low']  ?? 0,
            json_encode($data), $reportText, basename($reportFile),
            $scanId,
        ]
    );

    foreach ($vulns as $v) {
        try {
            DB::query(
                "INSERT INTO " . TBL_VULNS . " (scan_id, severity, type, title, description, solution, cve_id) VALUES (?,?,?,?,?,?,?)",
                [$scanId, $v['severity'], $v['type'], $v['title'], $v['desc'] ?? '', $v['solution'] ?? '', $v['cve'] ?? null]
            );
        } catch (Throwable $ignored) {}
    }

    echo json_encode([
        'success'     => true,
        'scan_id'     => $scanId,
        'risk_level'  => $risk['level'],
        'total_vulns' => count($vulns),
        'critical'    => $counts['critical'] ?? 0,
        'high'        => $counts['high']     ?? 0,
        'redirect'    => '/wp-analyzer/report.php?id=' . $scanId,
    ]);

} catch (Throwable $e) {
    if (isset($scanId)) {
        try { DB::query("UPDATE ".TBL_SCANS." SET status='failed',error_msg=?,completed_at=NOW() WHERE id=?", [$e->getMessage(), $scanId]); } catch (Throwable $ignored) {}
    }
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}
