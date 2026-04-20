<?php
session_start();
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/Auth.php';

if (!Auth::check()) {
    http_response_code(403);
    exit(json_encode(['error' => 'Unauthorized']));
}

session_write_close();

require_once dirname(__DIR__) . '/includes/UnauthScanner.php';
require_once dirname(__DIR__) . '/includes/AuthScanner.php';
require_once dirname(__DIR__) . '/includes/ReportGenerator.php';

header('Content-Type: application/json');
header('Cache-Control: no-cache, no-store');

set_time_limit(120);
ignore_user_abort(false);

// Accept GET or POST (LiteSpeed blocks POST to non-WP PHP files)
$type   = ($_REQUEST['type'] ?? 'unauth') === 'auth' ? 'auth' : 'unauth';
$wpUser = trim($_REQUEST['wp_user'] ?? '');
$wpPass = $_REQUEST['wp_pass'] ?? '';

if ($type === 'auth') {
    // Auth mode: full login URL provided, derive base URL from it
    $loginUrl = trim($_REQUEST['login_url'] ?? $_REQUEST['url'] ?? '');
    if (empty($loginUrl)) {
        http_response_code(400);
        exit(json_encode(['error' => 'URL de login requerida']));
    }
    if (!preg_match('#^https?://#i', $loginUrl)) $loginUrl = 'https://' . $loginUrl;
    if (!filter_var($loginUrl, FILTER_VALIDATE_URL)) {
        http_response_code(400);
        exit(json_encode(['error' => 'URL de login inválida: ' . $loginUrl]));
    }
    $parts = parse_url($loginUrl);
    $url   = $parts['scheme'] . '://' . $parts['host'];
    if (!empty($parts['port'])) $url .= ':' . $parts['port'];
} else {
    $url = trim($_REQUEST['url'] ?? '');
    if (empty($url)) {
        http_response_code(400);
        exit(json_encode(['error' => 'URL requerida']));
    }
    if (!preg_match('#^https?://#i', $url)) $url = 'https://' . $url;
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        http_response_code(400);
        exit(json_encode(['error' => 'URL inválida: ' . $url]));
    }
}

// Create scan record
try {
    $scanId = DB::insert(
        "INSERT INTO " . TBL_SCANS . " (url, scan_type, status, started_at) VALUES (?, ?, 'running', NOW())",
        [$url, $type]
    );
} catch (Throwable $e) {
    http_response_code(500);
    exit(json_encode(['error' => 'Error de base de datos: ' . $e->getMessage()]));
}

try {
    if ($type === 'auth') {
        $scanner = new AuthScanner();
        $report  = $scanner->scanAuth($loginUrl, $wpUser, $wpPass);
    } else {
        $scanner = new UnauthScanner();
        $report  = $scanner->scan($url);
    }

    $reportText = ReportGenerator::generateText($report);
    $reportFile = REPORTS_DIR . 'scan_' . $scanId . '_' . date('Ymd_His') . '.txt';

    if (!is_dir(REPORTS_DIR)) {
        mkdir(REPORTS_DIR, 0755, true);
    }
    @file_put_contents($reportFile, $reportText);

    $results = $report['results'] ?? [];
    $vulns   = $report['vulns']   ?? [];
    $risk    = $results['risk']   ?? ['level' => 'unknown', 'counts' => []];
    $counts  = $risk['counts']    ?? [];

    DB::query(
        "UPDATE " . TBL_SCANS . " SET
            status         = 'completed',
            completed_at   = NOW(),
            risk_level     = ?,
            wp_version     = ?,
            theme_name     = ?,
            server_ip      = ?,
            total_vulns    = ?,
            critical_count = ?,
            high_count     = ?,
            medium_count   = ?,
            low_count      = ?,
            scan_data      = ?,
            report_text    = ?,
            report_file    = ?
         WHERE id = ?",
        [
            $risk['level'],
            $results['wp_version']['version'] ?? null,
            array_key_first($results['themes'] ?? []) ?? null,
            $results['connectivity']['ip'] ?? null,
            count($vulns),
            $counts['critical'] ?? 0,
            $counts['high']     ?? 0,
            $counts['medium']   ?? 0,
            $counts['low']      ?? 0,
            json_encode($report),
            $reportText,
            basename($reportFile),
            $scanId,
        ]
    );

    foreach ($vulns as $vuln) {
        try {
            DB::query(
                "INSERT INTO " . TBL_VULNS . "
                    (scan_id, severity, type, title, description, solution, cve_id, component)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    $scanId,
                    $vuln['severity'],
                    $vuln['type'],
                    $vuln['title'],
                    $vuln['desc']      ?? '',
                    $vuln['solution']  ?? '',
                    $vuln['cve']       ?? null,
                    $vuln['component'] ?? null,
                ]
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
    try {
        DB::query(
            "UPDATE " . TBL_SCANS . " SET status='failed', error_msg=?, completed_at=NOW() WHERE id=?",
            [$e->getMessage(), $scanId]
        );
    } catch (Throwable $ignored) {}

    http_response_code(500);
    echo json_encode([
        'error'   => 'Error en el análisis: ' . $e->getMessage() . ' [' . basename($e->getFile()) . ':' . $e->getLine() . ']',
        'scan_id' => $scanId ?? null,
    ]);
}
