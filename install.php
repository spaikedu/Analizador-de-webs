<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/db.php';

$errors  = [];
$success = [];

try {
    $pdo = DB::get();

    $sql = "
    CREATE TABLE IF NOT EXISTS `" . TBL_SCANS . "` (
        `id`            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `url`           VARCHAR(500)  NOT NULL,
        `scan_type`     ENUM('unauth','auth') NOT NULL DEFAULT 'unauth',
        `status`        ENUM('pending','running','completed','failed') NOT NULL DEFAULT 'pending',
        `risk_level`    ENUM('critical','high','medium','low','info','unknown') DEFAULT 'unknown',
        `wp_version`    VARCHAR(50)   DEFAULT NULL,
        `theme_name`    VARCHAR(200)  DEFAULT NULL,
        `server_ip`     VARCHAR(50)   DEFAULT NULL,
        `total_vulns`   INT DEFAULT 0,
        `critical_count` INT DEFAULT 0,
        `high_count`    INT DEFAULT 0,
        `medium_count`  INT DEFAULT 0,
        `low_count`     INT DEFAULT 0,
        `scan_data`     LONGTEXT      DEFAULT NULL COMMENT 'JSON: full scan results',
        `report_text`   LONGTEXT      DEFAULT NULL COMMENT 'Plain text report',
        `report_file`   VARCHAR(300)  DEFAULT NULL COMMENT 'Path to .txt report file',
        `error_msg`     TEXT          DEFAULT NULL,
        `started_at`    DATETIME      DEFAULT NULL,
        `completed_at`  DATETIME      DEFAULT NULL,
        `created_at`    TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_url (url(191)),
        INDEX idx_status (status),
        INDEX idx_risk (risk_level),
        INDEX idx_created (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    ";
    $pdo->exec($sql);
    $success[] = 'Tabla ' . TBL_SCANS . ' creada/verificada.';

    $sql2 = "
    CREATE TABLE IF NOT EXISTS `" . TBL_VULNS . "` (
        `id`            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `scan_id`       INT UNSIGNED NOT NULL,
        `severity`      ENUM('critical','high','medium','low','info') NOT NULL,
        `type`          VARCHAR(100)  NOT NULL,
        `title`         VARCHAR(500)  NOT NULL,
        `description`   TEXT          DEFAULT NULL,
        `solution`      TEXT          DEFAULT NULL,
        `cve_id`        VARCHAR(50)   DEFAULT NULL,
        `component`     VARCHAR(200)  DEFAULT NULL,
        `created_at`    TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_scan_id (scan_id),
        INDEX idx_severity (severity),
        INDEX idx_cve (cve_id),
        CONSTRAINT fk_vuln_scan FOREIGN KEY (scan_id) REFERENCES `" . TBL_SCANS . "` (id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    ";
    $pdo->exec($sql2);
    $success[] = 'Tabla ' . TBL_VULNS . ' creada/verificada.';

    $sql3 = "
    CREATE TABLE IF NOT EXISTS `" . TBL_LOGS . "` (
        `id`            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `scan_id`       INT UNSIGNED NOT NULL,
        `step`          VARCHAR(100)  NOT NULL,
        `message`       TEXT          NOT NULL,
        `created_at`    TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_scan_id (scan_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    ";
    $pdo->exec($sql3);
    $success[] = 'Tabla ' . TBL_LOGS . ' creada/verificada.';

} catch (PDOException $e) {
    $errors[] = 'Error de base de datos: ' . $e->getMessage();
}

// Ensure reports dir exists
if (!is_dir(REPORTS_DIR)) {
    if (mkdir(REPORTS_DIR, 0755, true)) {
        $success[] = 'Directorio reports/ creado.';
    } else {
        $errors[] = 'No se pudo crear el directorio reports/. Créalo manualmente con permisos 755.';
    }
}

// Create .htaccess for reports dir
$htaccessReports = REPORTS_DIR . '.htaccess';
if (!file_exists($htaccessReports)) {
    file_put_contents($htaccessReports, "deny from all\n");
    $success[] = 'Protección .htaccess creada en reports/.';
}

?><!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>WP Analyzer — Instalación</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #07070f; color: #e2e8f0; font-family: 'Inter', sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 2rem; }
        .card { background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 2.5rem; max-width: 600px; width: 100%; }
        h1 { font-size: 1.8rem; color: #00ff9d; margin-bottom: 0.5rem; }
        p  { color: #94a3b8; margin-bottom: 1.5rem; }
        .msg { padding: 0.75rem 1rem; border-radius: 8px; margin-bottom: 0.5rem; font-size: 0.9rem; }
        .success { background: rgba(0,255,157,0.1); border: 1px solid rgba(0,255,157,0.3); color: #00ff9d; }
        .error   { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); color: #ef4444; }
        .btn { display: inline-block; margin-top: 1.5rem; padding: 0.75rem 2rem; background: #00ff9d; color: #07070f; border-radius: 8px; text-decoration: none; font-weight: 700; }
        .warn { background: rgba(245,158,11,0.1); border: 1px solid rgba(245,158,11,0.3); color: #f59e0b; padding: 1rem; border-radius: 8px; margin-top: 1.5rem; font-size: 0.85rem; }
    </style>
</head>
<body>
    <div class="card">
        <h1>⚡ WP Security Analyzer</h1>
        <p>Instalación de tablas de base de datos</p>

        <?php foreach ($success as $msg): ?>
            <div class="msg success">✓ <?= htmlspecialchars($msg) ?></div>
        <?php endforeach; ?>

        <?php foreach ($errors as $msg): ?>
            <div class="msg error">✗ <?= htmlspecialchars($msg) ?></div>
        <?php endforeach; ?>

        <?php if (empty($errors)): ?>
            <a href="/wp-analyzer/login.php" class="btn">Continuar al Login →</a>
            <div class="warn">
                ⚠ <strong>Seguridad:</strong> Elimina o protege install.php tras la instalación:<br>
                <code style="color:#f59e0b">rm install.php</code> o bloquear en .htaccess
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
