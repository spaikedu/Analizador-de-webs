<?php
session_start();
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/Auth.php';
Auth::requireLogin();

$id   = (int)($_GET['id'] ?? 0);
$scan = DB::fetch("SELECT * FROM " . TBL_SCANS . " WHERE id = ?", [$id]);

if (!$scan) {
    header('Location: /wp-analyzer/');
    exit;
}

$vulns     = DB::fetchAll("SELECT * FROM " . TBL_VULNS . " WHERE scan_id = ? ORDER BY FIELD(severity,'critical','high','medium','low','info')", [$id]);
$scanData  = json_decode($scan['scan_data'] ?? '{}', true) ?? [];
$results   = $scanData['results'] ?? [];
$risk      = $results['risk'] ?? ['level' => 'unknown', 'counts' => []];
$counts    = $risk['counts'] ?? [];

$pageTitle = 'Informe — ' . (parse_url($scan['url'], PHP_URL_HOST) ?? $scan['url']);
require_once __DIR__ . '/includes/header.php';
?>

<div class="page-header">
    <div class="page-header-content">
        <div class="report-header-top">
            <a href="/wp-analyzer/" class="btn btn-ghost btn-sm"><i class="fas fa-arrow-left"></i> Volver</a>
            <div class="report-actions">
                <a href="/wp-analyzer/api/export.php?id=<?= $id ?>" class="btn btn-secondary btn-sm" download>
                    <i class="fas fa-file-lines"></i> Descargar .TXT
                </a>
                <button onclick="generatePDF()" class="btn btn-primary btn-sm">
                    <i class="fas fa-file-pdf"></i> Exportar PDF
                </button>
            </div>
        </div>
        <h1 class="page-title mt-3">
            <i class="fas fa-file-shield"></i>
            Informe: <?= htmlspecialchars(parse_url($scan['url'], PHP_URL_HOST) ?? $scan['url']) ?>
        </h1>
        <div class="report-meta">
            <span class="risk-badge risk-<?= $scan['risk_level'] ?> risk-badge-lg">
                <i class="fas fa-circle-exclamation"></i> <?= strtoupper($scan['risk_level'] ?? 'N/A') ?>
            </span>
            <span class="meta-item"><i class="fas fa-calendar"></i> <?= date('d/m/Y H:i', strtotime($scan['created_at'])) ?></span>
            <span class="meta-item"><i class="fas fa-<?= $scan['scan_type'] === 'auth' ? 'user-lock' : 'eye' ?>"></i> <?= $scan['scan_type'] === 'auth' ? 'Análisis Autenticado' : 'Análisis No Autenticado' ?></span>
        </div>
    </div>
</div>

<!-- Executive Summary -->
<div class="report-summary-grid">
    <div class="summary-vuln-counts">
        <div class="vuln-count-big vc-critical">
            <span class="vcb-number"><?= $counts['critical'] ?? 0 ?></span>
            <span class="vcb-label">CRÍTICAS</span>
        </div>
        <div class="vuln-count-big vc-high">
            <span class="vcb-number"><?= $counts['high'] ?? 0 ?></span>
            <span class="vcb-label">ALTAS</span>
        </div>
        <div class="vuln-count-big vc-medium">
            <span class="vcb-number"><?= $counts['medium'] ?? 0 ?></span>
            <span class="vcb-label">MEDIAS</span>
        </div>
        <div class="vuln-count-big vc-low">
            <span class="vcb-number"><?= $counts['low'] ?? 0 ?></span>
            <span class="vcb-label">BAJAS</span>
        </div>
    </div>
</div>

<!-- Report Content (printable) -->
<div id="reportContent">

<!-- 1. General Info -->
<div class="report-section card">
    <div class="card-header">
        <h3 class="section-title"><span class="section-num">01</span> Información General</h3>
    </div>
    <div class="card-body">
        <div class="info-grid">
            <?php
            $conn = $results['connectivity'] ?? [];
            $ssl  = $results['ssl'] ?? [];
            $wpv  = $results['wp_version'] ?? [];
            $items = [
                ['URL',              $scan['url']],
                ['IP del Servidor',  $conn['ip'] ?? 'N/D'],
                ['Servidor HTTP',    $conn['server'] ?? 'N/D'],
                ['WordPress Versión', $wpv['version'] ?? 'No detectada'],
                ['SSL/HTTPS',        ($ssl['enabled'] ?? false) ? '✓ Activo — Expira en ' . ($ssl['days_left'] ?? '?') . ' días' : '✗ No activo'],
                ['Emisor SSL',       $ssl['issuer'] ?? 'N/D'],
                ['Login accesible',  ($results['login_page']['accessible'] ?? false) ? '⚠ Sí (wp-login.php)' : '✓ No accesible directamente'],
                ['XML-RPC',          ($results['xmlrpc']['accessible'] ?? false) ? '⚠ Activo' : '✓ Deshabilitado'],
            ];
            foreach ($items as [$k, $v]):
            ?>
            <div class="info-item">
                <span class="info-key"><?= htmlspecialchars($k) ?></span>
                <span class="info-val"><?= htmlspecialchars($v ?? 'N/D') ?></span>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
</div>

<!-- 2. Security Headers -->
<div class="report-section card">
    <div class="card-header">
        <h3 class="section-title"><span class="section-num">02</span> Cabeceras de Seguridad HTTP</h3>
    </div>
    <div class="card-body p-0">
        <table class="data-table">
            <thead>
                <tr><th>Cabecera</th><th>Estado</th><th>Valor / Diagnóstico</th></tr>
            </thead>
            <tbody>
            <?php foreach ($results['headers'] ?? [] as $header => $data): ?>
            <tr>
                <td class="td-mono"><?= htmlspecialchars($data['name'] ?? $header) ?></td>
                <td><?php if ($data['present']): ?>
                    <span class="badge badge-green"><i class="fas fa-check"></i> Presente</span>
                <?php else: ?>
                    <span class="badge badge-red"><i class="fas fa-xmark"></i> Faltante</span>
                <?php endif; ?></td>
                <td class="td-mono text-muted text-sm"><?= htmlspecialchars(substr($data['value'] ?? '— No configurada', 0, 80)) ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<!-- 3. Enumeration -->
<div class="report-section card">
    <div class="card-header">
        <h3 class="section-title"><span class="section-num">03</span> Enumeración Detallada</h3>
    </div>
    <div class="card-body">

        <!-- Plugins -->
        <?php $plugins = $results['plugins'] ?? []; if (!empty($plugins)): ?>
        <h4 class="subsection-title"><i class="fas fa-puzzle-piece"></i> Plugins Detectados (<?= count($plugins) ?>)</h4>
        <div class="table-wrapper mb-6">
            <table class="data-table">
                <thead><tr><th>Plugin</th><th>Versión</th><th>Últ. actualización</th><th>Estado</th><th>CVEs Conocidos</th></tr></thead>
                <tbody>
                <?php foreach ($plugins as $slug => $plugin):
                    $pluginCves = array_filter($vulns, fn($v) => !empty($v['cve_id']) && str_contains(strtolower($v['title'] ?? ''), strtolower($slug)));
                ?>
                <tr class="<?= ($plugin['has_update'] ?? false) ? 'row-warning' : '' ?>">
                    <td>
                        <span class="plugin-name"><?= htmlspecialchars($plugin['name'] ?? $slug) ?></span>
                        <span class="text-muted text-xs"><?= htmlspecialchars($slug) ?></span>
                    </td>
                    <td class="td-mono">
                        <?= htmlspecialchars($plugin['version'] ?? 'N/D') ?>
                        <?php if ($plugin['has_update'] ?? false): ?>
                            <span class="badge badge-yellow badge-sm"><i class="fas fa-arrow-up"></i> Update</span>
                        <?php endif; ?>
                    </td>
                    <td class="td-mono text-muted text-sm"><?= htmlspecialchars($plugin['last_updated'] ?? '—') ?></td>
                    <td>
                        <span class="badge badge-<?= ($plugin['active'] ?? true) ? 'green' : 'gray' ?>">
                            <?= ($plugin['active'] ?? true) ? 'Activo' : 'Inactivo' ?>
                        </span>
                    </td>
                    <td>
                        <?php foreach ($pluginCves as $cv): ?>
                            <span class="cve-tag sev-<?= $cv['severity'] ?>"><?= htmlspecialchars($cv['cve_id'] ?? '') ?></span>
                        <?php endforeach; ?>
                        <?php if (empty($pluginCves)): ?><span class="text-muted text-sm">—</span><?php endif; ?>
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>

        <!-- Themes -->
        <?php $themes = $results['themes'] ?? []; if (!empty($themes)): ?>
        <h4 class="subsection-title"><i class="fas fa-palette"></i> Temas Detectados</h4>
        <div class="table-wrapper mb-6">
            <table class="data-table">
                <thead><tr><th>Tema</th><th>Versión</th><th>Autor</th><th>Estado</th></tr></thead>
                <tbody>
                <?php foreach ($themes as $slug => $theme): ?>
                <tr class="<?= ($theme['has_update'] ?? false) ? 'row-warning' : '' ?>">
                    <td>
                        <?= htmlspecialchars($theme['name'] ?? $slug) ?>
                        <?php if ($theme['has_update'] ?? false): ?>
                            <span class="badge badge-yellow badge-sm"><i class="fas fa-arrow-up"></i> Update</span>
                        <?php endif; ?>
                    </td>
                    <td class="td-mono"><?= htmlspecialchars($theme['version'] ?? 'N/D') ?></td>
                    <td class="text-muted"><?= htmlspecialchars($theme['author'] ?? 'N/D') ?></td>
                    <td>
                        <?php if (isset($theme['active'])): ?>
                        <span class="badge badge-<?= $theme['active'] ? 'green' : 'gray' ?>">
                            <?= $theme['active'] ? 'Activo' : 'Inactivo' ?>
                        </span>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>

        <!-- Users -->
        <?php $users = $results['users'] ?? []; if (!empty($users)): ?>
        <h4 class="subsection-title text-danger"><i class="fas fa-users"></i> Usuarios Expuestos sin Autenticación ⚠</h4>
        <div class="table-wrapper mb-4">
            <table class="data-table">
                <thead><tr><th>ID</th><th>Login</th><th>Nombre</th><th>Fuente</th></tr></thead>
                <tbody>
                <?php foreach ($users as $user): ?>
                <tr>
                    <td class="td-mono"><?= htmlspecialchars((string)($user['id'] ?? '?')) ?></td>
                    <td class="td-mono text-warning"><strong><?= htmlspecialchars($user['slug'] ?? '?') ?></strong></td>
                    <td><?= htmlspecialchars($user['name'] ?? '?') ?></td>
                    <td class="text-muted"><?= htmlspecialchars($user['source'] ?? 'REST API') ?></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>

        <!-- Sensitive Files -->
        <?php $sensFiles = $results['sensitive_files'] ?? []; if (!empty($sensFiles)): ?>
        <h4 class="subsection-title text-danger"><i class="fas fa-file-circle-exclamation"></i> Archivos Sensibles Expuestos ⚠</h4>
        <div class="sensitive-files-list">
        <?php foreach ($sensFiles as $path => $data): ?>
            <div class="sensitive-file sev-<?= $data['sev'] ?>">
                <div class="sf-path"><i class="fas fa-file-code"></i> <code><?= htmlspecialchars($path) ?></code></div>
                <div class="sf-desc"><?= htmlspecialchars($data['desc'] ?? '') ?></div>
                <a href="<?= htmlspecialchars($data['url']) ?>" target="_blank" rel="noopener" class="sf-link">
                    <i class="fas fa-external-link"></i> Verificar
                </a>
            </div>
        <?php endforeach; ?>
        </div>
        <?php endif; ?>
    </div>
</div>

<!-- 4. Vulnerabilities -->
<div class="report-section card">
    <div class="card-header">
        <h3 class="section-title"><span class="section-num">04</span> Vulnerabilidades de Seguridad</h3>
        <span class="card-badge"><?= count($vulns) ?> encontradas</span>
    </div>
    <div class="card-body">
        <?php if (empty($vulns)): ?>
            <div class="empty-state">
                <i class="fas fa-shield-check empty-icon text-success"></i>
                <p>No se encontraron vulnerabilidades conocidas.</p>
            </div>
        <?php else: ?>
            <div class="vuln-list">
            <?php foreach ($vulns as $i => $vuln): ?>
            <div class="vuln-item vuln-sev-<?= htmlspecialchars($vuln['severity']) ?>" onclick="toggleVuln(this)">
                <div class="vuln-header">
                    <div class="vuln-header-left">
                        <span class="sev-pill sev-<?= $vuln['severity'] ?>"><?= strtoupper($vuln['severity']) ?></span>
                        <?php if (!empty($vuln['cve_id'])): ?>
                            <span class="cve-pill"><?= htmlspecialchars($vuln['cve_id']) ?></span>
                        <?php endif; ?>
                        <span class="vuln-type"><?= htmlspecialchars($vuln['type'] ?? '') ?></span>
                    </div>
                    <i class="fas fa-chevron-down vuln-chevron"></i>
                </div>
                <div class="vuln-title"><?= htmlspecialchars($vuln['title'] ?? '') ?></div>
                <div class="vuln-body">
                    <div class="vuln-desc">
                        <strong><i class="fas fa-circle-info"></i> Descripción:</strong>
                        <p><?= nl2br(htmlspecialchars($vuln['description'] ?? '')) ?></p>
                    </div>
                    <div class="vuln-solution">
                        <strong><i class="fas fa-wrench"></i> Solución:</strong>
                        <p><?= nl2br(htmlspecialchars($vuln['solution'] ?? '')) ?></p>
                    </div>
                </div>
            </div>
            <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>
</div>

<!-- 5. Elementor Analysis (if present) -->
<?php $elementor = $results['elementor'] ?? null; if ($elementor): ?>
<div class="report-section card">
    <div class="card-header">
        <h3 class="section-title"><span class="section-num">05</span> Análisis Elementor</h3>
        <span class="badge badge-purple">v<?= htmlspecialchars($elementor['version'] ?? 'N/D') ?></span>
    </div>
    <div class="card-body">
        <div class="elementor-checks">
            <div class="check-item <?= ($elementor['uploads_accessible'] ?? false) ? 'check-fail' : 'check-ok' ?>">
                <i class="fas fa-<?= ($elementor['uploads_accessible'] ?? false) ? 'times-circle' : 'check-circle' ?>"></i>
                Directorio uploads <?= ($elementor['uploads_accessible'] ?? false) ? 'accesible públicamente ⚠' : 'protegido ✓' ?>
            </div>
            <?php if (!empty($elementor['pro_version'])): ?>
            <div class="check-item check-info">
                <i class="fas fa-info-circle"></i>
                Elementor Pro detectado: v<?= htmlspecialchars($elementor['pro_version']) ?>
            </div>
            <?php endif; ?>
        </div>
        <?php if (!empty($elementor['recommendations'])): ?>
        <h4 class="subsection-title mt-4">Recomendaciones Elementor</h4>
        <ul class="rec-list">
            <?php foreach ($elementor['recommendations'] as $rec): ?>
            <li><i class="fas fa-arrow-right"></i> <?= htmlspecialchars($rec) ?></li>
            <?php endforeach; ?>
        </ul>
        <?php endif; ?>
    </div>
</div>
<?php endif; ?>

<!-- 6. Auth Findings -->
<?php if ($scan['scan_type'] === 'auth'): ?>
<div class="report-section card">
    <div class="card-header">
        <h3 class="section-title"><span class="section-num">06</span> Hallazgos Autenticados</h3>
    </div>
    <div class="card-body">
        <?php
        $authInfo    = $scanData['auth_success'] ?? false;
        $serverInfo  = $results['server_info'] ?? [];
        $coreUpd     = $results['core_update'] ?? [];
        $siteSettings = $results['site_settings'] ?? [];
        $adminUsers  = $results['admin_users'] ?? [];
        $suspicious  = $results['suspicious_plugins'] ?? [];
        ?>
        <?php if (!$authInfo): ?>
            <div class="alert alert-warning">
                <i class="fas fa-lock"></i>
                <div>
                    <strong>Autenticación fallida</strong>
                    <p><?= htmlspecialchars($results['auth']['error'] ?? $results['auth']['blocker'] ?? 'No se pudo autenticar.') ?></p>
                </div>
            </div>
        <?php else: ?>
            <div class="info-grid">
                <?php if (!empty($serverInfo['php_version'])): ?>
                <div class="info-item">
                    <span class="info-key">PHP Version</span>
                    <span class="info-val <?= version_compare($serverInfo['php_version'], '8.0', '<') ? 'text-warning' : '' ?>">
                        <?= htmlspecialchars($serverInfo['php_version']) ?>
                        <?= version_compare($serverInfo['php_version'], '8.0', '<') ? '⚠ EOL' : '✓' ?>
                    </span>
                </div>
                <?php endif; ?>
                <?php if (!empty($serverInfo['mysql_version'])): ?>
                <div class="info-item">
                    <span class="info-key">MySQL / MariaDB</span>
                    <span class="info-val"><?= htmlspecialchars($serverInfo['mysql_version']) ?></span>
                </div>
                <?php endif; ?>
                <?php if (isset($coreUpd['needed'])): ?>
                <div class="info-item">
                    <span class="info-key">WordPress Core</span>
                    <span class="info-val <?= $coreUpd['needed'] ? 'text-danger' : 'text-success' ?>">
                        <?php if ($coreUpd['needed']): ?>
                            ⚠ Actualización disponible<?= !empty($coreUpd['new_version']) ? ' → v' . htmlspecialchars($coreUpd['new_version']) : '' ?>
                        <?php else: ?>
                            ✓ Al día
                        <?php endif; ?>
                    </span>
                </div>
                <?php endif; ?>
                <?php
                $pluginsWithUpdate = count(array_filter($results['plugins'] ?? [], fn($p) => $p['has_update'] ?? false));
                ?>
                <div class="info-item">
                    <span class="info-key">Plugins sin actualizar</span>
                    <span class="info-val <?= $pluginsWithUpdate > 0 ? 'text-warning' : 'text-success' ?>">
                        <?= $pluginsWithUpdate > 0 ? "⚠ {$pluginsWithUpdate}" : '✓ 0' ?>
                    </span>
                </div>
                <?php $themesInfo = $results['themes_info'] ?? []; ?>
                <?php if (isset($themesInfo['update_count'])): ?>
                <div class="info-item">
                    <span class="info-key">Temas sin actualizar</span>
                    <span class="info-val <?= $themesInfo['update_count'] > 0 ? 'text-warning' : 'text-success' ?>">
                        <?= $themesInfo['update_count'] > 0 ? "⚠ {$themesInfo['update_count']}" : '✓ 0' ?>
                    </span>
                </div>
                <?php endif; ?>
                <?php if (isset($siteSettings['wp_debug'])): ?>
                <div class="info-item">
                    <span class="info-key">WP_DEBUG</span>
                    <span class="info-val <?= $siteSettings['wp_debug'] ? 'text-danger' : 'text-success' ?>">
                        <?= $siteSettings['wp_debug'] ? '⚠ ACTIVO (riesgo en producción)' : '✓ Inactivo' ?>
                    </span>
                </div>
                <?php elseif (array_key_exists('wp_debug', $siteSettings)): ?>
                <div class="info-item">
                    <span class="info-key">WP_DEBUG</span>
                    <span class="info-val text-muted">N/D</span>
                </div>
                <?php endif; ?>
                <?php if (isset($siteSettings['search_engine_blocked'])): ?>
                <div class="info-item">
                    <span class="info-key">Indexación SEO</span>
                    <span class="info-val <?= $siteSettings['search_engine_blocked'] ? 'text-danger' : 'text-success' ?>">
                        <?= $siteSettings['search_engine_blocked'] ? '⚠ Bloqueada (no indexa en Google)' : '✓ Permitida' ?>
                    </span>
                </div>
                <?php endif; ?>
            </div>

            <?php if (!empty($adminUsers)): ?>
            <h4 class="subsection-title mt-4"><i class="fas fa-users-gear"></i> Usuarios Administradores (<?= count($adminUsers) ?>)</h4>
            <div class="table-wrapper mb-4">
                <table class="data-table">
                    <thead><tr><th>ID</th><th>Login</th><th>Nombre</th><th>Email</th></tr></thead>
                    <tbody>
                    <?php foreach ($adminUsers as $admin): ?>
                    <tr>
                        <td class="td-mono text-muted"><?= (int)($admin['id'] ?? 0) ?></td>
                        <td class="td-mono"><strong><?= htmlspecialchars($admin['login'] ?? '?') ?></strong></td>
                        <td><?= htmlspecialchars($admin['name'] ?? '—') ?></td>
                        <td class="text-muted text-sm"><?= htmlspecialchars($admin['email'] ?? '—') ?></td>
                    </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <?php endif; ?>

            <?php if (!empty($suspicious)): ?>
            <h4 class="subsection-title text-danger mt-4"><i class="fas fa-skull"></i> Plugins Sospechosos</h4>
            <?php foreach ($suspicious as $sp): ?>
            <div class="alert alert-error mb-2">
                <i class="fas fa-exclamation-triangle"></i>
                <div>
                    <strong><?= htmlspecialchars($sp['name'] ?? $sp['slug']) ?></strong>
                    <p><?= htmlspecialchars($sp['reason']) ?></p>
                </div>
            </div>
            <?php endforeach; ?>
            <?php endif; ?>
        <?php endif; ?>
    </div>
</div>
<?php endif; ?>

<!-- 7. Recommendations -->
<div class="report-section card">
    <div class="card-header">
        <h3 class="section-title"><span class="section-num">07</span> Recomendaciones Prioritarias</h3>
    </div>
    <div class="card-body">
        <?php
        require_once __DIR__ . '/includes/ReportGenerator.php';
        $recs = [];
        // Extract from report text
        if (!empty($scan['report_text'])) {
            preg_match_all('/\[(\d+)\] (.+)\n\s+(.+)/', $scan['report_text'], $recMatches);
            foreach ($recMatches[2] as $i => $rt) {
                $recs[] = ['num' => $recMatches[1][$i], 'title' => $rt, 'detail' => $recMatches[3][$i] ?? ''];
            }
        }
        ?>
        <div class="rec-cards">
            <?php
            $recPriority = [
                ['icon' => 'fa-bolt', 'color' => 'red',    'title' => 'Actualizar plugins y temas', 'detail' => 'Los plugins/temas sin actualizar son la causa #1 de hackeos en WordPress. Actualizar semanalmente.'],
                ['icon' => 'fa-shield', 'color' => 'blue',  'title' => 'Instalar Wordfence o Sucuri', 'detail' => 'Un WAF (Web Application Firewall) bloquea ataques automáticamente y alerta de intrusiones.'],
                ['icon' => 'fa-lock', 'color' => 'purple', 'title' => 'Proteger wp-login.php', 'detail' => 'Cambiar URL de login + activar 2FA + limitar intentos de login fallidos.'],
                ['icon' => 'fa-database', 'color' => 'green', 'title' => 'Backups automáticos diarios', 'detail' => 'UpdraftPlus a almacenamiento externo. Probar restauración mensualmente.'],
                ['icon' => 'fa-code', 'color' => 'orange', 'title' => 'Deshabilitar editores de código', 'detail' => "En wp-config.php: define('DISALLOW_FILE_EDIT', true);"],
            ];
            ?>
            <?php foreach ($recPriority as $i => $rec): ?>
            <div class="rec-card">
                <div class="rec-num"><?= $i + 1 ?></div>
                <div class="rec-icon rec-icon-<?= $rec['color'] ?>">
                    <i class="fas <?= $rec['icon'] ?>"></i>
                </div>
                <div class="rec-content">
                    <strong><?= htmlspecialchars($rec['title']) ?></strong>
                    <p><?= htmlspecialchars($rec['detail']) ?></p>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
</div>

</div><!-- end #reportContent -->

<script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
<script>
function toggleVuln(el) {
    el.classList.toggle('vuln-expanded');
}

async function generatePDF() {
    const btn = document.querySelector('[onclick="generatePDF()"]');
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generando...';
    btn.disabled = true;

    try {
        const { jsPDF } = window.jspdf;
        const element = document.getElementById('reportContent');
        const canvas = await html2canvas(element, {
            scale: 1.5,
            useCORS: true,
            backgroundColor: '#07070f',
            logging: false,
        });

        const imgData = canvas.toDataURL('image/jpeg', 0.85);
        const pdf = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });

        const pageWidth  = pdf.internal.pageSize.getWidth();
        const pageHeight = pdf.internal.pageSize.getHeight();
        const imgWidth   = pageWidth;
        const imgHeight  = (canvas.height * imgWidth) / canvas.width;
        let   position   = 0;

        pdf.addImage(imgData, 'JPEG', 0, position, imgWidth, imgHeight);

        let heightLeft = imgHeight - pageHeight;
        while (heightLeft > 0) {
            position = heightLeft - imgHeight;
            pdf.addPage();
            pdf.addImage(imgData, 'JPEG', 0, position, imgWidth, imgHeight);
            heightLeft -= pageHeight;
        }

        const host = '<?= htmlspecialchars(parse_url($scan['url'], PHP_URL_HOST) ?? 'report') ?>';
        pdf.save(`WPSecAnalyzer_${host}_<?= date('Ymd', strtotime($scan['created_at'])) ?>.pdf`);
    } catch(e) {
        alert('Error generando PDF: ' + e.message);
    } finally {
        btn.innerHTML = '<i class="fas fa-file-pdf"></i> Exportar PDF';
        btn.disabled = false;
    }
}
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
