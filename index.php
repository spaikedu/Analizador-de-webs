<?php
session_start();
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/Auth.php';
Auth::requireLogin();

$pageTitle = 'Dashboard';

// Mark stale "running" scans as failed (older than 3 minutes = server killed them)
try {
    DB::query(
        "UPDATE " . TBL_SCANS . " SET status='failed', error_msg='Tiempo de espera agotado', completed_at=NOW()
         WHERE status='running' AND started_at < NOW() - INTERVAL 3 MINUTE"
    );
} catch (Throwable $ignored) {}

// Stats
$totalScans  = DB::fetch("SELECT COUNT(*) as c FROM " . TBL_SCANS)['c'] ?? 0;
$critical    = DB::fetch("SELECT COUNT(*) as c FROM " . TBL_SCANS . " WHERE risk_level='critical' AND status='completed'")['c'] ?? 0;
$high        = DB::fetch("SELECT COUNT(*) as c FROM " . TBL_SCANS . " WHERE risk_level='high' AND status='completed'")['c'] ?? 0;
$medium      = DB::fetch("SELECT COUNT(*) as c FROM " . TBL_SCANS . " WHERE risk_level='medium' AND status='completed'")['c'] ?? 0;
$low         = DB::fetch("SELECT COUNT(*) as c FROM " . TBL_SCANS . " WHERE risk_level IN ('low','info') AND status='completed'")['c'] ?? 0;

// Last 30 scans
$recentScans = DB::fetchAll("SELECT * FROM " . TBL_SCANS . " ORDER BY created_at DESC LIMIT 30");

// Scans by day for chart (last 14 days)
$scansByDay = DB::fetchAll("
    SELECT DATE(created_at) as day, COUNT(*) as total,
    SUM(CASE WHEN risk_level='critical' THEN 1 ELSE 0 END) as criticals
    FROM " . TBL_SCANS . "
    WHERE created_at >= DATE_SUB(NOW(), INTERVAL 14 DAY) AND status='completed'
    GROUP BY DATE(created_at)
    ORDER BY day
");

// Top vulnerabilities
$topVulns = DB::fetchAll("
    SELECT type, severity, COUNT(*) as count
    FROM " . TBL_VULNS . "
    GROUP BY type, severity
    ORDER BY count DESC
    LIMIT 10
");

// Risk distribution
$riskDist = DB::fetchAll("
    SELECT risk_level, COUNT(*) as count
    FROM " . TBL_SCANS . " WHERE status='completed'
    GROUP BY risk_level
");

require_once __DIR__ . '/includes/header.php';
?>

<div class="page-header">
    <div class="page-header-content">
        <h1 class="page-title"><i class="fas fa-chart-line"></i> Dashboard</h1>
        <p class="page-subtitle">Resumen de todos los análisis de seguridad</p>
    </div>
    <a href="/wp-analyzer/scan.php" class="btn btn-primary">
        <i class="fas fa-plus"></i> Nuevo Análisis
    </a>
</div>

<!-- Stats Cards -->
<div class="stats-grid">
    <div class="stat-card">
        <div class="stat-icon stat-icon-blue"><i class="fas fa-radar"></i></div>
        <div class="stat-info">
            <div class="stat-number"><?= number_format($totalScans) ?></div>
            <div class="stat-label">Análisis Totales</div>
        </div>
    </div>
    <div class="stat-card">
        <div class="stat-icon stat-icon-red"><i class="fas fa-skull-crossbones"></i></div>
        <div class="stat-info">
            <div class="stat-number text-critical"><?= $critical ?></div>
            <div class="stat-label">Riesgo Crítico</div>
        </div>
    </div>
    <div class="stat-card">
        <div class="stat-icon stat-icon-orange"><i class="fas fa-fire"></i></div>
        <div class="stat-info">
            <div class="stat-number text-high"><?= $high ?></div>
            <div class="stat-label">Riesgo Alto</div>
        </div>
    </div>
    <div class="stat-card">
        <div class="stat-icon stat-icon-yellow"><i class="fas fa-triangle-exclamation"></i></div>
        <div class="stat-info">
            <div class="stat-number text-medium"><?= $medium ?></div>
            <div class="stat-label">Riesgo Medio</div>
        </div>
    </div>
    <div class="stat-card">
        <div class="stat-icon stat-icon-green"><i class="fas fa-circle-check"></i></div>
        <div class="stat-info">
            <div class="stat-number text-low"><?= $low ?></div>
            <div class="stat-label">Riesgo Bajo</div>
        </div>
    </div>
</div>

<!-- Charts Row -->
<div class="charts-grid">
    <div class="card chart-card">
        <div class="card-header">
            <h3 class="card-title"><i class="fas fa-chart-donut"></i> Distribución de Riesgo</h3>
        </div>
        <div class="card-body chart-body">
            <canvas id="riskChart"></canvas>
        </div>
    </div>
    <div class="card chart-card">
        <div class="card-header">
            <h3 class="card-title"><i class="fas fa-chart-area"></i> Análisis (últimos 14 días)</h3>
        </div>
        <div class="card-body chart-body">
            <canvas id="timelineChart"></canvas>
        </div>
    </div>
    <div class="card chart-card">
        <div class="card-header">
            <h3 class="card-title"><i class="fas fa-chart-bar"></i> Vulnerabilidades Frecuentes</h3>
        </div>
        <div class="card-body chart-body">
            <canvas id="vulnChart"></canvas>
        </div>
    </div>
</div>

<!-- Recent Scans -->
<div class="card mt-6">
    <div class="card-header">
        <h3 class="card-title"><i class="fas fa-clock-rotate-left"></i> Análisis Recientes</h3>
        <div style="display:flex;align-items:center;gap:.75rem;">
            <div style="position:relative;">
                <i class="fas fa-magnifying-glass" style="position:absolute;left:.75rem;top:50%;transform:translateY(-50%);color:#64748b;font-size:13px;pointer-events:none;"></i>
                <input type="text" id="scanSearch" placeholder="Buscar URL..." autocomplete="off"
                    style="background:#0d0d1a;border:1px solid #1e293b;color:#e2e8f0;padding:.4rem .75rem .4rem 2.1rem;border-radius:6px;font-size:13px;width:200px;outline:none;"
                    oninput="filterScans(this.value)">
            </div>
            <span class="card-badge" id="scanCount"><?= count($recentScans) ?> registros</span>
        </div>
    </div>
    <div class="card-body p-0">
        <?php if (empty($recentScans)): ?>
        <div class="empty-state">
            <i class="fas fa-radar empty-icon"></i>
            <p>No hay análisis aún. <a href="/wp-analyzer/scan.php">Crea el primero</a>.</p>
        </div>
        <?php else: ?>
        <div id="noResults" class="empty-state" style="display:none;">
            <i class="fas fa-magnifying-glass empty-icon"></i>
            <p>Sin resultados para esa búsqueda.</p>
        </div>
        <div class="table-wrapper">
            <table class="data-table" id="scansTable">
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Tipo</th>
                        <th>Riesgo</th>
                        <th>WP Ver.</th>
                        <th>Vuln.</th>
                        <th>Estado</th>
                        <th>Fecha</th>
                        <th>Acción</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($recentScans as $scan): ?>
                    <tr data-url="<?= htmlspecialchars(strtolower($scan['url'])) ?>">
                        <td class="td-url">
                            <span class="url-text" title="<?= htmlspecialchars($scan['url']) ?>">
                                <?= htmlspecialchars(parse_url($scan['url'], PHP_URL_HOST) ?? $scan['url']) ?>
                            </span>
                        </td>
                        <td>
                            <span class="badge badge-<?= $scan['scan_type'] === 'auth' ? 'purple' : 'blue' ?>">
                                <i class="fas fa-<?= $scan['scan_type'] === 'auth' ? 'user-lock' : 'eye' ?>"></i>
                                <?= $scan['scan_type'] === 'auth' ? 'Auth' : 'Sin Auth' ?>
                            </span>
                        </td>
                        <td>
                            <span class="risk-badge risk-<?= htmlspecialchars($scan['risk_level'] ?? 'unknown') ?>">
                                <?= strtoupper($scan['risk_level'] ?? 'N/A') ?>
                            </span>
                        </td>
                        <td class="td-mono"><?= htmlspecialchars($scan['wp_version'] ?? 'N/D') ?></td>
                        <td>
                            <div class="vuln-counts">
                                <?php if ($scan['critical_count'] > 0): ?>
                                    <span class="vc vc-c" title="Críticas"><?= $scan['critical_count'] ?>C</span>
                                <?php endif; ?>
                                <?php if ($scan['high_count'] > 0): ?>
                                    <span class="vc vc-h" title="Altas"><?= $scan['high_count'] ?>H</span>
                                <?php endif; ?>
                                <?php if ($scan['medium_count'] > 0): ?>
                                    <span class="vc vc-m" title="Medias"><?= $scan['medium_count'] ?>M</span>
                                <?php endif; ?>
                                <?php if ($scan['total_vulns'] === 0): ?>
                                    <span class="vc vc-ok">0</span>
                                <?php endif; ?>
                            </div>
                        </td>
                        <td>
                            <span class="status-dot status-<?= $scan['status'] ?>"></span>
                            <?= ucfirst($scan['status']) ?>
                        </td>
                        <td class="td-mono text-muted"><?= date('d/m/y H:i', strtotime($scan['created_at'])) ?></td>
                        <td>
                            <?php if ($scan['status'] === 'completed'): ?>
                            <a href="/wp-analyzer/report.php?id=<?= $scan['id'] ?>" class="btn btn-sm btn-ghost">
                                <i class="fas fa-file-magnifying-glass"></i> Ver
                            </a>
                            <a href="/wp-analyzer/api/export.php?id=<?= $scan['id'] ?>" class="btn btn-sm btn-ghost" title="Descargar .txt">
                                <i class="fas fa-download"></i>
                            </a>
                            <?php else: ?>
                            <span class="text-muted text-sm">—</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>
    </div>
</div>

<?php
// Build JS data for charts
$riskLabels  = array_column($riskDist, 'risk_level');
$riskData    = array_column($riskDist, 'count');

$timeLabels  = array_column($scansByDay, 'day');
$timeData    = array_column($scansByDay, 'total');
$timeCrit    = array_column($scansByDay, 'criticals');

$vulnLabels  = array_map(fn($v) => $v['type'], $topVulns);
$vulnData    = array_column($topVulns, 'count');

$pageScript = "
function filterScans(q) {
    q = q.toLowerCase().trim();
    const rows = document.querySelectorAll('#scansTable tbody tr');
    let visible = 0;
    rows.forEach(r => {
        const url = r.dataset.url || '';
        const show = !q || url.includes(q);
        r.style.display = show ? '' : 'none';
        if (show) visible++;
    });
    const badge = document.getElementById('scanCount');
    if (badge) badge.textContent = visible + ' registros';
    const noRes = document.getElementById('noResults');
    const wrapper = document.querySelector('.table-wrapper');
    if (noRes && wrapper) {
        noRes.style.display = visible === 0 ? '' : 'none';
        wrapper.style.display = visible === 0 ? 'none' : '';
    }
}

initDashboard(
    " . json_encode($riskLabels) . ",
    " . json_encode($riskData) . ",
    " . json_encode($timeLabels) . ",
    " . json_encode($timeData) . ",
    " . json_encode($timeCrit) . ",
    " . json_encode($vulnLabels) . ",
    " . json_encode($vulnData) . "
);
";

require_once __DIR__ . '/includes/footer.php';
?>
