<?php
session_start();
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/Auth.php';
Auth::requireLogin();

$pageTitle = 'Nuevo Análisis';
require_once __DIR__ . '/includes/header.php';
?>

<div class="page-header">
    <div class="page-header-content">
        <h1 class="page-title"><i class="fas fa-radar"></i> Nuevo Análisis</h1>
        <p class="page-subtitle">Analiza una web WordPress de forma completa</p>
    </div>
</div>

<!-- Mode Tabs -->
<div class="mode-tabs">
    <button class="mode-tab active" data-mode="unauth" onclick="switchMode('unauth')">
        <div class="mode-tab-icon"><i class="fas fa-eye"></i></div>
        <div class="mode-tab-content">
            <strong>Modo 1 — Sin autenticación</strong>
            <span>Análisis externo completo</span>
        </div>
    </button>
    <button class="mode-tab" data-mode="auth" onclick="switchMode('auth')">
        <div class="mode-tab-icon"><i class="fas fa-user-lock"></i></div>
        <div class="mode-tab-content">
            <strong>Modo 2 — Con autenticación</strong>
            <span>Análisis interno profundo</span>
        </div>
    </button>
</div>

<!-- Scan Form -->
<div class="scan-form-container">
    <form id="scanForm" class="card">
        <div class="card-body">

            <!-- URL field — label/hint/placeholder change dynamically based on mode -->
            <div class="form-group">
                <label id="urlFieldLabel" class="form-label">
                    <i class="fas fa-globe"></i> URL del sitio WordPress
                </label>
                <div class="input-wrapper">
                    <span class="input-prefix">https://</span>
                    <input type="text" id="scanUrl" name="url" class="form-input input-with-prefix"
                           placeholder="ejemplo.com" autocomplete="off">
                </div>
                <p id="urlFieldHint" class="form-hint">Introduce el dominio completo sin ruta. Ej: miweb.com</p>
            </div>

            <!-- Auth fields (hidden by default) -->
            <div id="authFields" class="auth-fields hidden">
                <div class="form-divider">
                    <span>Credenciales de WordPress</span>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label class="form-label"><i class="fas fa-user"></i> Usuario WordPress</label>
                        <input type="text" id="wpUser" name="wp_user" class="form-input"
                               placeholder="admin" autocomplete="off">
                    </div>
                    <div class="form-group">
                        <label class="form-label"><i class="fas fa-key"></i> Contraseña WordPress</label>
                        <div class="input-wrapper">
                            <input type="password" id="wpPass" name="wp_pass" class="form-input"
                                   placeholder="••••••••" autocomplete="off">
                            <button type="button" class="input-toggle" onclick="togglePassField('wpPass', this)">
                                <i class="fas fa-eye"></i>
                            </button>
                        </div>
                    </div>
                </div>

                <div class="auth-info-box">
                    <i class="fas fa-circle-info"></i>
                    <div>
                        <strong>Información sobre autenticación</strong>
                        <p>Si hay reCAPTCHA en la página de login, el analizador lo detectará y avisará <strong>sin intentar el acceso</strong>. Desactiva temporalmente el plugin de reCAPTCHA antes de escanear.</p>
                    </div>
                </div>
            </div>

            <!-- What will be analyzed -->
            <div class="analysis-scope">
                <div class="scope-header">
                    <i class="fas fa-list-check"></i> Qué se analizará
                </div>
                <div class="scope-grid" id="scopeGrid">
                    <!-- Populated by JS based on mode -->
                </div>
            </div>

            <!-- Submit -->
            <div class="form-actions">
                <button type="submit" id="submitBtn" class="btn btn-primary btn-lg btn-glow">
                    <i class="fas fa-play" id="submitIcon"></i> <span id="submitText">Iniciar Análisis</span>
                </button>
                <p class="form-hint-center">El análisis puede tardar entre 1 y 3 minutos</p>
            </div>
        </div>
    </form>
</div>

<!-- Scan Progress -->
<div id="scanProgress" class="card scan-progress-card hidden">
    <div class="card-header">
        <div class="progress-title">
            <div class="pulse-dot"></div>
            <span>Analizando <strong id="progressUrl"></strong></span>
        </div>
        <div class="progress-percent" id="progressPercent">0%</div>
    </div>
    <div class="card-body">
        <div class="progress-bar-wrapper">
            <div class="progress-bar" id="progressBar" style="width:0%"></div>
        </div>

        <div class="terminal" id="terminal">
            <div class="terminal-header">
                <span class="terminal-dot red"></span>
                <span class="terminal-dot yellow"></span>
                <span class="terminal-dot green"></span>
                <span class="terminal-title">WP Security Scanner</span>
            </div>
            <div class="terminal-body" id="terminalBody">
                <div class="terminal-line">> Iniciando análisis...</div>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
