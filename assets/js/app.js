/* ============================================================
   WP Security Analyzer — Frontend Logic
   ============================================================ */

'use strict';

// ── Scan Mode Switcher ────────────────────────────────────
const SCOPE_UNAUTH = [
    { icon: 'fa-shield', label: 'Cabeceras HTTP' },
    { icon: 'fa-certificate', label: 'SSL/TLS' },
    { icon: 'fa-wordpress', label: 'Versión WordPress' },
    { icon: 'fa-users', label: 'Enumeración usuarios' },
    { icon: 'fa-file-code', label: 'Archivos sensibles' },
    { icon: 'fa-folder-open', label: 'Directory listing' },
    { icon: 'fa-robot', label: 'robots.txt' },
    { icon: 'fa-plug', label: 'XML-RPC' },
    { icon: 'fa-lock', label: 'wp-login.php' },
    { icon: 'fa-bug', label: 'CVEs & exploits' },
];

const SCOPE_AUTH = [
    ...SCOPE_UNAUTH,
    { icon: 'fa-user-shield', label: 'Panel de administración' },
    { icon: 'fa-rotate', label: 'Actualizaciones pendientes' },
    { icon: 'fa-layer-group', label: 'Plugins instalados + fecha actualización' },
    { icon: 'fa-palette', label: 'Temas instalados + actualizaciones' },
    { icon: 'fa-database', label: 'Versión PHP / MySQL' },
    { icon: 'fa-wordpress', label: 'Versión WordPress (autenticada)' },
    { icon: 'fa-robot', label: 'Indexación motores de búsqueda' },
    { icon: 'fa-bug', label: 'Estado WP_DEBUG' },
    { icon: 'fa-users-gear', label: 'Usuarios administradores' },
];

let currentMode = 'unauth';

function switchMode(mode) {
    currentMode = mode;

    document.querySelectorAll('.mode-tab').forEach(t => {
        t.classList.toggle('active', t.dataset.mode === mode);
    });

    const authFields = document.getElementById('authFields');
    if (authFields) authFields.classList.toggle('hidden', mode !== 'auth');

    // URL field changes meaning in auth mode
    const urlLabel  = document.getElementById('urlFieldLabel');
    const urlHint   = document.getElementById('urlFieldHint');
    const urlInput  = document.getElementById('scanUrl');
    const submitIcon = document.getElementById('submitIcon');
    const submitText = document.getElementById('submitText');

    if (mode === 'auth') {
        if (urlLabel) urlLabel.innerHTML = '<i class="fas fa-sign-in-alt"></i> URL de login WordPress';
        if (urlHint)  urlHint.textContent = 'URL completa de la página de login. Ej: pipoland.es/ep-pipoland o miweb.com/wp-login.php';
        if (urlInput) urlInput.placeholder = 'ejemplo.com/wp-login.php';
        if (submitIcon) submitIcon.className = 'fas fa-plug';
        if (submitText) submitText.textContent = 'Conectar';
    } else {
        if (urlLabel) urlLabel.innerHTML = '<i class="fas fa-globe"></i> URL del sitio WordPress';
        if (urlHint)  urlHint.textContent = 'Introduce el dominio completo sin ruta. Ej: miweb.com';
        if (urlInput) urlInput.placeholder = 'ejemplo.com';
        if (submitIcon) submitIcon.className = 'fas fa-play';
        if (submitText) submitText.textContent = 'Iniciar Análisis';
    }

    renderScope(mode === 'auth' ? SCOPE_AUTH : SCOPE_UNAUTH);
}

function renderScope(items) {
    const grid = document.getElementById('scopeGrid');
    if (!grid) return;
    grid.innerHTML = items.map(item => `
        <div class="scope-item">
            <i class="fas ${item.icon}"></i>
            ${item.label}
        </div>
    `).join('');
}

// ── Scan Form Handler ─────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    renderScope(SCOPE_UNAUTH);

    const form = document.getElementById('scanForm');
    if (form) {
        form.addEventListener('submit', startScan);
    }
});

function startScan(e) {
    e.preventDefault();

    const rawInput = document.getElementById('scanUrl')?.value?.trim() || '';
    const wpUser   = document.getElementById('wpUser')?.value?.trim() || '';
    const wpPass   = document.getElementById('wpPass')?.value || '';

    if (!rawInput) { showFormError('Introduce una URL válida'); return; }

    const progress  = document.getElementById('scanProgress');
    const btn       = document.getElementById('submitBtn');
    const termBody  = document.getElementById('terminalBody');
    if (termBody) termBody.innerHTML = '';

    const prevErr = document.getElementById('scanErrorBanner');
    if (prevErr) prevErr.remove();

    if (currentMode === 'auth') {
        // In auth mode the URL field contains the FULL login URL
        let loginUrl = rawInput.match(/^https?:\/\//i) ? rawInput : 'https://' + rawInput;
        if (!loginUrl.match(/^https?:\/\/.+\..+/i)) {
            showFormError('URL de login inválida. Ej: pipoland.es/ep-pipoland');
            return;
        }
        if (!wpUser || !wpPass) {
            showFormError('Introduce usuario y contraseña');
            return;
        }

        document.getElementById('scanForm').classList.add('hidden');
        progress.classList.remove('hidden');
        document.getElementById('progressUrl').textContent = loginUrl;
        if (btn) btn.disabled = true;

        addTerminalLine(`> Conectando a ${loginUrl}...`);
        addTerminalLine(`> Modo: Autenticado`, 'info');
        runServerScan(loginUrl, wpUser, wpPass, progress, btn);

    } else {
        let url = rawInput.match(/^https?:\/\//i) ? rawInput : 'https://' + rawInput;
        if (!url.match(/^https?:\/\/.+\..+/i)) {
            showFormError('URL no válida. Ejemplo: https://ejemplo.com');
            return;
        }

        document.getElementById('scanForm').classList.add('hidden');
        progress.classList.remove('hidden');
        document.getElementById('progressUrl').textContent = url;
        if (btn) btn.disabled = true;

        addTerminalLine(`> Iniciando análisis de ${url}...`);
        addTerminalLine(`> Modo: Sin autenticación`, 'info');
        runClientScan(url, progress, btn);
    }
}

// ── Mode 2: Server-side authenticated scan ────────────────
function runServerScan(loginUrl, wpUser, wpPass, progress, btn) {
    addTerminalLine(`> Verificando página de login...`);

    const fakeSteps = [
        [10, 2000, 'Comprobando reCAPTCHA y protecciones...'],
        [20, 3000, 'Autenticando en WordPress...'],
        [35, 3000, 'Obteniendo versión PHP, MySQL y WordPress...'],
        [50, 4000, 'Obteniendo fecha actualización plugins (WP.org API)...'],
        [65, 3000, 'Analizando temas instalados...'],
        [75, 2000, 'Verificando actualizaciones de WordPress core...'],
        [83, 2000, 'Verificando WP_DEBUG e indexación SEO...'],
        [91, 2000, 'Obteniendo usuarios administradores...'],
        [96, 1500, 'Cerrando sesión y generando informe...'],
    ];

    let stepIndex = 0;
    let animating = true;

    function animateStep() {
        if (!animating || stepIndex >= fakeSteps.length) return;
        const [pct, delay, msg] = fakeSteps[stepIndex++];
        updateProgress(pct, msg);
        setTimeout(animateStep, delay);
    }
    setTimeout(animateStep, 600);

    const params = new URLSearchParams({ login_url: loginUrl, type: 'auth', wp_user: wpUser, wp_pass: wpPass });

    fetch('/wp-analyzer/api/scan.php?' + params.toString(), { method: 'GET' })
        .then(r => r.text())
        .then(text => {
            animating = false;
            let data;
            try { data = JSON.parse(text); }
            catch { throw new Error('Respuesta inesperada del servidor. Detalle: ' + text.substring(0, 300)); }
            if (data.error) throw new Error(data.error);

            updateProgress(100, 'Análisis completado');
            addTerminalLine(
                `> Completado — Riesgo: ${(data.risk_level || '?').toUpperCase()} | Vulnerabilidades: ${data.total_vulns} (C:${data.critical} H:${data.high})`,
                'success'
            );
            setTimeout(() => { window.location.href = data.redirect; }, 1500);
        })
        .catch(err => {
            animating = false;
            showScanError(err.message, progress, btn);
        });
}

// ── Mode 1: Client-side unauthenticated scan ──────────────
async function runClientScan(url, progress, btn) {
    const base = url.replace(/\/$/, '');
    const results = {};
    const vulns   = [];

    function addVuln(severity, type, title, desc, solution, cve) {
        vulns.push({ severity, type, title, desc: desc || '', solution: solution || '', cve: cve || null });
    }

    // fetch with timeout. noCors=true → no-cors mode (opaque: can't read body/status but url is accessible)
    async function safeFetch(fetchUrl, opts = {}) {
        const controller = new AbortController();
        const tid = setTimeout(() => controller.abort(), opts.timeout || 8000);
        const mode = opts.noCors ? 'no-cors' : 'cors';
        try {
            const r = await fetch(fetchUrl, { signal: controller.signal, mode, credentials: 'omit' });
            clearTimeout(tid);
            if (opts.noCors) {
                // Opaque response — can't read body/status, but CAN read final url and redirected flag
                return { ok: true, status: 0, opaque: true, text: '', headers: {}, url: r.url, redirected: r.redirected };
            }
            let text = '';
            try { text = await r.text(); } catch {}
            const headers = {};
            r.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
            return { ok: r.ok, status: r.status, text, headers, url: r.url, redirected: r.redirected };
        } catch (err) {
            clearTimeout(tid);
            return { ok: false, status: 0, text: '', headers: {}, error: err.message };
        }
    }

    // Server-side proxy for file checks (bypasses browser CORS limitations)
    async function proxyCheck(targetUrl) {
        try {
            const r = await fetch('/wp-analyzer/api/check_file.php?url=' + encodeURIComponent(targetUrl), {
                method: 'GET', credentials: 'same-origin',
            });
            if (!r.ok) return { status: 0, snippet: '' };
            return await r.json();
        } catch {
            return { status: 0, snippet: '' };
        }
    }

    // ── Step 1: Connectivity + SSL + Headers (server-side) ─
    updateProgress(5, 'Verificando conectividad y SSL...');
    addTerminalLine('> Verificando conectividad...');

    // Use site_info.php: gets real IP, SSL cert details, HTTP headers — no CORS limit
    let siteInfo = null;
    try {
        const siResp = await fetch('/wp-analyzer/api/site_info.php?url=' + encodeURIComponent(base + '/'), { credentials: 'same-origin' });
        if (siResp.ok) siteInfo = await siResp.json();
    } catch {}

    // Fallback connectivity check from browser if server-side also blocked
    if (!siteInfo || siteInfo.status === 0) {
        const rootResp = await safeFetch(base + '/', { timeout: 10000, noCors: true });
        if (!rootResp.ok) {
            showScanError('No se puede conectar a ' + base + '. Verifica que el sitio esté activo y accesible desde tu navegador.', progress, btn);
            return;
        }
    } else if (siteInfo.status === 0) {
        // site_info returned 0 — try browser as fallback
        const rootResp = await safeFetch(base + '/', { timeout: 10000, noCors: true });
        if (!rootResp.ok) {
            showScanError('No se puede conectar a ' + base + '. Verifica que el sitio esté activo y accesible desde tu navegador.', progress, btn);
            return;
        }
    }

    const si = siteInfo || {};
    results.connectivity = {
        reachable: true,
        ip:     si.ip     || null,
        server: si.server || null,
    };

    // ── Step 2: SSL + HTTP Headers ────────────────────────
    const isHttps = base.startsWith('https://');
    results.ssl = si.ssl || { enabled: isHttps, days_left: null, issuer: null };
    if (!isHttps) {
        addVuln('medium', 'SSL', 'Sin HTTPS', 'El sitio no usa HTTPS. Los datos viajan sin cifrar.', "Instalar certificado SSL (Let's Encrypt es gratuito) y redirigir HTTP→HTTPS.");
    }

    const h = si.headers || {};
    const hasCors = (si.status || 0) > 0;
    const headersResp = { status: si.status || 0, text: si.snippet || '', headers: h };

    // Build headers in the format report.php expects: {name, present, value}
    const headerDefs = [
        { key: 'x-content-type-options', label: 'X-Content-Type-Options' },
        { key: 'x-frame-options',        label: 'X-Frame-Options' },
        { key: 'content-security-policy',label: 'Content-Security-Policy' },
        { key: 'strict-transport-security', label: 'Strict-Transport-Security' },
        { key: 'referrer-policy',        label: 'Referrer-Policy' },
        { key: 'permissions-policy',     label: 'Permissions-Policy' },
    ];
    results.headers = {};
    if (hasCors) {
        for (const hd of headerDefs) {
            results.headers[hd.label] = { name: hd.label, present: !!h[hd.key], value: h[hd.key] || null };
        }
        if (h['server']) {
            results.connectivity.server = h['server'];
            addVuln('info', 'Cabeceras HTTP', 'Versión de servidor expuesta', 'Cabecera Server: ' + h['server'], 'Ocultar versión del servidor en la configuración del hosting.');
        }
        if (!h['x-content-type-options']) {
            addVuln('low', 'Cabeceras HTTP', 'Falta cabecera X-Content-Type-Options', 'Sin esta cabecera el navegador puede interpretar archivos de forma incorrecta (MIME sniffing).', 'Añadir en .htaccess: Header set X-Content-Type-Options "nosniff"');
        }
        if (!h['x-frame-options'] && !h['content-security-policy']) {
            addVuln('low', 'Cabeceras HTTP', 'Falta cabecera X-Frame-Options', 'Sin esta cabecera el sitio puede ser incrustado en iframes maliciosos (clickjacking).', 'Añadir en .htaccess: Header set X-Frame-Options "SAMEORIGIN"');
        }
        if (isHttps && !h['strict-transport-security']) {
            addVuln('low', 'Cabeceras HTTP', 'Falta cabecera HSTS', 'Sin HSTS el navegador puede ser forzado a usar HTTP inseguro.', 'Añadir en .htaccess: Header set Strict-Transport-Security "max-age=31536000; includeSubDomains"');
        }
    }

    // ── Step 3: WordPress version ─────────────────────────
    updateProgress(20, 'Detectando WordPress y versión...');
    addTerminalLine('> Detectando WordPress...');

    const restResp = await safeFetch(base + '/wp-json/', { timeout: 8000 });
    let wpVersion  = null;
    let wpDetected = false;

    if (restResp.ok && restResp.text) {
        try {
            const json = JSON.parse(restResp.text);
            // Valid WP REST API response has namespaces array
            if (json.namespaces || json.routes) {
                wpDetected = true;
                // generator is "https://wordpress.org/?v=6.5" or "WordPress 6.5"
                const genMatch = json.generator?.match(/(?:\?v=|WordPress )([0-9.]+)/);
                wpVersion = genMatch ? genMatch[1] : null;
                results.wp_version = { version: wpVersion, detected_via: 'rest_api' };
                if (json.description) results.site_name = json.description;
            }
        } catch {}
    }

    // Fallback: meta generator from site_info HTML snippet or proxy body
    if (!wpDetected) {
        const htmlSnippet = (si.snippet || '') + (headersResp.text || '');
        const m = htmlSnippet.match(/<meta name="generator"\s+content="WordPress ([0-9.]+)"/i);
        if (m) { wpDetected = true; wpVersion = m[1]; results.wp_version = { version: wpVersion, detected_via: 'meta_generator' }; }
        else if (si.wp_version_hint) { wpDetected = true; wpVersion = si.wp_version_hint; results.wp_version = { version: wpVersion, detected_via: 'meta_generator' }; }
    }

    // Fallback: detect WP via proxy check of wp-login.php
    if (!wpDetected) {
        const wpLoginProxy = await proxyCheck(base + '/wp-login.php');
        if (wpLoginProxy.status === 200) {
            wpDetected = true;
            results.wp_version = { version: null, detected_via: 'wp-login' };
            addTerminalLine('> WordPress detectado vía wp-login.php', 'info');
        }
    }

    if (!wpDetected) {
        results.wp_version = { version: null };
        addVuln('info', 'WordPress', 'WordPress no detectado o versión oculta', 'No se pudo confirmar que sea WordPress o la versión está oculta.', 'Si es WordPress, ocultar la versión es una buena práctica.');
    } else if (wpVersion) {
        addTerminalLine(`> WordPress ${wpVersion} detectado`, 'info');
        const ver = parseFloat(wpVersion);
        if (ver < 6.0) {
            addVuln('high', 'WordPress Desactualizado', `WordPress ${wpVersion} posiblemente desactualizado`, 'Versiones antiguas de WordPress tienen vulnerabilidades conocidas con exploits públicos.', 'Actualizar WordPress a la última versión estable desde wp-admin/update-core.php.');
        }
        addVuln('info', 'Versión WordPress', `WordPress ${wpVersion} detectado públicamente`, 'La versión de WordPress es visible públicamente en la REST API o en el meta generador.', 'Ocultar versión de WordPress con un plugin de seguridad o añadiendo código al functions.php.');
    } else {
        addTerminalLine('> WordPress detectado (versión oculta)', 'info');
    }

    // ── Step 4: User enumeration ──────────────────────────
    updateProgress(35, 'Verificando enumeración de usuarios...');
    addTerminalLine('> Comprobando enumeración de usuarios...');

    // results.users must be a flat array for report.php
    results.users = [];

    const usersResp = await safeFetch(base + '/wp-json/wp/v2/users?per_page=5', { timeout: 8000 });
    if (usersResp.ok && usersResp.text) {
        try {
            const parsed = JSON.parse(usersResp.text);
            if (Array.isArray(parsed) && parsed.length > 0) {
                results.users = parsed.map(u => ({ id: u.id, name: u.name, slug: u.slug, source: 'REST API' }));
                const names = parsed.map(u => u.slug || u.name).join(', ');
                addVuln('medium', 'Enumeración Usuarios', `${parsed.length} usuario(s) enumerables via REST API`, `Usuarios expuestos: ${names}`, "Deshabilitar enumeración: instalar Wordfence o añadir a functions.php: add_filter('rest_endpoints', ...)");
            }
        } catch {}
    }

    if (results.users.length === 0) {
        // Use no-cors so redirect target URL is readable even without CORS headers
        const authorResp = await safeFetch(base + '/?author=1', { timeout: 6000, noCors: true });
        if (authorResp.ok && authorResp.url && authorResp.url.includes('/author/')) {
            const m = authorResp.url.match(/\/author\/([^/?#]+)/);
            if (m) {
                results.users = [{ id: 1, name: m[1], slug: m[1], source: '/?author=1' }];
                addVuln('medium', 'Enumeración Usuarios', 'Usuario enumerable via /?author=1', `Usuario expuesto: ${m[1]}`, 'Deshabilitar redirección de autor en functions.php.');
            }
        }
    }

    // ── Step 5: Sensitive files + XML-RPC + login ─────────
    updateProgress(52, 'Verificando archivos sensibles y configuración...');
    addTerminalLine('> Comprobando archivos sensibles...');

    const fileChecks = [
        { path: '/xmlrpc.php',           key: 'xmlrpc' },
        { path: '/wp-login.php',         key: 'login' },
        { path: '/robots.txt',           key: 'robots' },
        { path: '/readme.html',          key: 'readme' },
        { path: '/license.txt',          key: 'license' },
        { path: '/.env',                 key: 'env' },
        { path: '/wp-config.php.bak',    key: 'wpconfig_bak' },
        { path: '/wp-config.php.old',    key: 'wpconfig_old' },
        { path: '/debug.log',            key: 'debug_log' },
        { path: '/wp-content/debug.log', key: 'wp_debug_log' },
        { path: '/.git/config',          key: 'git_config' },
        { path: '/wp-content/uploads/',  key: 'uploads_dir' },
    ];

    // Use server-side proxy — bypasses browser CORS limitations, reads real HTTP status
    const fileResults = await Promise.all(
        fileChecks.map(async ({ path, key }) => {
            const r = await proxyCheck(base + path);
            return { key, path, status: r.status, text: (r.snippet || '').substring(0, 500) };
        })
    );

    // xmlrpc and login_page as separate top-level keys (report.php checks these)
    results.xmlrpc      = { accessible: false };
    results.login_page  = { accessible: false };
    // sensitive_files: only exposed items, keyed by path, with {sev, desc, url}
    results.sensitive_files = {};

    for (const r of fileResults) {
        if (r.key === 'xmlrpc' && r.status === 200 && r.text.includes('XML-RPC')) {
            results.xmlrpc = { accessible: true };
            addVuln('medium', 'XML-RPC', 'XML-RPC habilitado', 'XML-RPC permite ataques de fuerza bruta amplificados y pingback DDoS.', 'Desactivar XML-RPC: añadir en .htaccess: <Files xmlrpc.php> deny from all </Files>');
        }
        if (r.key === 'login' && r.status === 200) {
            results.login_page = { accessible: true };
            addVuln('low', 'Login Expuesto', 'wp-login.php accesible públicamente', 'La página de login está expuesta permitiendo ataques de fuerza bruta.', 'Proteger wp-login.php con autenticación HTTP básica o cambiar la URL de login con un plugin.');
        }
        if (r.key === 'env' && r.status === 200 && r.text.length > 10) {
            results.sensitive_files['/.env'] = { sev: 'critical', desc: 'Archivo .env con posibles credenciales expuesto', url: base + '/.env' };
            addVuln('critical', 'Archivo .env Expuesto', 'Archivo .env accesible públicamente', 'El archivo .env puede contener credenciales de base de datos y tokens API.', 'Bloquear acceso: añadir en .htaccess: <Files .env> deny from all </Files>');
        }
        if ((r.key === 'wpconfig_bak' || r.key === 'wpconfig_old') && r.status === 200) {
            results.sensitive_files[r.path] = { sev: 'critical', desc: 'Backup de wp-config.php con credenciales expuesto', url: base + r.path };
            addVuln('critical', 'Backup wp-config Expuesto', `${r.path} accesible públicamente`, 'Una copia de wp-config.php expone las credenciales de base de datos y las claves secretas de WordPress.', 'Eliminar el archivo de backup inmediatamente del servidor.');
        }
        if ((r.key === 'debug_log' || r.key === 'wp_debug_log') && r.status === 200 && r.text.length > 50) {
            results.sensitive_files[r.path] = { sev: 'medium', desc: 'Log de debug con información sensible del servidor', url: base + r.path };
            addVuln('medium', 'Log de Debug Expuesto', `${r.path} accesible públicamente`, 'Los logs de debug pueden contener rutas del servidor y errores SQL.', 'Deshabilitar WP_DEBUG en producción o proteger el log con .htaccess.');
        }
        if (r.key === 'git_config' && r.status === 200 && r.text.includes('[core]')) {
            results.sensitive_files['/.git/config'] = { sev: 'critical', desc: 'Repositorio Git accesible — código fuente descargable', url: base + '/.git/config' };
            addVuln('critical', 'Repositorio Git Expuesto', '.git/config accesible públicamente', 'El repositorio Git es accesible. Un atacante puede descargar todo el código fuente.', 'Bloquear acceso a .git/ inmediatamente en .htaccess.');
        }
        if (r.key === 'uploads_dir' && r.status === 200 && r.text.includes('<')) {
            results.sensitive_files['/wp-content/uploads/'] = { sev: 'low', desc: 'Listado de directorio habilitado en uploads', url: base + '/wp-content/uploads/' };
            addVuln('low', 'Directory Listing', 'Listado de directorio wp-content/uploads/ habilitado', 'El listado de directorios expone la estructura de archivos del sitio.', 'Desactivar directory listing: añadir "Options -Indexes" en .htaccess.');
        }
        if (r.key === 'readme' && r.status === 200) {
            results.sensitive_files['/readme.html'] = { sev: 'medium', desc: 'readme.html revela versión exacta de WordPress', url: base + '/readme.html' };
            addVuln('medium', 'Archivos Sensibles', 'Archivo accesible: /readme.html', 'readme.html revela versión exacta de WordPress', '<files readme.html>\n  deny from all\n</files>');
        }
        if (r.key === 'license' && r.status === 200) {
            results.sensitive_files['/license.txt'] = { sev: 'low', desc: 'license.txt expone información sobre la versión de WordPress', url: base + '/license.txt' };
            addVuln('low', 'Archivos Sensibles', 'Archivo accesible: /license.txt', 'license.txt puede revelar la versión de WordPress.', '<files license.txt>\n  deny from all\n</files>');
        }
        if (r.key === 'robots' && r.status === 200) {
            results.robots_txt = { found: true, content: r.text };
            if (r.text.includes('Disallow: /wp-admin') || r.text.includes('Disallow: /wp-includes')) {
                addVuln('info', 'robots.txt', 'robots.txt revela rutas de WordPress', 'robots.txt muestra rutas internas como /wp-admin o /wp-includes.', 'Revisar robots.txt para no exponer estructura interna innecesaria.');
            }
        }
    }

    // rest_api key — used by ReportGenerator for endpoints section
    results.rest_api = { users_exposed: results.users.length > 0 };

    // ── Step 6: Theme detection ────────────────────────────
    updateProgress(68, 'Detectando tema activo...');
    addTerminalLine('> Detectando tema activo...');

    results.themes = {};
    // Use no-cors HTML fetch to detect theme slug from source
    const htmlNoCors = await safeFetch(base + '/', { timeout: 8000, noCors: true });
    // Try to get theme from cors response body (may have been fetched already)
    const htmlBody = hasCors ? (headersResp.text || '') : '';
    const themeMatch = htmlBody.match(/wp-content\/themes\/([^/'"]+)/);
    if (themeMatch) {
        const slug = themeMatch[1];
        results.themes[slug] = { name: slug, version: null, author: null };
        addTerminalLine(`> Tema detectado: ${slug}`, 'info');
        // Try to get version and author from style.css
        const styleResp = await safeFetch(base + '/wp-content/themes/' + slug + '/style.css', { timeout: 6000 });
        if (styleResp.status === 200 && styleResp.text) {
            const verMatch  = styleResp.text.match(/Version:\s*([^\n\r]+)/i);
            const authMatch = styleResp.text.match(/Author:\s*([^\n\r]+)/i);
            const nameMatch = styleResp.text.match(/Theme Name:\s*([^\n\r]+)/i);
            results.themes[slug].version = verMatch  ? verMatch[1].trim()  : null;
            results.themes[slug].author  = authMatch ? authMatch[1].trim() : null;
            results.themes[slug].name    = nameMatch ? nameMatch[1].trim() : slug;
        }
    }

    // ── Step 7: CVE correlation ────────────────────────────
    updateProgress(80, 'Correlacionando CVEs conocidos...');
    addTerminalLine('> Correlacionando vulnerabilidades conocidas...');

    if (wpVersion && wpVersion !== 'detectado') {
        const ver = parseFloat(wpVersion);
        if (ver < 5.0) {
            addVuln('critical', 'CVE WordPress', `WordPress ${wpVersion} tiene múltiples CVEs críticos`, 'Versiones < 5.0 tienen vulnerabilidades críticas conocidas incluidas XSS, SQLi y RCE.', 'Actualizar urgentemente a la última versión de WordPress.', 'CVE-2019-8942');
        }
    }

    // ── Step 8: Risk calculation ──────────────────────────
    updateProgress(90, 'Calculando nivel de riesgo...');

    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const v of vulns) { const s = v.severity?.toLowerCase(); if (s in counts) counts[s]++; }

    let riskLevel = vulns.length === 0 ? 'info' : 'low';
    if (counts.critical > 0)    riskLevel = 'critical';
    else if (counts.high > 0)   riskLevel = 'high';
    else if (counts.medium > 0) riskLevel = 'medium';
    else if (counts.low > 0)    riskLevel = 'low';

    results.risk = { level: riskLevel, counts };
    addTerminalLine(`> Riesgo: ${riskLevel.toUpperCase()} | Vulns: ${vulns.length} (C:${counts.critical} H:${counts.high} M:${counts.medium})`, 'info');

    // ── Step 9: Save ──────────────────────────────────────
    updateProgress(95, 'Guardando informe...');
    addTerminalLine('> Guardando resultados en el servidor...');

    try {
        const saveResp = await fetch('/wp-analyzer/api/save.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: base, type: 'unauth', results, vulns }),
        });

        const saveText = await saveResp.text();
        let saveData;
        try { saveData = JSON.parse(saveText); }
        catch { throw new Error('Respuesta inesperada del servidor: ' + saveText.substring(0, 200)); }

        if (saveData.error) throw new Error(saveData.error);

        updateProgress(100, 'Análisis completado');
        addTerminalLine(
            `> Completado — Riesgo: ${(saveData.risk_level || riskLevel).toUpperCase()} | Vulnerabilidades: ${saveData.total_vulns} (C:${saveData.critical} H:${saveData.high})`,
            'success'
        );
        setTimeout(() => { window.location.href = saveData.redirect; }, 1500);
    } catch (err) {
        showScanError('Error guardando resultados: ' + err.message, progress, btn);
    }
}

// ── Shared helpers ────────────────────────────────────────
function showScanError(msg, progress, btn) {
    updateProgress(0, 'Error');
    addTerminalLine(`> ERROR: ${msg}`, 'error');

    if (progress) progress.classList.add('hidden');
    const form = document.getElementById('scanForm');
    if (form) form.classList.remove('hidden');
    if (btn) btn.disabled = false;

    let banner = document.getElementById('scanErrorBanner');
    if (!banner) {
        banner = document.createElement('div');
        banner.id = 'scanErrorBanner';
        banner.style.cssText = 'background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.4);color:#fca5a5;padding:1rem 1.2rem;border-radius:8px;margin-bottom:1rem;font-size:13px;line-height:1.5;';
        const container = document.querySelector('.scan-form-container');
        if (container) container.insertBefore(banner, container.firstChild);
    }
    const isTimeout = msg.includes('timed out') || msg.includes('conectar') || msg.includes('activo');
    banner.innerHTML = `<strong style="color:#f87171">⚠ Error en el análisis:</strong><br>${msg}` +
        (isTimeout ? '<br><br><small>Verifica que el sitio esté activo y accesible desde tu navegador.</small>' : '');
    banner.style.display = 'block';
}

function updateProgress(percent, label) {
    const bar = document.getElementById('progressBar');
    const pct = document.getElementById('progressPercent');

    if (percent !== null && percent !== undefined) {
        if (bar) bar.style.width = `${percent}%`;
        if (pct) pct.textContent = `${percent}%`;
    }

    if (label) {
        const cls = percent >= 100 ? 'success' : (percent === 0 ? 'error' : '');
        addTerminalLine(`> ${label}`, cls);
    }
}

function addTerminalLine(text, cls = '') {
    const body = document.getElementById('terminalBody');
    if (!body) return;

    const line = document.createElement('div');
    line.className = `terminal-line ${cls}`;
    line.textContent = text;
    body.appendChild(line);
    body.scrollTop = body.scrollHeight;

    while (body.children.length > 100) {
        body.removeChild(body.firstChild);
    }
}

function showFormError(msg) {
    let el = document.getElementById('formError');
    if (!el) {
        el = document.createElement('div');
        el.id = 'formError';
        el.className = 'alert alert-error';
        el.style.marginBottom = '1rem';
        const form = document.getElementById('scanForm')?.querySelector('.card-body');
        if (form) form.insertBefore(el, form.firstChild);
    }
    el.innerHTML = `<i class="fas fa-circle-exclamation"></i> ${msg}`;
    el.classList.remove('hidden');
    setTimeout(() => el.classList.add('hidden'), 4000);
}

function togglePassField(inputId, btn) {
    const input = document.getElementById(inputId);
    const icon  = btn.querySelector('i');
    if (!input) return;
    if (input.type === 'password') {
        input.type = 'text';
        icon.className = 'fas fa-eye-slash';
    } else {
        input.type = 'password';
        icon.className = 'fas fa-eye';
    }
}

// ── Dashboard Charts ──────────────────────────────────────
function initDashboard(riskLabels, riskData, timeLabels, timeData, timeCrit, vulnLabels, vulnData) {
    const RISK_COLORS = {
        critical: '#ef4444', high: '#f97316',
        medium: '#eab308', low: '#22c55e',
        info: '#38bdf8', unknown: '#64748b',
    };

    // Risk Donut Chart
    const riskCtx = document.getElementById('riskChart');
    if (riskCtx && riskData.length > 0) {
        new Chart(riskCtx, {
            type: 'doughnut',
            data: {
                labels: riskLabels.map(l => l.toUpperCase()),
                datasets: [{
                    data: riskData,
                    backgroundColor: riskLabels.map(l => (RISK_COLORS[l] || '#64748b') + 'cc'),
                    borderColor: riskLabels.map(l => RISK_COLORS[l] || '#64748b'),
                    borderWidth: 1.5,
                    hoverOffset: 6,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '72%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#94a3b8', font: { size: 11 }, padding: 12 },
                    },
                    tooltip: {
                        backgroundColor: '#0d0d1a',
                        borderColor: '#1e293b',
                        borderWidth: 1,
                        titleColor: '#e2e8f0',
                        bodyColor: '#94a3b8',
                    },
                },
            },
        });
    } else if (riskCtx) {
        riskCtx.closest('.chart-card').querySelector('.card-body').innerHTML =
            '<div class="empty-state"><i class="fas fa-chart-pie empty-icon"></i><p>Sin datos aún</p></div>';
    }

    // Timeline Chart
    const timeCtx = document.getElementById('timelineChart');
    if (timeCtx) {
        new Chart(timeCtx, {
            type: 'line',
            data: {
                labels: timeLabels,
                datasets: [
                    {
                        label: 'Total análisis',
                        data: timeData,
                        borderColor: '#00ff9d',
                        backgroundColor: 'rgba(0,255,157,0.08)',
                        fill: true,
                        tension: 0.4,
                        pointBackgroundColor: '#00ff9d',
                        pointRadius: 4,
                    },
                    {
                        label: 'Críticos',
                        data: timeCrit,
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239,68,68,0.06)',
                        fill: true,
                        tension: 0.4,
                        pointBackgroundColor: '#ef4444',
                        pointRadius: 3,
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { labels: { color: '#94a3b8', font: { size: 11 }, padding: 12 } },
                    tooltip: { backgroundColor: '#0d0d1a', borderColor: '#1e293b', borderWidth: 1, titleColor: '#e2e8f0', bodyColor: '#94a3b8' },
                },
                scales: {
                    x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#64748b', font: { size: 11 } } },
                    y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#64748b', font: { size: 11 }, stepSize: 1 } },
                },
            },
        });
    }

    // Vulnerability Bar Chart
    const vulnCtx = document.getElementById('vulnChart');
    if (vulnCtx && vulnData.length > 0) {
        new Chart(vulnCtx, {
            type: 'bar',
            data: {
                labels: vulnLabels.map(l => l.length > 25 ? l.substring(0, 25) + '…' : l),
                datasets: [{
                    label: 'Ocurrencias',
                    data: vulnData,
                    backgroundColor: 'rgba(0,255,157,0.15)',
                    borderColor: '#00ff9d',
                    borderWidth: 1,
                    borderRadius: 4,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: {
                    legend: { display: false },
                    tooltip: { backgroundColor: '#0d0d1a', borderColor: '#1e293b', borderWidth: 1, titleColor: '#e2e8f0', bodyColor: '#94a3b8' },
                },
                scales: {
                    x: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#64748b', font: { size: 11 }, stepSize: 1 } },
                    y: { grid: { display: false }, ticks: { color: '#94a3b8', font: { size: 10 } } },
                },
            },
        });
    }
}
