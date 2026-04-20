<?php
require_once __DIR__ . '/CveDatabase.php';

class UnauthScanner {

    protected string $url     = '';
    protected array  $results = [];
    protected array  $vulns   = [];
    protected array  $logs    = [];
    protected        $eventCb = null;

    public function __construct(?callable $cb = null) {
        $this->eventCb = $cb;
    }

    protected function emit(string $step, string $msg): void {
        $this->logs[] = ['step' => $step, 'msg' => $msg];
        if ($this->eventCb) {
            ($this->eventCb)(['step' => $step, 'message' => $msg]);
        }
    }

    // Single cURL request
    protected function http(string $url, array $opts = []): array {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_TIMEOUT        => 8,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => $opts['follow'] ?? true,
            CURLOPT_MAXREDIRS      => 3,
            CURLOPT_USERAGENT      => 'Mozilla/5.0 (compatible; WPSecurityAnalyzer/1.0)',
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
        ]);
        if (!empty($opts['nobody'])) curl_setopt($ch, CURLOPT_NOBODY, true);
        if (!empty($opts['post']))   { curl_setopt($ch, CURLOPT_POST, true); curl_setopt($ch, CURLOPT_POSTFIELDS, $opts['post']); }
        if (!empty($opts['nofollow'])) { curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false); }

        $raw   = curl_exec($ch);
        $info  = curl_getinfo($ch);
        $err   = curl_error($ch);
        $hsz   = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);

        if ($raw === false) return ['status' => 0, 'headers' => [], 'body' => '', 'error' => $err, 'info' => $info, 'final_url' => $url];

        return [
            'status'    => (int)$info['http_code'],
            'headers'   => $this->parseHeaders(substr($raw, 0, $hsz)),
            'body'      => substr($raw, $hsz),
            'error'     => $err,
            'info'      => $info,
            'final_url' => $info['url'] ?? $url,
        ];
    }

    // Parallel cURL requests (curl_multi)
    protected function httpMulti(array $urls, bool $headOnly = false): array {
        if (empty($urls)) return [];

        $mh      = curl_multi_init();
        $handles = [];

        foreach ($urls as $key => $url) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER         => true,
                CURLOPT_TIMEOUT        => 6,
                CURLOPT_CONNECTTIMEOUT => 4,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 2,
                CURLOPT_USERAGENT      => 'Mozilla/5.0 (compatible; WPSecurityAnalyzer/1.0)',
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
            ]);
            if ($headOnly) curl_setopt($ch, CURLOPT_NOBODY, true);
            curl_multi_add_handle($mh, $ch);
            $handles[$key] = $ch;
        }

        $running = null;
        do {
            curl_multi_exec($mh, $running);
            if ($running) curl_multi_select($mh, 0.5);
        } while ($running > 0);

        $results = [];
        foreach ($handles as $key => $ch) {
            $raw  = curl_multi_getcontent($ch) ?? '';
            $info = curl_getinfo($ch);
            $hsz  = (int)($info['header_size'] ?? 0);
            $results[$key] = [
                'status'  => (int)$info['http_code'],
                'headers' => $this->parseHeaders(substr($raw, 0, $hsz)),
                'body'    => substr($raw, $hsz),
            ];
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
        }

        curl_multi_close($mh);
        return $results;
    }

    protected function parseHeaders(string $raw): array {
        $h = [];
        foreach (explode("\r\n", $raw) as $line) {
            $pos = strpos($line, ':');
            if ($pos !== false) {
                $key = strtolower(trim(substr($line, 0, $pos)));
                $h[$key] = trim(substr($line, $pos + 1));
            }
        }
        return $h;
    }

    // Main scan entry — Mode 1 (no plugin enumeration)
    public function scan(string $rawUrl): array {
        $url = trim($rawUrl);
        if (!preg_match('#^https?://#i', $url)) $url = 'https://' . $url;
        $this->url     = rtrim($url, '/');
        $this->results = [];
        $this->vulns   = [];

        $this->emit('init', "Iniciando análisis de {$this->url}");

        // Step 1: Connectivity + headers + WP version + login (1 main request + reuse body)
        $this->checkConnectivityAndHeaders();

        // Step 2: SSL certificate
        $this->checkSSL();

        // Step 3: Parallel batch — sensitive files + xmlrpc + rest API + robots
        $this->runParallelChecks();

        // Step 4: User enumeration (uses REST API results)
        $this->enumerateUsers();

        // Step 5: Detect theme from HTML
        $this->detectTheme();

        // Step 6: CVE mapping (no HTTP)
        $this->mapCVEs();
        $this->calculateRisk();

        $this->emit('complete', "Análisis completado.");
        return $this->buildReport();
    }

    protected function checkConnectivityAndHeaders(): void {
        $this->emit('connectivity', "Conectando con {$this->url}...");
        $r = $this->http($this->url);

        if ($r['status'] === 0) {
            $this->results['connectivity'] = ['ok' => false, 'error' => $r['error'] ?: 'Sin respuesta'];
            throw new \RuntimeException("No se puede conectar a {$this->url}: " . ($r['error'] ?: 'host no responde'));
        }

        $h = $r['headers'];
        $this->results['connectivity'] = [
            'ok'        => true,
            'status'    => $r['status'],
            'server'    => $h['server'] ?? 'Desconocido',
            'ip'        => $r['info']['primary_ip'] ?? '',
            'final_url' => $r['final_url'],
        ];

        if ($r['status'] >= 400) {
            throw new \RuntimeException("El servidor devuelve HTTP {$r['status']} — la URL no está disponible.");
        }

        $this->emit('connectivity', "Conectado · Servidor: " . ($h['server'] ?? 'N/A') . " · IP: " . ($r['info']['primary_ip'] ?? 'N/A'));

        // Security headers from same response
        $this->emit('headers', "Analizando cabeceras de seguridad...");
        $required = [
            'content-security-policy'   => ['Content-Security-Policy',        'high'],
            'strict-transport-security' => ['HTTP Strict Transport Security',  'high'],
            'x-frame-options'           => ['X-Frame-Options',                 'medium'],
            'x-content-type-options'    => ['X-Content-Type-Options',          'medium'],
            'referrer-policy'           => ['Referrer-Policy',                 'low'],
        ];
        $headerResults = [];
        foreach ($required as $key => [$name, $sev]) {
            $present = isset($h[$key]);
            $headerResults[$key] = ['present' => $present, 'value' => $h[$key] ?? null, 'name' => $name];
            if (!$present) {
                $this->addVuln($sev, 'Cabeceras HTTP', "Falta: {$name}", "Sin esta cabecera el navegador no puede proteger al usuario.", "Header always set {$key} \"valor-adecuado\"");
            }
        }
        if (!empty($h['x-powered-by'])) {
            $this->addVuln('low', 'Information Disclosure', 'X-Powered-By expone: ' . $h['x-powered-by'], 'Revela tecnología del servidor.', 'Header unset X-Powered-By');
        }
        $this->results['headers'] = $headerResults;
        $missing = count(array_filter($headerResults, fn($v) => !$v['present']));
        $this->emit('headers', "{$missing} cabeceras de seguridad ausentes");

        // WordPress version from same HTML
        $this->emit('wp_version', "Detectando versión de WordPress...");
        $version = null; $sources = [];
        $body = $r['body'];
        if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress ([0-9.]+)/i', $body, $m)) {
            $version = $m[1]; $sources[] = 'meta generator';
            $this->addVuln('low', 'Information Disclosure', "Versión WP {$version} expuesta en meta generator", 'Facilita ataques dirigidos.', "remove_action('wp_head', 'wp_generator');");
        }
        $this->results['wp_version'] = ['version' => $version ?? 'No detectada', 'sources' => $sources];
        $this->emit('wp_version', $version ? "WordPress {$version} detectado" : "Versión no detectada en HTML");

        // Store body for theme detection
        $this->results['_html'] = $body;
    }

    protected function checkSSL(): void {
        $this->emit('ssl', "Verificando certificado SSL...");
        if (!str_starts_with($this->url, 'https://')) {
            $this->results['ssl'] = ['enabled' => false];
            $this->addVuln('high', 'SSL/TLS', 'HTTPS no habilitado', 'Datos viajan en texto plano.', "Instalar Let's Encrypt y forzar HTTPS.");
            return;
        }
        $host = parse_url($this->url, PHP_URL_HOST);
        $ctx  = stream_context_create(['ssl' => ['capture_peer_cert' => true, 'verify_peer' => false, 'verify_peer_name' => false]]);
        $sock = @stream_socket_client("ssl://{$host}:443", $errno, $errstr, 8, STREAM_CLIENT_CONNECT, $ctx);
        if (!$sock) {
            $this->results['ssl'] = ['enabled' => true, 'error' => $errstr];
            return;
        }
        $params   = stream_context_get_params($sock);
        $cert     = openssl_x509_parse($params['options']['ssl']['peer_certificate'] ?? null);
        fclose($sock);
        $expiry   = $cert['validTo_time_t'] ?? 0;
        $daysLeft = $expiry ? (int)ceil(($expiry - time()) / 86400) : null;
        $this->results['ssl'] = [
            'enabled'   => true,
            'issuer'    => $cert['issuer']['O'] ?? 'Desconocido',
            'subject'   => $cert['subject']['CN'] ?? $host,
            'valid_to'  => $expiry ? date('Y-m-d', $expiry) : 'Desconocido',
            'days_left' => $daysLeft,
        ];
        if ($daysLeft !== null && $daysLeft < 30) {
            $sev = $daysLeft < 7 ? 'critical' : 'high';
            $this->addVuln($sev, 'SSL/TLS', "Certificado expira en {$daysLeft} días", "Expira el " . date('Y-m-d', $expiry), 'Renovar el certificado SSL urgentemente.');
        }
        $this->emit('ssl', "SSL OK · Expira: " . ($daysLeft !== null ? "{$daysLeft} días" : '?'));
    }

    protected function runParallelChecks(): void {
        $this->emit('parallel', "Verificando archivos sensibles, XML-RPC y REST API en paralelo...");

        $urls = [
            // Sensitive files
            'debug'       => $this->url . '/debug.log',
            'wpdebug'     => $this->url . '/wp-content/debug.log',
            'configbak'   => $this->url . '/wp-config.php.bak',
            'env'         => $this->url . '/.env',
            'gitconfig'   => $this->url . '/.git/config',
            'phpinfo'     => $this->url . '/phpinfo.php',
            'readme'      => $this->url . '/readme.html',
            'license'     => $this->url . '/license.txt',
            // WordPress checks
            'xmlrpc_head' => $this->url . '/xmlrpc.php',
            'wpjsonusers' => $this->url . '/wp-json/wp/v2/users',
            'robots'      => $this->url . '/robots.txt',
            'login'       => $this->url . '/wp-login.php',
            // Directory listing
            'dir_uploads' => $this->url . '/wp-content/uploads/',
            'dir_plugins' => $this->url . '/wp-content/plugins/',
        ];

        $r = $this->httpMulti($urls);

        // Sensitive files
        $sfMap = [
            'debug'     => ['/debug.log',          'critical', 'Log de errores con datos sensibles y rutas internas'],
            'wpdebug'   => ['/wp-content/debug.log','critical', 'Debug log de WordPress con queries SQL y stack traces'],
            'configbak' => ['/wp-config.php.bak',  'critical', 'Backup de wp-config con credenciales de base de datos'],
            'env'       => ['/.env',               'critical', '.env con API keys, tokens y credenciales'],
            'gitconfig' => ['/.git/config',        'critical', 'Repositorio Git expuesto — código fuente accesible'],
            'phpinfo'   => ['/phpinfo.php',        'high',     'phpinfo() expone configuración PHP completa'],
            'readme'    => ['/readme.html',        'medium',   'readme.html revela versión exacta de WordPress'],
            'license'   => ['/license.txt',        'low',      'Confirma que el sitio usa WordPress'],
        ];
        $foundFiles = [];
        foreach ($sfMap as $key => [$path, $sev, $desc]) {
            if (($r[$key]['status'] ?? 0) === 200) {
                $foundFiles[$path] = ['sev' => $sev, 'desc' => $desc];
                if ($sev !== 'low') {
                    $this->addVuln($sev, 'Archivos Sensibles', "Archivo accesible: {$path}", $desc, "<files " . basename($path) . ">\n  deny from all\n</files>");
                }
                // Try to get WP version from readme if not found yet
                if ($key === 'readme' && ($this->results['wp_version']['version'] ?? '') === 'No detectada') {
                    if (preg_match('/Version ([0-9.]+)/i', $r[$key]['body'] ?? '', $mv)) {
                        $this->results['wp_version']['version'] = $mv[1];
                        $this->results['wp_version']['sources'][] = 'readme.html';
                    }
                }
            }
        }
        $this->results['sensitive_files'] = $foundFiles;
        $this->emit('sensitive_files', count($foundFiles) . " archivos sensibles encontrados");

        // Directory listing
        $dirFound = [];
        foreach (['dir_uploads' => '/wp-content/uploads/', 'dir_plugins' => '/wp-content/plugins/'] as $key => $path) {
            $body = $r[$key]['body'] ?? '';
            if (($r[$key]['status'] ?? 0) === 200 && (str_contains($body, 'Index of') || str_contains($body, 'Directory listing'))) {
                $dirFound[] = $path;
            }
        }
        $this->results['directory_listing'] = $dirFound;
        if (!empty($dirFound)) {
            $this->addVuln('high', 'Directory Listing', 'Listado de directorios activo: ' . implode(', ', $dirFound), 'Los atacantes pueden ver todos los archivos instalados.', 'Añadir: Options -Indexes en .htaccess');
        }

        // XML-RPC — do a POST check now (separate single request for POST)
        $this->emit('xmlrpc', "Verificando XML-RPC...");
        $xmlrpcPost = $this->http($this->url . '/xmlrpc.php', [
            'post' => '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
        ]);
        $xmlrpcActive = $xmlrpcPost['status'] === 200 && str_contains($xmlrpcPost['body'], 'methodResponse');
        $this->results['xmlrpc'] = ['accessible' => $xmlrpcActive, 'status' => $xmlrpcPost['status']];
        if ($xmlrpcActive) {
            $this->addVuln('high', 'XML-RPC', 'XML-RPC habilitado', 'Permite fuerza bruta amplificada vía system.multicall.', '<files xmlrpc.php>\n  deny from all\n</files>');
        }
        $this->emit('xmlrpc', $xmlrpcActive ? "XML-RPC ACTIVO — riesgo alto" : "XML-RPC no activo");

        // Login page
        $loginStatus = $r['login']['status'] ?? 0;
        $loginBody   = $r['login']['body'] ?? '';
        $this->results['login_page'] = ['accessible' => $loginStatus === 200, 'status' => $loginStatus];
        if ($loginStatus === 200) {
            $hasProtection = str_contains($loginBody, 'recaptcha') || str_contains($loginBody, 'two-factor') || str_contains($loginBody, 'loginizer');
            if (!$hasProtection) {
                $this->addVuln('high', 'Brute Force', 'wp-login.php sin protección anti-fuerza bruta', 'No se detecta reCAPTCHA ni 2FA.', 'Instalar "Limit Login Attempts Reloaded" y activar 2FA.');
            } else {
                $this->addVuln('low', 'Brute Force', 'wp-login.php accesible (con protección detectada)', 'La página de login está expuesta pero tiene protección.', 'Considera cambiar URL de login con "WPS Hide Login".');
            }
        }

        // REST API users
        $this->emit('rest_api', "Analizando REST API...");
        $usersBody   = $r['wpjsonusers']['body'] ?? '';
        $usersStatus = $r['wpjsonusers']['status'] ?? 0;
        $this->results['rest_api'] = ['status' => $usersStatus, 'users_exposed' => false, 'users' => []];
        if ($usersStatus === 200) {
            $data = json_decode($usersBody, true);
            if (is_array($data) && !empty($data)) {
                $users = array_map(fn($u) => ['id' => $u['id'] ?? '?', 'slug' => $u['slug'] ?? '?', 'name' => $u['name'] ?? '?'], array_slice($data, 0, 10));
                $this->results['rest_api']['users_exposed'] = true;
                $this->results['rest_api']['users']         = $users;
                $count = count($data);
                $this->addVuln('high', 'Enumeración de Usuarios', "REST API expone {$count} usuario(s)", 'Facilita ataques de fuerza bruta dirigidos.', "add_filter('rest_endpoints', fn(\$e) => (unset(\$e['/wp/v2/users']), \$e));");
                $this->emit('rest_api', "ALERTA: {$count} usuarios expuestos vía REST API");
            }
        }

        // Robots.txt
        $this->emit('robots', "Analizando robots.txt...");
        $robotsStatus = $r['robots']['status'] ?? 0;
        if ($robotsStatus === 200) {
            $disallowed = [];
            foreach (explode("\n", $r['robots']['body'] ?? '') as $line) {
                $line = trim($line);
                if (stripos($line, 'disallow:') === 0) {
                    $disallowed[] = trim(substr($line, 9));
                }
            }
            $revealAdmin = in_array('/wp-admin/', $disallowed) || in_array('/wp-admin', $disallowed);
            $this->results['robots'] = ['exists' => true, 'disallowed' => $disallowed, 'reveal_admin' => $revealAdmin];
            if ($revealAdmin) {
                $this->addVuln('low', 'Information Disclosure', 'robots.txt confirma /wp-admin', 'Confirma la ruta del panel de administración.', 'Evaluar si /wp-admin debe estar en robots.txt.');
            }
        } else {
            $this->results['robots'] = ['exists' => false];
        }
    }

    protected function enumerateUsers(): void {
        $this->emit('users', "Enumerando usuarios via ?author=...");
        $users = $this->results['rest_api']['users'] ?? [];

        // Author redirect check in parallel
        $authorUrls = [];
        for ($i = 1; $i <= 5; $i++) {
            $authorUrls[$i] = $this->url . "/?author={$i}";
        }
        $authorR = $this->httpMulti($authorUrls);

        foreach ($authorR as $i => $ar) {
            $loc = $ar['headers']['location'] ?? '';
            if (in_array($ar['status'], [301, 302]) && preg_match('/\/author\/([^\/]+)/', $loc, $m)) {
                $slug = $m[1];
                $exists = false;
                foreach ($users as $u) { if ($u['slug'] === $slug) { $exists = true; break; } }
                if (!$exists) {
                    $users[] = ['id' => $i, 'slug' => $slug, 'name' => $slug, 'source' => 'author_redirect'];
                }
            }
        }

        if (!empty($users) && empty($this->results['rest_api']['users_exposed'])) {
            $this->addVuln('medium', 'Enumeración de Usuarios', 'Usuarios expuestos vía ?author=N', 'Revela nombres de usuario internos.', 'Bloquear redirección de autor con plugin "Stop User Enumeration".');
        }
        $this->results['users'] = $users;
        $this->emit('users', count($users) . " usuarios identificados");
    }

    protected function detectTheme(): void {
        $this->emit('themes', "Detectando tema activo...");
        $body   = $this->results['_html'] ?? '';
        $themes = [];
        unset($this->results['_html']);

        if (preg_match_all('/wp-content\/themes\/([^\/\'"]+)/i', $body, $matches)) {
            $slugs = array_unique($matches[1]);
            $cssUrls = [];
            foreach ($slugs as $slug) {
                $cssUrls[$slug] = $this->url . "/wp-content/themes/{$slug}/style.css";
            }
            $cssR = $this->httpMulti($cssUrls);
            foreach ($cssR as $slug => $css) {
                $info = ['slug' => $slug, 'name' => $slug, 'version' => null];
                if ($css['status'] === 200) {
                    if (preg_match('/^Theme Name:\s*(.+)$/mi', $css['body'], $mn)) $info['name']    = trim($mn[1]);
                    if (preg_match('/^Version:\s*(.+)$/mi',    $css['body'], $mv)) $info['version'] = trim($mv[1]);
                    if (preg_match('/^Author:\s*(.+)$/mi',     $css['body'], $ma)) $info['author']  = trim($ma[1]);
                }
                $themes[$slug] = $info;
            }
        }
        $this->results['themes'] = $themes;
        $this->emit('themes', count($themes) . " tema(s) detectado(s)");
    }

    protected function mapCVEs(): void {
        $this->emit('cves', "Correlacionando CVEs...");
        $count = 0;
        $wpVer = $this->results['wp_version']['version'] ?? null;
        if ($wpVer && $wpVer !== 'No detectada') {
            foreach (CveDatabase::checkWordPressCore($wpVer) as $cve) {
                $this->addVuln($cve['severity'], 'CVE - WP Core', "[{$cve['cve']}] {$cve['type']} en WordPress {$wpVer}", $cve['desc'], $cve['fix']);
                $count++;
            }
        }
        $this->results['cve_count'] = $count;
        $this->emit('cves', "{$count} CVEs encontrados");
    }

    protected function calculateRisk(): void {
        $counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
        foreach ($this->vulns as $v) {
            $sev = $v['severity'];
            if (isset($counts[$sev])) $counts[$sev]++;
        }
        if ($counts['critical'] > 0)   $level = 'critical';
        elseif ($counts['high'] > 2)   $level = 'critical';
        elseif ($counts['high'] > 0)   $level = 'high';
        elseif ($counts['medium'] > 3) $level = 'high';
        elseif ($counts['medium'] > 0) $level = 'medium';
        else                            $level = 'low';

        $this->results['risk'] = ['level' => $level, 'counts' => $counts];
    }

    protected function addVuln(string $sev, string $type, string $title, string $desc, string $fix, string $cve = ''): void {
        $this->vulns[] = ['severity' => $sev, 'type' => $type, 'title' => $title, 'desc' => $desc, 'solution' => $fix, 'cve' => $cve];
    }

    protected function buildReport(): array {
        return [
            'url'       => $this->url,
            'type'      => 'unauth',
            'results'   => $this->results,
            'vulns'     => $this->vulns,
            'logs'      => $this->logs,
            'scan_time' => date('Y-m-d H:i:s'),
        ];
    }
}
