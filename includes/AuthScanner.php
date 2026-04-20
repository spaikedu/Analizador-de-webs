<?php
require_once __DIR__ . '/UnauthScanner.php';

class AuthScanner extends UnauthScanner {

    private string  $username   = '';
    private string  $password   = '';
    private string  $cookieFile = '';
    private string  $loginPath  = '/wp-login.php';
    private bool    $loggedIn   = false;
    private string  $authError  = '';

    public function scanAuth(string $loginUrl, string $username, string $password): array {
        if (!preg_match('#^https?://#i', $loginUrl)) $loginUrl = 'https://' . $loginUrl;

        // Parse base URL and login path from full login URL
        $parts           = parse_url($loginUrl);
        $this->url       = $parts['scheme'] . '://' . $parts['host'];
        if (!empty($parts['port'])) $this->url .= ':' . $parts['port'];
        $this->loginPath = rtrim($parts['path'] ?? '/wp-login.php', '/') ?: '/wp-login.php';

        $this->username   = $username;
        $this->password   = $password;
        $this->cookieFile = sys_get_temp_dir() . '/wpsa_' . md5($loginUrl . $username . time()) . '.txt';
        $this->results    = [];
        $this->vulns      = [];

        $this->emit('init', "Iniciando análisis autenticado de {$this->url}");

        $this->emit('auth', "Autenticando en WordPress ({$this->loginPath})...");
        $this->authenticate();

        if (!$this->loggedIn) {
            $this->results['auth'] = ['success' => false, 'error' => $this->authError];
            $this->addVuln('info', 'Autenticación', 'No se pudo autenticar', $this->authError, 'Verifica usuario y contraseña. Asegúrate de que no hay 2FA ni CAPTCHA activos.');
            $this->calculateRisk();
            $this->cleanup();
            $report = $this->buildReport();
            $report['type'] = 'auth';
            return $report;
        }

        $this->results['auth'] = ['success' => true];
        $this->emit('auth', "Autenticación correcta.");

        $this->getServerInfo();
        $this->getPlugins();
        $this->getThemes();
        $this->getCoreUpdateStatus();
        $this->getSiteSettings();
        $this->getAdminUsers();
        $this->doLogout();

        $this->calculateRisk();
        $this->cleanup();

        $this->emit('complete', "Análisis autenticado completado.");

        $report = $this->buildReport();
        $report['type']         = 'auth';
        $report['auth_success'] = true;
        return $report;
    }

    private function authHttp(string $url, array $opts = []): array {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_TIMEOUT        => 20,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_USERAGENT      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36',
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_COOKIEJAR      => $this->cookieFile,
            CURLOPT_COOKIEFILE     => $this->cookieFile,
            CURLOPT_HTTPHEADER     => $opts['headers'] ?? [],
        ]);

        if (!empty($opts['post'])) {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $opts['post']);
        }

        $raw  = curl_exec($ch);
        $info = curl_getinfo($ch);
        $err  = curl_error($ch);
        $hsz  = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);

        if ($raw === false) return ['status' => 0, 'headers' => [], 'body' => '', 'error' => $err, 'final_url' => $url];

        return [
            'status'    => (int)$info['http_code'],
            'headers'   => $this->parseHeaders(substr($raw, 0, $hsz)),
            'body'      => substr($raw, $hsz),
            'final_url' => $info['url'] ?? $url,
        ];
    }

    private function authenticate(): void {
        $loginUrl = $this->url . $this->loginPath;

        $init = $this->authHttp($loginUrl);

        if ($init['status'] === 0) {
            $this->authError = 'No se puede conectar a ' . $this->loginPath . ': ' . ($init['error'] ?? 'timeout');
            return;
        }

        $body = strtolower($init['body'] ?? '');

        if (str_contains($body, 'g-recaptcha') || str_contains($body, 'recaptcha')) {
            $this->authError = 'reCAPTCHA detectado en la página de login. Desactiva temporalmente el plugin de reCAPTCHA para el análisis.';
            return;
        }
        if (str_contains($body, 'two-factor') || str_contains($body, '2fa') || str_contains($body, 'totp')) {
            $this->authError = 'Autenticación en dos pasos (2FA) activa. Desactívala temporalmente para el análisis.';
            return;
        }

        $post = http_build_query([
            'log'         => $this->username,
            'pwd'         => $this->password,
            'wp-submit'   => 'Log In',
            'redirect_to' => $this->url . '/wp-admin/',
            'testcookie'  => '1',
        ]);

        // POST without following redirect — check Location header directly.
        // curl converts POST→GET on 302 (RFC behaviour), so following would lose session.
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $loginUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_TIMEOUT        => 20,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $post,
            CURLOPT_USERAGENT      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36',
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_COOKIEJAR      => $this->cookieFile,
            CURLOPT_COOKIEFILE     => $this->cookieFile,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
        ]);
        $raw    = curl_exec($ch);
        $info   = curl_getinfo($ch);
        $hsz    = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $status = (int)$info['http_code'];
        curl_close($ch);

        $rawHeaders = $raw === false ? '' : substr($raw, 0, $hsz);
        $resBody    = $raw === false ? '' : substr($raw, $hsz);

        $location = '';
        if (preg_match('/^Location:\s*(.+)$/im', $rawHeaders, $lm)) {
            $location = trim($lm[1]);
        }

        // Success path 1: server sent 302 → wp-admin directly
        if (($status === 302 || $status === 301) && str_contains($location, 'wp-admin')) {
            $this->loggedIn = true;
            $absLocation = str_starts_with($location, 'http') ? $location : $this->url . $location;
            $this->authHttp($absLocation);
            return;
        }

        // Success path 2: body already has dashboard (rare but possible)
        if (str_contains($resBody, 'wp-admin-bar') || str_contains($resBody, 'wpbody-content')) {
            $this->loggedIn = true;
            return;
        }

        // Verify login by GETting wp-admin with saved cookies.
        // Handles redirect chains (WPS Hide Login, security plugins, etc.) that don't
        // land directly on wp-admin in the first Location header.
        $adminCheck   = $this->authHttp($this->url . '/wp-admin/');
        $adminBody    = $adminCheck['body'] ?? '';
        $adminFinalUrl = $adminCheck['final_url'] ?? '';

        if (str_contains($adminBody, 'wp-admin-bar') || str_contains($adminBody, 'wpbody-content') || str_contains($adminBody, 'dashicons')) {
            $this->loggedIn = true;
            return;
        }

        // Not logged in — determine why
        $lower = strtolower($adminBody . ' ' . $resBody);
        if (str_contains($lower, 'demasiados') || str_contains($lower, 'too many') || str_contains($lower, 'minutos') || str_contains($lower, 'blocked')) {
            $this->authError = 'IP bloqueada por exceso de intentos (Limit Login Attempts). Desbloquea desde wp-admin o espera unos minutos.';
        } elseif (str_contains($adminFinalUrl, 'login') || str_contains($adminFinalUrl, ltrim($this->loginPath, '/'))) {
            $this->authError = 'Credenciales incorrectas — wp-admin redirige al login. Verifica usuario y contraseña.';
        } else {
            $this->authError = 'Login fallido. HTTP POST→' . $status . ($location ? ' [' . $location . ']' : '') . '. wp-admin final: ' . $adminFinalUrl;
        }
    }

    private function getServerInfo(): void {
        $this->emit('server_info', "Obteniendo versión PHP, MySQL y WordPress...");

        $r    = $this->authHttp($this->url . '/wp-admin/site-health.php');
        $body = $r['body'] ?? '';

        $php   = null;
        $mysql = null;
        $wp    = null;

        if (preg_match('/PHP\s+(\d+\.\d+[\.\d]*)/i', $body, $m))   $php   = $m[1];
        if (preg_match('/MySQL\s+(\d+\.\d+[\.\d]*)/i', $body, $m)) $mysql = $m[1];
        if (preg_match('/MariaDB\s+(\d+\.\d+[\.\d]*)/i', $body, $m)) $mysql = 'MariaDB ' . $m[1];

        // WP version from REST API generator field
        $health = $this->authHttp($this->url . '/wp-json/wp/v2/');
        $hbody  = $health['body'] ?? '';
        if (preg_match('/"generator":"https:\/\/wordpress\.org\/\?v=([0-9.]+)"/i', $hbody, $m)) {
            $wp = $m[1];
        } elseif (preg_match('/"generator":"WordPress ([0-9.]+)"/i', $hbody, $m)) {
            $wp = $m[1];
        }

        // Fallback PHP from dashboard
        if (!$php) {
            $dash = $this->authHttp($this->url . '/wp-admin/');
            if (preg_match('/PHP\s+(\d+\.\d+[\.\d]*)/i', $dash['body'] ?? '', $m)) $php = $m[1];
        }

        $this->results['server_info'] = [
            'php_version'   => $php,
            'mysql_version' => $mysql,
            'wp_version'    => $wp,
        ];

        if ($wp) {
            $this->results['wp_version'] = ['version' => $wp, 'detected_via' => 'authenticated'];
        }

        if ($php) {
            $this->emit('server_info', "PHP {$php}" . ($mysql ? " · {$mysql}" : '') . ($wp ? " · WP {$wp}" : ''));
            if (version_compare($php, '8.0', '<')) {
                $this->addVuln('high', 'PHP Desactualizado', "PHP {$php} sin soporte de seguridad",
                    'PHP < 8.0 llegó a fin de vida y no recibe parches de seguridad.',
                    'Actualizar PHP a 8.1 o superior en el panel de hosting.');
            }
        } else {
            $this->emit('server_info', "Versión PHP no detectada en site-health" . ($wp ? " · WP {$wp}" : ''));
        }
    }

    private function getPlugins(): void {
        $this->emit('plugins_auth', "Obteniendo lista de plugins instalados...");
        $r    = $this->authHttp($this->url . '/wp-admin/plugins.php');
        $body = $r['body'] ?? '';

        if (empty($body) || $r['status'] !== 200) {
            $this->emit('plugins_auth', "No se pudo acceder a plugins.php (status: {$r['status']})");
            return;
        }

        $plugins    = [];
        $needUpdate = [];

        preg_match_all('/<tr[^>]+data-slug="([^"]+)"[^>]*>(.*?)<\/tr>/si', $body, $rows);

        foreach ($rows[1] as $i => $slug) {
            $row = $rows[2][$i];

            $name = $slug;
            if (preg_match('/<strong[^>]*><a[^>]*>([^<]+)<\/a>/i', $row, $nm)) {
                $name = trim(strip_tags($nm[1]));
            } elseif (preg_match('/<strong[^>]*>([^<]+)<\/strong>/i', $row, $nm)) {
                $name = trim(strip_tags($nm[1]));
            }

            $version = null;
            if (preg_match('/(?:Version|Versión)[^\d]*(\d+[\d.]+)/i', strip_tags($row), $vm)) {
                $version = trim($vm[1]);
            }

            $active = !str_contains($rows[0][$i] ?? '', 'inactive');

            $hasUpdate  = str_contains($row, 'update-message') || str_contains($row, 'There is a new version') || str_contains($row, 'hay una nueva versión');
            $newVersion = null;
            if ($hasUpdate) {
                if (preg_match('/(?:new version|nueva versión)[^>]*>?\s*[\'"]?(\d+[\d.]+)/i', strip_tags($row), $uv)) {
                    $newVersion = $uv[1];
                }
                $needUpdate[] = $name . ($version ? " (v{$version}" . ($newVersion ? " → v{$newVersion}" : '') . ')' : '');
            }

            $plugins[$slug] = [
                'slug'        => $slug,
                'name'        => $name,
                'version'     => $version,
                'active'      => $active,
                'has_update'  => $hasUpdate,
                'new_version' => $newVersion,
                'last_updated'=> null,
                'source'      => 'admin_panel',
            ];
        }

        // Simpler fallback if main regex found nothing
        if (empty($plugins)) {
            preg_match_all('/<tr[^>]+class="[^"]*(?:active|inactive)[^"]*"[^>]*>(.*?)<\/tr>/si', $body, $simpleRows);
            foreach ($simpleRows[1] as $row) {
                $name = '';
                if (preg_match('/<strong[^>]*>([^<]+)/i', $row, $nm)) $name = trim(strip_tags($nm[1]));
                if (empty($name)) continue;
                $hasUpdate = str_contains($row, 'update-message');
                $slug = sanitize_slug($name);
                $plugins[$slug] = ['slug' => $slug, 'name' => $name, 'active' => !str_contains($row, 'inactive'), 'has_update' => $hasUpdate, 'last_updated' => null];
                if ($hasUpdate) $needUpdate[] = $name;
            }
        }

        // Enrich with last_updated from WP.org API (parallel requests)
        if (!empty($plugins)) {
            $this->enrichPluginDates($plugins);
        }

        $this->results['plugins'] = $plugins;
        $updateCount = count($needUpdate);

        if ($updateCount > 0) {
            $this->addVuln('high', 'Plugins Desactualizados', "{$updateCount} plugins con actualizaciones pendientes",
                "Plugins sin actualizar: " . implode(', ', $needUpdate),
                'Actualizar todos los plugins desde wp-admin/plugins.php o con WP-CLI: wp plugin update --all');
        }

        $this->emit('plugins_auth', count($plugins) . " plugins detectados · {$updateCount} con actualizaciones pendientes");
    }

    private function enrichPluginDates(array &$plugins): void {
        $mh  = curl_multi_init();
        $chs = [];

        foreach (array_keys($plugins) as $slug) {
            $ch = curl_init('https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=' . urlencode($slug) . '&request[fields][last_updated]=1');
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 8,
                CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_SSL_VERIFYPEER => false,
            ]);
            curl_multi_add_handle($mh, $ch);
            $chs[$slug] = $ch;
        }

        $running = null;
        do {
            curl_multi_exec($mh, $running);
            if ($running) curl_multi_select($mh, 1.0);
        } while ($running > 0);

        foreach ($chs as $slug => $ch) {
            $resp = curl_multi_getcontent($ch);
            if ($resp) {
                $info = json_decode($resp, true);
                if (!empty($info['last_updated'])) {
                    // Format: "2024-05-15 12:00pm GMT" → "2024-05-15"
                    $plugins[$slug]['last_updated'] = substr($info['last_updated'], 0, 10);
                }
            }
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
        }

        curl_multi_close($mh);
    }

    private function getThemes(): void {
        $this->emit('themes_auth', "Obteniendo lista de temas instalados...");
        $r    = $this->authHttp($this->url . '/wp-admin/themes.php');
        $body = $r['body'] ?? '';

        $themes     = [];
        $needUpdate = 0;

        // Try parsing _wpThemeSettings JS variable (most reliable, WP inlines theme data as JSON)
        if (preg_match('/var _wpThemeSettings\s*=\s*(\{.+?\});\s*[\r\n]/s', $body, $m)) {
            $settings = @json_decode($m[1], true);
            if (!empty($settings['themes']) && is_array($settings['themes'])) {
                foreach ($settings['themes'] as $slug => $t) {
                    $author    = is_array($t['author'] ?? '') ? ($t['author']['display_name'] ?? '') : ($t['author'] ?? null);
                    $hasUpdate = !empty($t['hasUpdate']) || !empty($t['update']);
                    if ($hasUpdate) $needUpdate++;
                    $themes[$slug] = [
                        'name'       => $t['name'] ?? $slug,
                        'version'    => $t['version'] ?? null,
                        'author'     => $author,
                        'active'     => !empty($t['active']),
                        'has_update' => $hasUpdate,
                    ];
                }
            }
        }

        // Fallback: data attributes
        if (empty($themes)) {
            preg_match_all('/data-slug="([^"]+)"/i', $body, $slugM);
            preg_match_all('/data-name="([^"]+)"/i', $body, $nameM);
            $needUpdate = substr_count($body, 'update-message');
            $slugs = array_unique($slugM[1] ?? []);
            foreach ($slugs as $i => $slug) {
                $themes[$slug] = [
                    'name'       => $nameM[1][$i] ?? $slug,
                    'version'    => null,
                    'author'     => null,
                    'active'     => false,
                    'has_update' => false,
                ];
            }
        }

        $inactiveCount = max(0, count($themes) - 1);

        $this->results['themes']      = $themes;
        $this->results['themes_info'] = [
            'count'          => count($themes),
            'update_count'   => $needUpdate,
            'inactive_count' => $inactiveCount,
        ];

        if ($needUpdate > 0) {
            $this->addVuln('medium', 'Temas Desactualizados', "{$needUpdate} temas con actualizaciones pendientes",
                'Los temas sin actualizar pueden contener vulnerabilidades de seguridad.',
                'Actualizar temas desde wp-admin/themes.php.');
        }
        if ($inactiveCount > 2) {
            $this->addVuln('low', 'Temas Inactivos', "{$inactiveCount} temas inactivos instalados",
                'Los temas inactivos aumentan la superficie de ataque innecesariamente.',
                'Eliminar todos los temas que no se usen. Solo mantener el activo y uno de reserva.');
        }

        $this->emit('themes_auth', count($themes) . " temas · {$needUpdate} con actualizaciones · {$inactiveCount} inactivos");
    }

    private function getCoreUpdateStatus(): void {
        $this->emit('updates', "Verificando actualización de WordPress core...");
        $r    = $this->authHttp($this->url . '/wp-admin/update-core.php');
        $body = $r['body'] ?? '';

        $needsUpdate = preg_match('/WordPress [0-9.]+ (?:is available|está disponible)/i', $body, $m);
        $newVersion  = null;
        if ($needsUpdate && preg_match('/WordPress ([0-9.]+)/i', $m[0], $vv)) {
            $newVersion = $vv[1];
        }

        $this->results['core_update'] = ['needed' => (bool)$needsUpdate, 'new_version' => $newVersion];

        if ($needsUpdate && $newVersion) {
            $this->addVuln('critical', 'WordPress Core Desactualizado', "Actualización disponible: WordPress {$newVersion}",
                'El core desactualizado tiene vulnerabilidades conocidas con exploits públicos.',
                "Actualizar a WordPress {$newVersion} desde wp-admin/update-core.php. URGENTE.");
        }

        $this->emit('updates', $needsUpdate ? "WordPress core necesita actualización → v{$newVersion}" : "WordPress core está actualizado");
    }

    private function getSiteSettings(): void {
        $this->emit('settings', "Verificando configuración del sitio...");

        // Search engine indexing from Reading settings
        $r    = $this->authHttp($this->url . '/wp-admin/options-reading.php');
        $body = $r['body'] ?? '';

        $searchEngineBlocked = null;
        // WP renders: <input name="blog_public" type="checkbox" ... > checked = "discourage search engines" = blocked
        if (preg_match('/<input[^>]+name="blog_public"[^>]*>/i', $body, $cbMatch)) {
            $searchEngineBlocked = str_contains(strtolower($cbMatch[0]), 'checked');
        }

        // WP_DEBUG from Site Health debug tab
        $r2    = $this->authHttp($this->url . '/wp-admin/site-health.php?tab=debug');
        $body2 = $r2['body'] ?? '';

        $wpDebug = null;
        // Site Health shows WP_DEBUG as label/value pair
        if (preg_match('/WP_DEBUG[\s\S]{0,300}?(Enabled|Disabled|true|false)/i', $body2, $m)) {
            $wpDebug = in_array(strtolower($m[1]), ['enabled', 'true']);
        }

        $this->results['site_settings'] = [
            'search_engine_blocked' => $searchEngineBlocked,
            'wp_debug'              => $wpDebug,
        ];

        if ($searchEngineBlocked === true) {
            $this->addVuln('high', 'Indexación SEO', 'Motores de búsqueda bloqueados',
                '"Desalentar a los motores de búsqueda a indexar este sitio" está activo. El sitio no aparecerá en Google ni Bing.',
                'Ajustes > Lectura → desmarcar "Solicitar a los motores de búsqueda que no indexen este sitio".');
        }
        if ($wpDebug === true) {
            $this->addVuln('high', 'WP_DEBUG', 'WP_DEBUG activo en producción',
                'WP_DEBUG=true expone errores PHP con rutas de archivos del servidor y posibles datos sensibles.',
                'En wp-config.php: define("WP_DEBUG", false);');
        }

        $debugStr = $wpDebug === null ? 'N/D' : ($wpDebug ? '⚠ ACTIVO' : '✓ inactivo');
        $indexStr = $searchEngineBlocked === null ? 'N/D' : ($searchEngineBlocked ? '⚠ BLOQUEADA' : '✓ permitida');
        $this->emit('settings', "WP_DEBUG: {$debugStr} · Indexación: {$indexStr}");
    }

    private function getAdminUsers(): void {
        $this->emit('users_auth', "Obteniendo usuarios administradores...");
        $r    = $this->authHttp($this->url . '/wp-admin/users.php?role=administrator');
        $body = $r['body'] ?? '';

        $admins = [];

        preg_match_all('/<tr[^>]+id="user-(\d+)"[^>]*>(.*?)<\/tr>/si', $body, $rows);

        foreach ($rows[1] as $i => $userId) {
            $row   = $rows[2][$i];
            $login = '';
            $name  = '';
            $email = '';

            if (preg_match('/class="[^"]*column-username[^"]*"[^>]*>(.*?)<\/td>/si', $row, $col)) {
                if (preg_match('/<strong[^>]*><a[^>]*>([^<]+)<\/a>/i', $col[1], $u)) {
                    $login = trim(strip_tags($u[1]));
                } elseif (preg_match('/<strong[^>]*>([^<]+)<\/strong>/i', $col[1], $u)) {
                    $login = trim(strip_tags($u[1]));
                }
            }
            if (preg_match('/class="[^"]*column-name[^"]*"[^>]*>(.*?)<\/td>/si', $row, $col)) {
                $name = trim(strip_tags($col[1]));
            }
            if (preg_match('/class="[^"]*column-email[^"]*"[^>]*>(.*?)<\/td>/si', $row, $col)) {
                $email = trim(strip_tags($col[1]));
            }

            if ($login) {
                $admins[] = [
                    'id'    => (int)$userId,
                    'login' => $login,
                    'name'  => $name,
                    'email' => $email,
                ];
            }
        }

        $this->results['admin_users'] = $admins;

        if (count($admins) > 3) {
            $this->addVuln('medium', 'Usuarios', 'Múltiples usuarios administradores',
                count($admins) . ' cuentas con rol administrador. Revisar si todas son necesarias.',
                'Reducir el número de administradores al mínimo. Usar roles de menor privilegio cuando sea posible.');
        }

        $this->emit('users_auth', count($admins) . " administrador(es) encontrado(s)");
    }

    private function doLogout(): void {
        // Fetch admin dashboard to get logout nonce
        $r    = $this->authHttp($this->url . '/wp-admin/');
        $body = $r['body'] ?? '';

        if (preg_match('/href="([^"]*action=logout[^"]*_wpnonce[^"]*)"/', $body, $m)) {
            $logoutUrl = html_entity_decode($m[1]);
            // Ensure absolute URL
            if (!str_starts_with($logoutUrl, 'http')) {
                $logoutUrl = $this->url . $logoutUrl;
            }
            $this->authHttp($logoutUrl);
            $this->emit('auth', "Sesión cerrada correctamente.");
        }
    }

    private function cleanup(): void {
        if ($this->cookieFile && file_exists($this->cookieFile)) {
            @unlink($this->cookieFile);
        }
    }
}

function sanitize_slug(string $name): string {
    return strtolower(preg_replace('/[^a-z0-9]+/i', '-', trim($name)));
}
