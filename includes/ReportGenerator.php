<?php

class ReportGenerator {

    public static function generateText(array $report): string {
        $url       = $report['url'] ?? 'N/A';
        $type      = $report['type'] ?? 'unauth';
        $results   = $report['results'] ?? [];
        $vulns     = $report['vulns'] ?? [];
        $scanTime  = $report['scan_time'] ?? date('Y-m-d H:i:s');
        $risk      = $results['risk'] ?? ['level' => 'unknown', 'counts' => []];
        $counts    = $risk['counts'] ?? [];

        $lines = [];
        $sep   = str_repeat('═', 80);
        $sep2  = str_repeat('─', 80);

        $lines[] = $sep;
        $lines[] = '  WP SECURITY ANALYZER — INFORME DE SEGURIDAD';
        $lines[] = '  Generado: ' . $scanTime;
        $lines[] = '  Tipo de análisis: ' . ($type === 'auth' ? 'AUTENTICADO' : 'NO AUTENTICADO');
        $lines[] = $sep;
        $lines[] = '';

        // ═══ 1. RESUMEN EJECUTIVO ═══
        $lines[] = '╔══════════════════════════════════════════════════════════════════════════════╗';
        $lines[] = '║  1. RESUMEN EJECUTIVO                                                        ║';
        $lines[] = '╚══════════════════════════════════════════════════════════════════════════════╝';
        $lines[] = '';
        $riskLabel = strtoupper($risk['level'] ?? 'DESCONOCIDO');
        $lines[] = "  Estado General:    [{$riskLabel}]";
        $lines[] = "  URL Analizada:     {$url}";
        $lines[] = "  Vulnerabilidades:  Críticas: " . ($counts['critical'] ?? 0) .
                   " | Altas: " . ($counts['high'] ?? 0) .
                   " | Medias: " . ($counts['medium'] ?? 0) .
                   " | Bajas: " . ($counts['low'] ?? 0);

        $topVulns = array_slice(array_filter($vulns, fn($v) => in_array($v['severity'], ['critical', 'high'])), 0, 3);
        if (!empty($topVulns)) {
            $lines[] = '';
            $lines[] = '  RIESGOS PRINCIPALES:';
            foreach ($topVulns as $v) {
                $lines[] = "  ► [{$v['severity']}] {$v['title']}";
            }
        }

        // Quick wins
        $lines[] = '';
        $lines[] = '  QUICK WINS (acciones inmediatas):';
        $quickWins = self::getQuickWins($vulns);
        foreach (array_slice($quickWins, 0, 5) as $qw) {
            $lines[] = "  ✓ {$qw}";
        }
        $lines[] = '';

        // ═══ 2. INFORMACIÓN GENERAL ═══
        $lines[] = $sep2;
        $lines[] = '  2. INFORMACIÓN GENERAL';
        $lines[] = $sep2;
        $lines[] = '';

        $conn    = $results['connectivity'] ?? [];
        $sslData = $results['ssl'] ?? [];
        $wpVer   = $results['wp_version'] ?? [];

        $lines[] = self::tableRow('URL', $url);
        $lines[] = self::tableRow('IP del Servidor', $conn['ip'] ?? 'N/A');
        $lines[] = self::tableRow('Servidor HTTP', $conn['server'] ?? 'N/A');
        $lines[] = self::tableRow('WordPress Versión', $wpVer['version'] ?? 'No detectada');
        $lines[] = self::tableRow('SSL/HTTPS', $sslData['enabled'] ? "✓ Activo — Expira en " . ($sslData['days_left'] ?? '?') . " días" : '✗ No activo');
        $lines[] = self::tableRow('Emisor SSL', $sslData['issuer'] ?? 'N/A');
        $lines[] = self::tableRow('Tipo de Análisis', $type === 'auth' ? 'Con autenticación' : 'Sin autenticación');

        if ($type === 'auth') {
            $authOk = $report['auth_success'] ?? false;
            $lines[] = self::tableRow('Login WordPress', $authOk ? '✓ Exitoso' : '✗ Fallido');
        }
        $lines[] = '';

        // ═══ 3. CABECERAS DE SEGURIDAD ═══
        $lines[] = $sep2;
        $lines[] = '  3. CABECERAS DE SEGURIDAD HTTP';
        $lines[] = $sep2;
        $lines[] = '';
        $lines[] = sprintf('  %-50s %-10s %s', 'Cabecera', 'Estado', 'Valor');
        $lines[] = str_repeat('-', 78);

        $headerResults = $results['headers'] ?? [];
        foreach ($headerResults as $header => $data) {
            $status = $data['present'] ? '✓ OK' : '✗ FALTA';
            $value  = $data['present'] ? substr($data['value'] ?? '', 0, 30) : 'No configurada';
            $lines[] = sprintf('  %-50s %-10s %s', $data['name'] ?? $header, $status, $value);
        }
        $lines[] = '';

        // ═══ 4. ENUMERACIÓN ═══
        $lines[] = $sep2;
        $lines[] = '  4. ENUMERACIÓN DETALLADA';
        $lines[] = $sep2;
        $lines[] = '';

        // Plugins
        $plugins = $results['plugins'] ?? [];
        if (!empty($plugins)) {
            $lines[] = '  4.1 PLUGINS DETECTADOS';
            $lines[] = sprintf('  %-35s %-15s %-8s %s', 'Plugin', 'Versión', 'Estado', 'CVEs');
            $lines[] = str_repeat('-', 78);
            foreach ($plugins as $slug => $plugin) {
                $active  = ($plugin['active'] ?? true) ? 'Activo' : 'Inactivo';
                $version = $plugin['version'] ?? 'N/D';
                $name    = substr($plugin['name'] ?? $slug, 0, 34);
                $hasCve  = '';
                foreach ($vulns as $v) {
                    if (!empty($v['cve']) && str_contains(strtolower($v['title']), strtolower($slug))) {
                        $hasCve .= $v['cve'] . ' ';
                    }
                }
                $hasUpdate = ($plugin['has_update'] ?? false) ? ' [⚠ UPDATE]' : '';
                $lines[] = sprintf('  %-35s %-15s %-8s %s%s', $name, $version . $hasUpdate, $active, $hasCve ? "CVE: {$hasCve}" : '');
            }
            $lines[] = '';
        }

        // Themes
        $themes = $results['themes'] ?? [];
        if (!empty($themes)) {
            $lines[] = '  4.2 TEMAS DETECTADOS';
            $lines[] = sprintf('  %-30s %-15s %s', 'Tema', 'Versión', 'Autor');
            $lines[] = str_repeat('-', 60);
            foreach ($themes as $slug => $theme) {
                $lines[] = sprintf('  %-30s %-15s %s',
                    substr($theme['name'] ?? $slug, 0, 29),
                    $theme['version'] ?? 'N/D',
                    $theme['author'] ?? 'N/D'
                );
            }
            $lines[] = '';
        }

        // Users
        $users = $results['users'] ?? [];
        if (!empty($users)) {
            $lines[] = '  4.3 USUARIOS EXPUESTOS';
            $lines[] = '  ⚠ ADVERTENCIA: Usuarios identificados sin autenticación';
            $lines[] = sprintf('  %-6s %-25s %s', 'ID', 'Login', 'Fuente');
            $lines[] = str_repeat('-', 50);
            foreach ($users as $user) {
                $lines[] = sprintf('  %-6s %-25s %s',
                    $user['id'] ?? '?',
                    $user['slug'] ?? $user['name'] ?? '?',
                    $user['source'] ?? 'REST API'
                );
            }
            $lines[] = '';
        }

        // REST API
        $restApi = $results['rest_api'] ?? [];
        $lines[] = '  4.4 ENDPOINTS SENSIBLES';
        $lines[] = sprintf('  %-45s %s', 'Endpoint', 'Estado');
        $lines[] = str_repeat('-', 60);
        $lines[] = sprintf('  %-45s %s', '/wp-json/wp/v2/users', ($restApi['users_exposed'] ?? false) ? '⚠ EXPUESTO — enumera usuarios' : 'Protegido o no accesible');
        $lines[] = sprintf('  %-45s %s', '/xmlrpc.php', ($results['xmlrpc']['accessible'] ?? false) ? '⚠ ACTIVO — riesgo de brute force' : 'Deshabilitado');
        $lines[] = sprintf('  %-45s %s', '/wp-login.php', ($results['login_page']['accessible'] ?? false) ? '⚠ Accesible sin protección adicional' : 'Protegido');
        $lines[] = sprintf('  %-45s %s', '/readme.html', ($results['sensitive_files']['/readme.html'] ?? false) ? '⚠ Accesible — expone versión WP' : 'No accesible');
        $lines[] = '';

        // Sensitive files
        $sensFiles = $results['sensitive_files'] ?? [];
        if (!empty($sensFiles)) {
            $lines[] = '  4.5 ARCHIVOS SENSIBLES EXPUESTOS';
            foreach ($sensFiles as $path => $data) {
                $lines[] = "  ⚠ {$path}";
                $lines[] = "    Severidad: " . strtoupper($data['sev'] ?? '?');
            }
            $lines[] = '';
        }

        // ═══ 5. VULNERABILIDADES ═══
        $lines[] = $sep2;
        $lines[] = '  5. VULNERABILIDADES DE SEGURIDAD';
        $lines[] = $sep2;
        $lines[] = '';

        $sevOrder = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4];
        usort($vulns, fn($a, $b) => ($sevOrder[$a['severity']] ?? 5) <=> ($sevOrder[$b['severity']] ?? 5));

        $i = 1;
        foreach ($vulns as $vuln) {
            $sev = strtoupper($vuln['severity'] ?? 'INFO');
            $lines[] = "  [{$i}] [{$sev}] {$vuln['title']}";
            $lines[] = "      Tipo: {$vuln['type']}";
            if (!empty($vuln['cve'])) {
                $lines[] = "      CVE:  {$vuln['cve']}";
            }
            $lines[] = "      Descripción:";
            foreach (explode("\n", wordwrap($vuln['desc'] ?? '', 70, "\n")) as $line) {
                $lines[] = "        {$line}";
            }
            $lines[] = "      Solución:";
            foreach (explode("\n", $vuln['solution'] ?? '') as $line) {
                $lines[] = "        {$line}";
            }
            $lines[] = '';
            $i++;
        }

        // ═══ 6. ELEMENTOR (si aplica) ═══
        $elementor = $results['elementor'] ?? null;
        if ($elementor) {
            $lines[] = $sep2;
            $lines[] = '  6. ANÁLISIS DE ELEMENTOR';
            $lines[] = $sep2;
            $lines[] = '';
            $lines[] = "  Versión detectada: " . ($elementor['version'] ?? 'N/D');
            $lines[] = "  Directorio uploads accesible: " . (($elementor['uploads_accessible'] ?? false) ? '⚠ SÍ' : '✓ No');
            if (!empty($elementor['recommendations'])) {
                $lines[] = '';
                $lines[] = '  RECOMENDACIONES ELEMENTOR:';
                foreach ($elementor['recommendations'] as $rec) {
                    $lines[] = "  • {$rec}";
                }
            }
            $lines[] = '';
        }

        // ═══ 7. AUTENTICADO (si aplica) ═══
        if ($type === 'auth' && ($report['auth_success'] ?? false)) {
            $serverInfo = $results['server_info'] ?? [];
            $lines[] = $sep2;
            $lines[] = '  7. HALLAZGOS AUTENTICADOS';
            $lines[] = $sep2;
            $lines[] = '';

            if (!empty($serverInfo['php_version'])) {
                $lines[] = self::tableRow('Versión PHP', $serverInfo['php_version']);
            }
            if (!empty($serverInfo['mysql_version'])) {
                $lines[] = self::tableRow('Versión MySQL', $serverInfo['mysql_version']);
            }

            $adminInfo = $results['wp_admin_info'] ?? [];
            if (isset($adminInfo['plugin_updates'])) {
                $lines[] = self::tableRow('Plugins pendientes de actualizar', $adminInfo['plugin_updates']);
            }
            if (isset($adminInfo['theme_updates'])) {
                $lines[] = self::tableRow('Temas pendientes de actualizar', $adminInfo['theme_updates']);
            }
            if (isset($results['core_update']['needed'])) {
                $lines[] = self::tableRow('Core WP pendiente de actualizar', $results['core_update']['needed'] ? '⚠ SÍ' : '✓ No');
            }

            $suspPlugins = $results['suspicious_plugins'] ?? [];
            if (!empty($suspPlugins)) {
                $lines[] = '';
                $lines[] = '  PLUGINS SOSPECHOSOS:';
                foreach ($suspPlugins as $sp) {
                    $lines[] = "  ⚠ {$sp['name']} ({$sp['slug']})";
                    $lines[] = "    → {$sp['reason']}";
                }
            }
            $lines[] = '';
        }

        // ═══ 8. RECOMENDACIONES PRIORITARIAS ═══
        $lines[] = $sep2;
        $lines[] = '  8. RECOMENDACIONES PRIORITARIAS';
        $lines[] = $sep2;
        $lines[] = '';

        $recommendations = self::generateRecommendations($results, $vulns, $type);
        $priority = 1;
        foreach ($recommendations as $rec) {
            $lines[] = "  [{$priority}] {$rec['title']}";
            $lines[] = "      {$rec['detail']}";
            $lines[] = '';
            $priority++;
        }

        // ═══ FOOTER ═══
        $lines[] = $sep;
        $lines[] = '  Informe generado por WP Security Analyzer v' . APP_VERSION;
        $lines[] = '  IMPORTANTE: Este informe es confidencial. No compartir sin autorización.';
        $lines[] = '  Las vulnerabilidades deben ser corregidas por un profesional cualificado.';
        $lines[] = $sep;

        return implode("\n", $lines);
    }

    private static function tableRow(string $key, string $value): string {
        return sprintf('  %-35s %s', $key . ':', $value);
    }

    private static function getQuickWins(array $vulns): array {
        $wins = [];
        $types = [];
        foreach ($vulns as $v) {
            $type = $v['type'] ?? '';
            if (!isset($types[$type])) {
                $types[$type] = true;
                if (str_contains($type, 'Cabeceras')) $wins[] = 'Añadir cabeceras de seguridad HTTP en .htaccess';
                elseif (str_contains($type, 'XML-RPC')) $wins[] = 'Deshabilitar XML-RPC (deny from all en .htaccess)';
                elseif (str_contains($type, 'Brute Force')) $wins[] = 'Instalar Limit Login Attempts Reloaded';
                elseif (str_contains($type, 'readme')) $wins[] = 'Eliminar readme.html del servidor';
                elseif (str_contains($type, 'Plugin') && str_contains($type, 'Desactualizado')) $wins[] = 'Actualizar todos los plugins desde wp-admin';
                elseif (str_contains($type, 'Core')) $wins[] = 'Actualizar WordPress core urgentemente';
                elseif (str_contains($type, 'Debug')) $wins[] = 'Deshabilitar WP_DEBUG en wp-config.php';
                elseif (str_contains($type, 'Enumeración')) $wins[] = 'Bloquear enumeración de usuarios via REST API';
            }
        }
        if (empty($wins)) $wins[] = 'Revisar y aplicar las recomendaciones de este informe';
        return $wins;
    }

    private static function generateRecommendations(array $results, array $vulns, string $type): array {
        $recs = [];

        // Check critical patterns
        $hasCritical = !empty(array_filter($vulns, fn($v) => $v['severity'] === 'critical'));
        $hasPlugin   = !empty(array_filter($vulns, fn($v) => str_contains($v['type'], 'Plugin') && str_contains($v['type'], 'Desactualizado')));
        $hasCore     = !empty(array_filter($vulns, fn($v) => str_contains($v['type'], 'Core')));
        $hasHeaders  = !empty(array_filter($vulns, fn($v) => str_contains($v['type'], 'Cabeceras')));
        $hasBrute    = !empty(array_filter($vulns, fn($v) => str_contains($v['type'], 'Brute')));
        $hasXmlRpc   = $results['xmlrpc']['accessible'] ?? false;

        if ($hasCritical) {
            $recs[] = ['title' => '🔴 URGENTE: Corregir vulnerabilidades críticas', 'detail' => 'Hay CVEs críticos con exploits públicos. Actuar en las próximas 24h.'];
        }
        if ($hasPlugin) {
            $recs[] = ['title' => 'Actualizar todos los plugins', 'detail' => 'Ir a wp-admin/plugins.php y actualizar todos. Activar actualizaciones automáticas para plugins críticos de seguridad.'];
        }
        if ($hasCore) {
            $recs[] = ['title' => 'Actualizar WordPress Core', 'detail' => 'El núcleo de WordPress está desactualizado. Hacer backup y actualizar desde wp-admin/update-core.php.'];
        }
        $recs[] = ['title' => 'Instalar plugin de seguridad', 'detail' => 'Instalar Wordfence o Sucuri Security para firewall WAF, escaneo de malware y alertas en tiempo real.'];
        if ($hasHeaders) {
            $recs[] = ['title' => 'Configurar cabeceras de seguridad HTTP', 'detail' => "Añadir al .htaccess de WordPress:\nHeader always set X-Content-Type-Options \"nosniff\"\nHeader always set X-Frame-Options \"SAMEORIGIN\"\nHeader always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\""];
        }
        if ($hasBrute) {
            $recs[] = ['title' => 'Proteger wp-login.php contra fuerza bruta', 'detail' => '1. Cambiar URL de login con wps-hide-login. 2. Activar 2FA. 3. Instalar Limit Login Attempts Reloaded.'];
        }
        if ($hasXmlRpc) {
            $recs[] = ['title' => 'Deshabilitar XML-RPC', 'detail' => "Si no usas la app móvil de WordPress ni Jetpack, añadir al .htaccess:\n<files xmlrpc.php>\ndeny from all\n</files>"];
        }
        $recs[] = ['title' => 'Configurar backups automáticos', 'detail' => 'Instalar UpdraftPlus o similar. Configurar backups diarios a almacenamiento externo (Google Drive, S3, Dropbox).'];
        $recs[] = ['title' => 'Revisar usuarios y roles', 'detail' => 'Auditar todos los usuarios administradores. Eliminar los que no sean necesarios. Aplicar contraseñas fuertes.'];
        $recs[] = ['title' => 'Plan de mantenimiento mensual', 'detail' => 'Establecer rutina: actualizar WP + plugins + temas mensualmente. Revisar logs de seguridad. Escanear malware.'];

        return $recs;
    }
}
