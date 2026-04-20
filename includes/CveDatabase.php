<?php

class CveDatabase {

    private static array $db = [

        // =================== WORDPRESS CORE ===================
        'wordpress_core' => [
            ['cve' => 'CVE-2023-2745',  'max' => '6.2.0',  'severity' => 'medium',   'type' => 'Directory Traversal',     'desc' => 'wp_is_local_attachment() allows path traversal. Fixed in 6.2.1.',                              'fix' => 'Actualizar WordPress a 6.2.1+'],
            ['cve' => 'CVE-2022-3590',  'max' => '6.0.2',  'severity' => 'medium',   'type' => 'SSRF',                    'desc' => 'Server-Side Request Forgery en procesamiento de pingbacks. Fixed en 6.0.3.',                   'fix' => 'Actualizar WordPress a 6.0.3+. Deshabilitar XML-RPC si no se usa.'],
            ['cve' => 'CVE-2021-29447', 'max' => '5.7.0',  'severity' => 'high',     'type' => 'XXE Injection',           'desc' => 'XXE via media upload en WordPress < 5.7.1. Permite leer archivos del servidor (wp-config.php).', 'fix' => 'Actualizar WordPress a 5.7.1+'],
            ['cve' => 'CVE-2021-29450', 'max' => '5.7.0',  'severity' => 'medium',   'type' => 'Information Disclosure',  'desc' => 'WordPress < 5.7.1 expone contraseñas en texto plano en los logs de errores.',                   'fix' => 'Actualizar WordPress a 5.7.1+. Deshabilitar WP_DEBUG en producción.'],
            ['cve' => 'CVE-2019-17671', 'max' => '5.2.3',  'severity' => 'high',     'type' => 'Unauthenticated View',    'desc' => 'WordPress < 5.2.4 permite ver contenido privado sin autenticación.',                           'fix' => 'Actualizar WordPress a 5.2.4+'],
            ['cve' => 'CVE-2019-16781', 'max' => '5.3.0',  'severity' => 'high',     'type' => 'Stored XSS',             'desc' => 'XSS almacenado en el editor de bloques de WordPress < 5.3.1.',                                  'fix' => 'Actualizar WordPress a 5.3.1+'],
            ['cve' => 'CVE-2020-28032', 'max' => '5.5.1',  'severity' => 'high',     'type' => 'Object Injection',        'desc' => 'PHP Object Injection en WordPress < 5.5.2 vía deserialización.',                               'fix' => 'Actualizar WordPress a 5.5.2+'],
            ['cve' => 'CVE-2023-38000', 'max' => '6.3.1',  'severity' => 'medium',   'type' => 'Contributor+ Stored XSS', 'desc' => 'XSS almacenado en el bloque de navegación para usuarios Contributor+. Fixed en 6.3.2.',         'fix' => 'Actualizar WordPress a 6.3.2+'],
        ],

        // =================== ELEMENTOR ===================
        'elementor' => [
            ['cve' => 'CVE-2023-5360',  'max' => '3.17.3', 'severity' => 'critical', 'type' => 'Arbitrary File Upload / RCE', 'desc' => 'CVSS 9.8. Elementor <= 3.17.3: carga de archivos arbitrarios sin autenticación via icon library endpoint. Permite RCE completo.', 'fix' => 'Actualizar Elementor a 3.18.0+. Urgente.', 'payload' => 'POST /wp-admin/admin-ajax.php action=elementor_library_add_category con archivo PHP renombrado'],
            ['cve' => 'CVE-2022-1329',  'max' => '3.6.2',  'severity' => 'critical', 'type' => 'Authenticated RCE',           'desc' => 'CVSS 9.9. Elementor <= 3.6.2: RCE autenticado via importación de plantillas maliciosas.',          'fix' => 'Actualizar Elementor a 3.6.3+'],
            ['cve' => 'CVE-2023-32243', 'max' => '3.13.2', 'severity' => 'critical', 'type' => 'Privilege Escalation',        'desc' => 'CVSS 9.8. Elementor <= 3.13.2: cambio de contraseña arbitraria sin autenticación.',               'fix' => 'Actualizar Elementor a 3.13.3+. Urgente.'],
            ['cve' => 'CVE-2024-1521',  'max' => '3.20.1', 'severity' => 'high',     'type' => 'LFI via SSTI',               'desc' => 'Elementor <= 3.20.1: Local File Inclusion via Server-Side Template Injection en widgets.',       'fix' => 'Actualizar Elementor a 3.20.2+'],
            ['cve' => 'CVE-2021-4236',  'max' => '3.4.7',  'severity' => 'high',     'type' => 'Stored XSS',                 'desc' => 'Elementor <= 3.4.7: XSS almacenado via atributos de widgets para usuarios Contributor+.',         'fix' => 'Actualizar Elementor a 3.5.0+'],
        ],

        'elementor-pro' => [
            ['cve' => 'CVE-2023-48777', 'max' => '3.18.0', 'severity' => 'critical', 'type' => 'Arbitrary File Upload',      'desc' => 'CVSS 9.8. Elementor Pro <= 3.18.0: carga de archivos arbitrarios. Similar a CVE-2023-5360.',    'fix' => 'Actualizar Elementor Pro a 3.18.1+'],
            ['cve' => 'CVE-2022-29455', 'max' => '3.7.2',  'severity' => 'high',     'type' => 'DOM-Based XSS',              'desc' => 'Elementor Pro <= 3.7.2: DOM XSS via parámetro URL en el tema Hello Elementor.',                 'fix' => 'Actualizar Elementor Pro a 3.7.3+'],
        ],

        // =================== CONTACT FORM 7 ===================
        'contact-form-7' => [
            ['cve' => 'CVE-2020-35489', 'max' => '5.3.1',  'severity' => 'critical', 'type' => 'Arbitrary File Upload',      'desc' => 'CVSS 10.0. CF7 <= 5.3.1: carga de archivos PHP sin restricción, permite RCE completo.',          'fix' => 'Actualizar Contact Form 7 a 5.3.2+'],
            ['cve' => 'CVE-2023-6449',  'max' => '5.8.0',  'severity' => 'high',     'type' => 'Arbitrary File Upload',      'desc' => 'CF7 <= 5.8: bypass de extensión de archivo permite subida de .php5, .phtml, etc.',              'fix' => 'Actualizar CF7 a 5.8.1+. Validar extensiones en servidor.'],
            ['cve' => 'CVE-2021-24924', 'max' => '5.4.1',  'severity' => 'medium',   'type' => 'Reflected XSS',              'desc' => 'CF7 <= 5.4.1: XSS reflejado en validación de formulario.',                                     'fix' => 'Actualizar CF7 a 5.4.2+'],
        ],

        // =================== YOAST SEO ===================
        'wordpress-seo' => [
            ['cve' => 'CVE-2021-25118', 'max' => '16.7',   'severity' => 'medium',   'type' => 'Information Disclosure',     'desc' => 'Yoast SEO <= 16.7: expone metadatos internos vía REST API sin autenticación.',                    'fix' => 'Actualizar Yoast SEO a 16.8+'],
            ['cve' => 'CVE-2021-3726',  'max' => '15.1.1', 'severity' => 'medium',   'type' => 'Reflected XSS',              'desc' => 'Yoast SEO <= 15.1.1: XSS reflejado en parámetros de búsqueda en admin.',                       'fix' => 'Actualizar Yoast SEO a 15.2+'],
        ],

        // =================== WOOCOMMERCE ===================
        'woocommerce' => [
            ['cve' => 'CVE-2023-28121', 'max' => '7.8.1',  'severity' => 'critical', 'type' => 'Authentication Bypass',      'desc' => 'CVSS 9.8. WooCommerce Payments <= 5.6.1: bypass de autenticación permite actuar como admin.',   'fix' => 'Actualizar WooCommerce Payments a 5.6.2+. Urgente.'],
            ['cve' => 'CVE-2021-32789', 'max' => '5.5.1',  'severity' => 'high',     'type' => 'SQL Injection',              'desc' => 'WooCommerce <= 5.5.1: SQL injection en parámetros de pedido. Exposición de base de datos.',     'fix' => 'Actualizar WooCommerce a 5.5.2+'],
            ['cve' => 'CVE-2022-2099',  'max' => '6.6.0',  'severity' => 'high',     'type' => 'Stored XSS',                 'desc' => 'WooCommerce <= 6.6.0: XSS almacenado para usuarios con rol shop_manager.',                     'fix' => 'Actualizar WooCommerce a 6.6.1+'],
        ],

        // =================== JETPACK ===================
        'jetpack' => [
            ['cve' => 'CVE-2023-2996',  'max' => '12.1.0', 'severity' => 'high',     'type' => 'Sensitive Data Exposure',    'desc' => 'Jetpack <= 12.1: expone datos de formularios privados a usuarios no autorizados.',              'fix' => 'Actualizar Jetpack a 12.1.1+'],
            ['cve' => 'CVE-2022-0633',  'max' => '10.9',   'severity' => 'medium',   'type' => 'Broken Access Control',      'desc' => 'Jetpack <= 10.9: control de acceso roto en endpoint de subscripciones.',                        'fix' => 'Actualizar Jetpack a 10.9.1+'],
        ],

        // =================== WPFORMS ===================
        'wpforms-lite' => [
            ['cve' => 'CVE-2024-0394',  'max' => '1.8.4',  'severity' => 'medium',   'type' => 'Reflected XSS',              'desc' => 'WPForms Lite <= 1.8.4: XSS reflejado via parámetros de formulario.',                           'fix' => 'Actualizar WPForms a 1.8.5+'],
        ],

        // =================== REVOLUTION SLIDER ===================
        'revslider' => [
            ['cve' => 'CVE-2014-9734',  'max' => '4.2.0',  'severity' => 'critical', 'type' => 'Arbitrary File Upload',      'desc' => 'RevSlider <= 4.2: carga de archivos PHP sin autenticación. Exploit masivo activo en 2014-2023.',  'fix' => 'Actualizar RevSlider o eliminarlo. Verificar servidor comprometido.'],
            ['cve' => 'CVE-2014-9734',  'max' => '4.1.4',  'severity' => 'critical', 'type' => 'Local File Inclusion',        'desc' => 'RevSlider <= 4.1.4: LFI via admin-ajax permite leer wp-config.php y otros archivos.',           'fix' => 'Actualizar RevSlider urgentemente o eliminar.'],
        ],

        // =================== DUPLICATOR ===================
        'duplicator' => [
            ['cve' => 'CVE-2020-11738', 'max' => '1.3.26', 'severity' => 'high',     'type' => 'Path Traversal',             'desc' => 'Duplicator <= 1.3.26: path traversal sin autenticación, lectura de archivos arbitrarios.',       'fix' => 'Actualizar Duplicator a 1.3.28+'],
            ['cve' => 'CVE-2023-6114',  'max' => '1.5.7',  'severity' => 'critical', 'type' => 'Unauthenticated Data Exposure','desc' => 'Duplicator <= 1.5.7: acceso sin auth a archivos de backup que contienen BD y credenciales.',      'fix' => 'Actualizar Duplicator a 1.5.8+. Borrar archivos installer_*.php y backups expuestos.'],
        ],

        // =================== ALL-IN-ONE SEO ===================
        'all-in-one-seo-pack' => [
            ['cve' => 'CVE-2021-24307', 'max' => '4.1.0',  'severity' => 'high',     'type' => 'Privilege Escalation',       'desc' => 'AIOSEO <= 4.1.0.2: escalada de privilegios autenticada via REST API.',                          'fix' => 'Actualizar AIOSEO a 4.1.1+'],
        ],

        // =================== WP STATISTICS ===================
        'wp-statistics' => [
            ['cve' => 'CVE-2022-4681',  'max' => '13.2.8', 'severity' => 'high',     'type' => 'SQL Injection',              'desc' => 'WP Statistics <= 13.2.8: SQLi ciego via statsVisits. Exposición de toda la BD.',                'fix' => 'Actualizar WP Statistics a 13.2.9+'],
        ],

        // =================== NEWSLETTER ===================
        'newsletter' => [
            ['cve' => 'CVE-2021-24825', 'max' => '7.3.5',  'severity' => 'high',     'type' => 'Reflected XSS',              'desc' => 'Newsletter <= 7.3.5: XSS reflejado via parámetros en páginas de newsletter.',                   'fix' => 'Actualizar Newsletter plugin a 7.3.6+'],
        ],

        // =================== WPML ===================
        'sitepress-multilingual-cms' => [
            ['cve' => 'CVE-2023-45556', 'max' => '4.6.6',  'severity' => 'high',     'type' => 'SQL Injection',              'desc' => 'WPML <= 4.6.6: SQL injection via parámetros de idioma.',                                       'fix' => 'Actualizar WPML a 4.6.7+'],
        ],

        // =================== ULTIMATE MEMBER ===================
        'ultimate-member' => [
            ['cve' => 'CVE-2023-3460',  'max' => '2.6.6',  'severity' => 'critical', 'type' => 'Privilege Escalation',       'desc' => 'CVSS 9.8. Ultimate Member <= 2.6.6: creación de cuentas de administrador sin autenticación.',   'fix' => 'Actualizar Ultimate Member a 2.6.7+. Urgente.'],
        ],

        // =================== BACKUP BUDDY ===================
        'backupbuddy' => [
            ['cve' => 'CVE-2022-31474', 'max' => '8.7.4',  'severity' => 'high',     'type' => 'Arbitrary File Download',    'desc' => 'BackupBuddy <= 8.7.4: descarga de archivos arbitrarios sin autenticación.',                     'fix' => 'Actualizar BackupBuddy a 8.7.5+'],
        ],
    ];

    public static function checkPlugin(string $slug, string $version): array {
        $found = [];
        $normalSlug = strtolower(trim($slug));

        foreach (self::$db as $dbSlug => $cves) {
            if ($dbSlug === $normalSlug || str_contains($normalSlug, $dbSlug) || str_contains($dbSlug, $normalSlug)) {
                foreach ($cves as $cve) {
                    if (!empty($version) && version_compare($version, $cve['max'], '<=')) {
                        $found[] = array_merge($cve, ['component' => $slug, 'detected_version' => $version]);
                    } elseif (empty($version)) {
                        $found[] = array_merge($cve, ['component' => $slug, 'detected_version' => 'Desconocida', 'note' => 'No se pudo detectar versión']);
                    }
                }
            }
        }

        return $found;
    }

    public static function checkWordPressCore(string $version): array {
        $found = [];
        if (empty($version)) return $found;

        foreach (self::$db['wordpress_core'] as $cve) {
            if (version_compare($version, $cve['max'], '<=')) {
                $found[] = array_merge($cve, ['component' => 'WordPress Core', 'detected_version' => $version]);
            }
        }

        return $found;
    }

    public static function getSuspiciousPlugins(): array {
        return [
            'adminer'             => 'Herramienta de gestión de BD expuesta públicamente. ELIMINAR en producción.',
            'wp-phpmyadmin'       => 'phpMyAdmin integrado en WordPress. Exposición crítica de BD.',
            'exploit'             => 'Nombre sospechoso. Posible plugin malicioso.',
            'backdoor'            => 'Nombre sospechoso. Posible backdoor.',
            'shell'               => 'Nombre sospechoso. Posible webshell.',
            'filemanager'         => 'File Manager expuesto. Riesgo alto de RCE.',
            'wp-file-manager'     => 'WP File Manager con historial de vulnerabilidades críticas.',
            'wp-terminal'         => 'Terminal SSH en WordPress. Riesgo extremo.',
            'search-replace-db'   => 'Script de búsqueda/reemplazo en BD. Eliminar tras uso.',
            'installer'           => 'Script installer accesible. Eliminar tras instalación.',
        ];
    }
}
