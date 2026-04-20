# WordPress Analyzer

Herramienta de análisis y auditoría de seguridad especializada en WordPress que detecta vulnerabilidades, plugins desactualizados, temas problemáticos, problemas de configuración y riesgos de seguridad.

## Características

- 🔍 **Análisis de vulnerabilidades** - Detecta vulnerabilidades conocidas en WordPress, plugins y temas
- 🛡️ **Auditoría de seguridad** - Verifica configuraciones de seguridad y mejores prácticas
- 📊 **Reportes detallados** - Genera reportes completos con recomendaciones de hardening
- 🔐 **Detección de riesgos** - Identifica configuraciones débiles y exposiciones de datos
- 🚀 **Escaneo rápido** - Análisis eficiente de sitios WordPress

## Requisitos

- PHP 7.4 o superior
- Base de datos compatible (MySQL/MariaDB)
- Acceso a Internet (para base de datos de CVE)
- Servidor web (Apache/Nginx)

## Instalación

1. **Clonar el repositorio**
   ```bash
   git clone https://github.com/spaikedu/wp-analyzer.git
   cd wp-analyzer
   ```

2. **Configurar la base de datos**
   - Editar `config.php` con tus credenciales
   - Ejecutar `install.php` en el navegador

3. **Permisos de archivos**
   ```bash
   chmod 755 wp-analyzer/
   chmod 644 wp-analyzer/*.php
   ```

## Uso

### Acceso web
1. Abrir `http://localhost/wp-analyzer/`
2. Ingresar credenciales
3. Ingresar URL del sitio WordPress a analizar
4. Ejecutar escaneo y revisar reportes

### API
```bash
curl -X POST http://localhost/wp-analyzer/api/scan.php \
  -d '{"url":"https://ejemplo.com","token":"YOUR_TOKEN"}'
```

## Estructura del Proyecto

```
wp-analyzer/
├── index.php              # Página principal
├── login.php              # Autenticación
├── scan.php               # Interfaz de escaneo
├── report.php             # Visualización de reportes
├── config.php             # Configuración (NO commitar)
├── install.php            # Script de instalación
├── api/
│   └── scan.php           # Endpoints API
├── includes/
│   ├── Auth.php           # Gestión de autenticación
│   ├── AuthScanner.php    # Escáner autenticado
│   ├── UnauthScanner.php  # Escáner sin autenticación
│   ├── CveDatabase.php    # Base de datos de CVEs
│   ├── ReportGenerator.php # Generación de reportes
│   ├── db.php             # Conexión BD
│   ├── header.php         # Header HTML
│   └── footer.php         # Footer HTML
├── assets/
│   ├── css/style.css      # Estilos
│   └── js/app.js          # JavaScript
└── README.md              # Este archivo
```

## Configuración

Editar `config.php` antes de la instalación:

```php
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASSWORD', 'password');
define('DB_NAME', 'wp_analyzer');
```

## Seguridad

- Mantener `config.php` fuera del control de versiones
- Usar variables de entorno para credenciales sensibles
- Cambiar credenciales de acceso regularmente
- Ejecutar sobre HTTPS en producción
- Aplicar restricciones de acceso por IP si es posible

## Contribuir

Las contribuciones son bienvenidas. Por favor:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## Licencia

Este proyecto está bajo la licencia MIT. Ver archivo `LICENSE` para más detalles.

## Soporte

Para reportar bugs o solicitar features, abre un issue en GitHub.

---

**Autor:** spaikedu  
**Estado:** En desarrollo
