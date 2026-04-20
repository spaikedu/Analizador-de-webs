<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($pageTitle ?? APP_NAME) ?> — WP Analyzer</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <link rel="stylesheet" href="/wp-analyzer/assets/css/style.css">
</head>
<body>
    <div class="scan-line"></div>
    <nav class="navbar">
        <div class="nav-brand">
            <div class="brand-icon"><i class="fas fa-shield-halved"></i></div>
            <span class="brand-text">WP<span class="accent">Sec</span>Analyzer</span>
        </div>
        <div class="nav-links">
            <a href="/wp-analyzer/" class="nav-link <?= ($_SERVER['PHP_SELF'] === '/wp-analyzer/index.php' || $_SERVER['PHP_SELF'] === '/wp-analyzer/') ? 'active' : '' ?>">
                <i class="fas fa-chart-line"></i> Dashboard
            </a>
            <a href="/wp-analyzer/scan.php" class="nav-link <?= str_contains($_SERVER['PHP_SELF'], 'scan.php') ? 'active' : '' ?>">
                <i class="fas fa-radar"></i> Nuevo Análisis
            </a>
            <a href="/wp-analyzer/logout.php" class="nav-link nav-link-logout">
                <i class="fas fa-right-from-bracket"></i> Salir
            </a>
        </div>
    </nav>
    <main class="main-content">
