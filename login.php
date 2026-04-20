<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/Auth.php';

if (Auth::check()) {
    header('Location: /wp-analyzer/');
    exit;
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $pwd = $_POST['password'] ?? '';
    if (Auth::login($pwd)) {
        header('Location: /wp-analyzer/');
        exit;
    } else {
        $error = 'Contraseña incorrecta.';
        // Small delay to prevent brute force
        sleep(1);
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WP Security Analyzer — Login</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <link rel="stylesheet" href="/wp-analyzer/assets/css/style.css">
</head>
<body class="login-body">
    <div class="scan-line"></div>
    <div class="login-bg">
        <div class="login-grid"></div>
        <div class="login-glow"></div>
    </div>
    <div class="login-container">
        <div class="login-card">
            <div class="login-icon">
                <i class="fas fa-shield-halved"></i>
            </div>
            <h1 class="login-title">WP<span class="accent">Sec</span>Analyzer</h1>
            <p class="login-subtitle">Plataforma de Análisis de Seguridad WordPress</p>

            <?php if ($error): ?>
            <div class="alert alert-error">
                <i class="fas fa-circle-exclamation"></i> <?= htmlspecialchars($error) ?>
            </div>
            <?php endif; ?>

            <form method="POST" class="login-form">
                <div class="form-group">
                    <label class="form-label"><i class="fas fa-lock"></i> Contraseña de acceso</label>
                    <div class="input-wrapper">
                        <input type="password" name="password" class="form-input" placeholder="••••••••••••" autofocus autocomplete="current-password">
                        <button type="button" class="input-toggle" onclick="togglePass(this)">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                </div>
                <button type="submit" class="btn btn-primary btn-full">
                    <i class="fas fa-right-to-bracket"></i> Acceder al sistema
                </button>
            </form>

            <p class="login-footer">
                <i class="fas fa-lock-keyhole"></i> Acceso restringido — Solo uso autorizado
            </p>
        </div>
    </div>

    <script>
    function togglePass(btn) {
        const input = btn.closest('.input-wrapper').querySelector('input');
        const icon = btn.querySelector('i');
        if (input.type === 'password') {
            input.type = 'text';
            icon.className = 'fas fa-eye-slash';
        } else {
            input.type = 'password';
            icon.className = 'fas fa-eye';
        }
    }
    </script>
</body>
</html>
