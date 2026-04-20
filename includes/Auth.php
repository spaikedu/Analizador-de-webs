<?php
require_once __DIR__ . '/../config.php';

class Auth {
    public static function check(): bool {
        if (session_status() === PHP_SESSION_NONE) session_start();
        return !empty($_SESSION[APP_SESSION_KEY]);
    }

    public static function requireLogin(): void {
        if (!self::check()) {
            header('Location: /wp-analyzer/login.php');
            exit;
        }
    }

    public static function login(string $password): bool {
        if (session_status() === PHP_SESSION_NONE) session_start();
        if (hash_equals(APP_PASSWORD, $password)) {
            session_regenerate_id(true);
            $_SESSION[APP_SESSION_KEY] = true;
            $_SESSION['login_time'] = time();
            return true;
        }
        return false;
    }

    public static function logout(): void {
        if (session_status() === PHP_SESSION_NONE) session_start();
        session_destroy();
    }

    public static function csrfToken(): string {
        if (session_status() === PHP_SESSION_NONE) session_start();
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }

    public static function verifyCsrf(string $token): bool {
        if (session_status() === PHP_SESSION_NONE) session_start();
        return !empty($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
    }
}
