<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/Auth.php';
Auth::logout();
header('Location: /wp-analyzer/login.php');
exit;
