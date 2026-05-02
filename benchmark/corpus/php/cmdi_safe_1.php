<?php
// SAFE: escapeshellarg() neutralises shell metacharacters
$allowed = ['localhost', 'example.com', '8.8.8.8'];
$host    = $_GET['host'] ?? 'localhost';

if (!in_array($host, $allowed, true)) {
    http_response_code(400);
    exit("Host not permitted");
}

$output = shell_exec("ping -c 1 " . escapeshellarg($host));
echo "<pre>" . htmlspecialchars($output, ENT_QUOTES, 'UTF-8') . "</pre>";
