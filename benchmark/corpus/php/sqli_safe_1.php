<?php
// SAFE: PDO prepared statement with bound parameter
function getUser(PDO $pdo, string $id): ?array {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}

$pdo  = new PDO("mysql:host=localhost;dbname=mydb", "root", "");
$user = getUser($pdo, $_GET['id'] ?? '');
echo htmlspecialchars($user['username'] ?? '', ENT_QUOTES, 'UTF-8');
