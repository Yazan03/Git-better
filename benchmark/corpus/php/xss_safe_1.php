<?php
// SAFE: all user input passed through htmlspecialchars() before output
$name   = htmlspecialchars($_GET['name'] ?? '', ENT_QUOTES, 'UTF-8');
$search = htmlspecialchars($_POST['q']    ?? '', ENT_QUOTES, 'UTF-8');

echo "<h1>Hello, " . $name . "</h1>";
echo "<p>You searched for: " . $search . "</p>";
