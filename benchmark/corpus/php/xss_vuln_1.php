<?php
// VULN: CWE-79 — Reflected XSS via unescaped $_GET output
$name   = $_GET['name'];
$search = $_POST['q'] ?? '';

echo "<h1>Hello, " . $name . "</h1>";
echo "<p>You searched for: " . $search . "</p>";
