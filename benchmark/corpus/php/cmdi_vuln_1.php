<?php
// VULN: CWE-78 — Command injection via shell_exec() with $_GET parameter
$host   = $_GET['host'];
$output = shell_exec("ping -c 1 " . $host);
echo "<pre>" . $output . "</pre>";
