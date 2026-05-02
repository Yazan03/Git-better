<?php
// VULN: CWE-89 — SQL injection via $_GET concatenated into query string
function getUser($conn) {
    $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
    $result = mysqli_query($conn, $query);
    return mysqli_fetch_assoc($result);
}

$conn = mysqli_connect("localhost", "root", "", "mydb");
$user = getUser($conn);
echo $user['username'];
