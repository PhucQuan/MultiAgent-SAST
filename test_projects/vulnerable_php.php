<?php
// Taint Source: $_GET['page']
$page = $_GET['page'];

// VULNERABLE: Local File Inclusion / Path Traversal
// Taint Sink: include()
include("pages/" . $page . ".php");

// Another one: SQL Injection
$id = $_POST['id'];
$conn = mysqli_connect("localhost", "db_user", "db_pass", "database");

// Taint Sink: mysqli_query()
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
?>
