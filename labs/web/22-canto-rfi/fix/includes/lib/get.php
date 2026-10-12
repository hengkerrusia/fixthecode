<?php
$subdomain = $_GET['subdomain'] ?? 'default';
$wp_abspath = $_GET['wp_abspath'] ?? dirname(__DIR__, 2);
require_once($wp_abspath . '/wp-admin/admin.php');
