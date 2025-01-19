<?php

use De\Idrinth\WebRoot\VirtualHostGenerator;
use Dotenv\Dotenv;
use Twig\Environment;
use Twig\Loader\FilesystemLoader;

require_once dirname(__DIR__) . '/vendor/autoload.php';

Dotenv::createImmutable(dirname(__DIR__))->load();

$database = new PDO('mysql:dbname=' . $_ENV['DB_DATABASE'] . ';host=' . $_ENV['DB_HOST'], $_ENV['DB_USER'], $_ENV['DB_PASSWORD']);
$needsRefresh = $database->query("SELECT 1 FROM force_refresh WHERE server='" . gethostname() . "'")->fetchColumn();
if ($needsRefresh) {
    exec('php '.__DIR__.'/cron.php');
}
