<?php

echo "Welcome to idrinth/webroot. Answer a few quick questions to have your system setup for use!\n\n";
echo "\nWhat is your mysql hostname?";
$hostname = trim(fgets(STDIN));
echo "\nWhat is your mysql username?";
$username = trim(fgets(STDIN));
echo "\nWhat is your mysql password?";
$password = trim(fgets(STDIN));
echo "\nWhat is your mysql database name?";
$database = trim(fgets(STDIN));
file_put_contents(dirname(__DIR__) . '/.env', "DB_DATABASE=$database
DB_USER=$username
DB_PASSWORD=$password
DB_HOST=$hostname
ROTATE_LOG_DAYS=7");
$pdo = new PDO("mysql:dbname=$database;host=$hostname", $username, $password);
$pdo->exec("CREATE TABLE IF NOT EXISTS `force_refresh` (
	`server` VARCHAR(255) NOT NULL COLLATE 'ascii_bin'
)
COLLATE='ascii_bin'
ENGINE=InnoDB;");
$pdo->exec("CREATE TABLE IF NOT EXISTS `owner` (
	`aid` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
	`name` VARCHAR(255) NOT NULL COLLATE 'ascii_bin',
	`atatus_license_key` VARCHAR(255) NOT NULL COLLATE 'ascii_bin',
	PRIMARY KEY (`aid`) USING BTREE
)
COLLATE='ascii_bin'
ENGINE=InnoDB;");
$pdo->exec("CREATE TABLE IF NOT EXISTS `domain` (
	`aid` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
	`domain` VARCHAR(255) NULL DEFAULT NULL COLLATE 'ascii_bin',
	`admin` VARCHAR(255) NOT NULL COLLATE 'ascii_bin',
	`owner` INT(10) UNSIGNED NOT NULL,
	`is_proxied` INT(1) UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (`aid`) USING BTREE,
	UNIQUE INDEX `domain` (`domain`) USING BTREE,
	CONSTRAINT `owner` FOREIGN KEY (`owner`) REFERENCES `virtualhosts`.`owner` (`aid`) ON UPDATE NO ACTION ON DELETE CASCADE
)
COLLATE='ascii_bin'
ENGINE=InnoDB;");
$pdo->exec("CREATE TABLE IF NOT EXISTS `server` (
	`aid` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
	`hostname` VARCHAR(255) NOT NULL COLLATE 'ascii_bin',
	`admin` VARCHAR(255) NOT NULL COLLATE 'ascii_bin',
	PRIMARY KEY (`aid`) USING BTREE,
	UNIQUE INDEX `hostname` (`hostname`) USING BTREE
)
COLLATE='ascii_bin'
ENGINE=InnoDB;");
$pdo->exec("CREATE TABLE IF NOT EXISTS `virtualhost` (
	`aid` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
	`hidden` TINYINT(3) UNSIGNED NOT NULL DEFAULT '0',
	`extra_webroot` TINYINT(3) UNSIGNED NOT NULL DEFAULT '0',
	`name` VARCHAR(255) NOT NULL COLLATE 'ascii_bin',
	`domain` INT(10) UNSIGNED NOT NULL,
	`server` INT(10) UNSIGNED NOT NULL,
	`is_wordpress` TINYINT(1) UNSIGNED NOT NULL DEFAULT 0,
	`is_nextcloud` TINYINT(1) UNSIGNED NOT NULL DEFAULT 0,
	PRIMARY KEY (`aid`) USING BTREE,
	UNIQUE INDEX `name_domain` (`name`, `domain`) USING BTREE,
	INDEX `domain` (`domain`) USING BTREE,
	INDEX `server` (`server`) USING BTREE,
	CONSTRAINT `domain` FOREIGN KEY (`domain`) REFERENCES `virtualhosts`.`domain` (`aid`) ON UPDATE NO ACTION ON DELETE CASCADE,
	CONSTRAINT `server` FOREIGN KEY (`server`) REFERENCES `virtualhosts`.`server` (`aid`) ON UPDATE NO ACTION ON DELETE CASCADE
)
COLLATE='ascii_bin'
ENGINE=InnoDB;");
$pdo->exec("CREATE TABLE IF NOT EXISTS `virtualhost_domain_alias` (
	`virtualhost` INT(10) UNSIGNED NOT NULL,
	`domain` INT(10) UNSIGNED NOT NULL,
	`subdomain` VARCHAR(255) NOT NULL DEFAULT '' COLLATE 'ascii_bin',
	UNIQUE INDEX `virtualhost_domain` (`virtualhost`, `domain`) USING BTREE,
	UNIQUE INDEX `domain_subdomain` (`domain`, `subdomain`) USING BTREE,
	CONSTRAINT `FK_virtualhost_domain_alias_domain` FOREIGN KEY (`domain`) REFERENCES `virtualhosts`.`domain` (`aid`) ON UPDATE NO ACTION ON DELETE NO ACTION,
	CONSTRAINT `FK_virtualhost_domain_alias_virtualhost` FOREIGN KEY (`virtualhost`) REFERENCES `virtualhosts`.`virtualhost` (`aid`) ON UPDATE NO ACTION ON DELETE NO ACTION
)
COLLATE='ascii_bin'
ENGINE=InnoDB;");
$pdo->exec("CREATE TABLE IF NOT EXISTS `link` (
	`aid` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
	`name` VARCHAR(255) NOT NULL COLLATE 'ascii_bin',
	`domain` INT(10) UNSIGNED NOT NULL,
	`server` INT(10) UNSIGNED NOT NULL,
	`target` TEXT NOT NULL COLLATE 'ascii_bin',
	PRIMARY KEY (`aid`) USING BTREE,
	UNIQUE INDEX `name_domain` (`name`, `domain`) USING BTREE,
	INDEX `domain` (`domain`) USING BTREE,
	INDEX `server` (`server`) USING BTREE,
	CONSTRAINT `link_domain` FOREIGN KEY (`domain`) REFERENCES `virtualhosts`.`domain` (`aid`) ON UPDATE NO ACTION ON DELETE CASCADE,
	CONSTRAINT `link_server` FOREIGN KEY (`server`) REFERENCES `virtualhosts`.`server` (`aid`) ON UPDATE NO ACTION ON DELETE CASCADE
)
COLLATE='ascii_bin'
ENGINE=InnoDB;");
$pdo->exec("CREATE TABLE IF NOT EXISTS `proxy` (
	`aid` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
	`name` VARCHAR(255) NOT NULL COLLATE 'ascii_bin',
	`domain` INT(10) UNSIGNED NOT NULL,
	`server` INT(10) UNSIGNED NOT NULL,
	`target` TEXT NOT NULL COLLATE 'ascii_bin',
	PRIMARY KEY (`aid`) USING BTREE,
	UNIQUE INDEX `name_domain` (`name`, `domain`) USING BTREE,
	INDEX `domain` (`domain`) USING BTREE,
	INDEX `server` (`server`) USING BTREE,
	CONSTRAINT `proxy_domain` FOREIGN KEY (`domain`) REFERENCES `virtualhosts`.`domain` (`aid`) ON UPDATE NO ACTION ON DELETE CASCADE,
	CONSTRAINT `proxy_server` FOREIGN KEY (`server`) REFERENCES `virtualhosts`.`server` (`aid`) ON UPDATE NO ACTION ON DELETE CASCADE
)
COLLATE='ascii_bin'
ENGINE=InnoDB;");
$pdo->prepare("INSERT INTO server (hostname) VALUES (:hostname)")->execute(['hostname' => gethostname()]);
echo "\nDatabase created and current hostname added to servers.\n";
