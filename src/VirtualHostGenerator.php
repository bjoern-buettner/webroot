<?php

namespace De\Idrinth\WebRoot;

use PDO;
use PDOStatement;
use Twig\Environment;

class VirtualHostGenerator
{
    private const array REQUIRED_APACHE2_MODULES = [
        'ssl',
        'rewrite',
        'proxy',
    ];
    private const array SUGGESTED_APACHE2_MODULES = [
        'expires',
        'deflate',
        'evasive20',
        'security2',
        'mpm_itk',
        'php',
        'headers',
    ];
    private const array HTTP_SITES = [
        'default',
        'http-only',
        'http-redirect-only',
        'http-proxy-only',
    ];
    private const array HTTPS_SITES = [
        'https-only',
        'https-redirect-only',
        'https-proxy-only',
    ];

    public function __construct(private PDO $database, private Environment $twig, private int $rotateLogDays, private bool $enableSuggested)
    {
    }
    private function certificate(string $vhost, string $admin): bool
    {
        $from = "/etc/letsencrypt/live/$vhost";
        if (!is_file("$from/cert.pem") || filemtime("$from/cert.pem") < time() - 60*24*60*60) {
            exec(
                "certbot certonly"
                . " --non-interactive"
                . " --expand"
                . " --quiet "
                . "--standalone "
                . "--domains=$vhost"
                . " --agree-tos"
                . " --email $admin"
            );
            if(!is_file("$from/cert.pem")) {
                return false;
            }
        }
        return true;
    }
    private function buildHostList(PDOStatement $statement, array &$virtualhosts, string $ip): void
    {
        $hasCoreRuleset = (int) is_dir('/opt/coreruleset'); // https://github.com/coreruleset/coreruleset
        foreach ($statement->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $vhost = trim($row['name'] . '.' . $row['domain'], '.');
            echo "Handling $vhost\n";
            if ($row['is_proxied'] == 0 && gethostbyname($vhost . '.') !== $ip) {
                continue;
            }
            if (!$this->certificate($vhost, $row['admin'])) {
                continue;
            }
            $aliases = [];
            echo "  Handling Alias www.$vhost\n";
            if (($row['is_proxied'] == 1 || gethostbyname("www.$vhost.") === $ip) && $this->certificate("www.$vhost", $row['admin'])) {
                $aliases[] = "www.$vhost";
            }
            $stmt = $this->database->prepare('SELECT virtualhost_domain_alias.subdomain,domain.domain,domain.admin '
                . 'FROM virtualhost_domain_alias '
                . 'INNER JOIN domain ON domain.aid=virtualhost_domain_alias.domain '
                . 'WHERE virtualhost_domain_alias.virtualhost=:id');
            $stmt->execute([':id' => $row['aid']]);
            foreach ($stmt->fetchAll() as $alias) {
                $domain = trim($alias['subdomain'] . '.' . $alias['domain'], '.');
                echo "  Handling Alias $domain\n";
                if (gethostbyname("$domain.") === $ip && $this->certificate($domain, $alias['admin'])) {
                    $aliases[] = $domain;
                }
                echo "  Handling Alias www.$domain\n";
                if (gethostbyname("www.$domain.") === $ip && $this->certificate("www.$domain", $alias['admin'])) {
                    $aliases[] = "www.$domain";
                }
            }
            $user = md5($vhost);
            $virtualhosts[] = [
                'domain' => $vhost,
                'webroot' => $row['extra_webroot'] == '1' ? "/var/$vhost/public" : "/var/$vhost",
                'root' => "/var/$vhost",
                'admin' => $row['admin'],
                'aliases' => $aliases,
                'atatus_license_key' => $row['atatus_api_key'],
                'user' => $user,
                'hasCoreRuleset' => $hasCoreRuleset,
                'isWordpress' => (int) ($row['is_wordpress'] == '1'),
                'isNextcloud' => (int) ($row['is_nextcloud'] == '1'),
            ];
            if (!is_dir('/var/' . $vhost)) {
                mkdir('/var/' . $vhost);
            }
            if ($row['extra_webroot'] === '1' && !is_dir('/var/' . $vhost . '/public')) {
                mkdir('/var/' . $vhost . '/public');
            }
            shell_exec("useradd -c \"$vhost\" $user || true");
            $this->chowngrp('/var/' . $vhost, $user);
            $today = date('Ymd');
            $tooOld = date('Ymd', strtotime("now -{$this->rotateLogDays}days"));
            foreach (['access', 'error', 'php', 'evasive'] as $type) {
                if (! is_file("/var/log/$vhost-$type.$today.log")) {
                    rename(
                        "/var/log/$vhost-$type.log",
                        "/var/log/$vhost-$type.$today.log"
                    );
                }
                if (is_file("/var/log/$vhost-$type.$tooOld.log")) {
                    unlink("/var/log/$vhost-$type.$tooOld.log");
                }
            }
        }
    }
    private function chowngrp(string $path, string $owner): void
    {
        if (is_dir($path)) {
            foreach(array_diff(scandir($path), ['.', '..']) as $file) {
                $this->chowngrp($path . '/' . $file, $owner);
            }
        }
        chown($path, $owner);
        chgrp($path, $owner);
    }
    private function buildLinkList(PDOStatement $statement, array &$virtualhosts, string $ip): void
    {
        foreach ($statement->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $vhost = trim($row['name'] . '.' . $row['domain'], '.');
            echo "Handling $vhost => {$row['target']}\n";
            if (gethostbyname($vhost . '.') !== $ip) {
                continue;
            }
            if (!$this->certificate($vhost, $row['admin'])) {
                continue;
            }
            $aliases = [];
            echo "  Handling Alias www.$vhost => {$row['target']}\n";
            if (gethostbyname("www.$vhost.") === $ip && $this->certificate("www.$vhost", $row['admin'])) {
                $aliases[] = "www.$vhost";
            }
            $virtualhosts[] = [
                'admin' => $row['admin'],
                'domain' => $vhost,
                'aliases' => $aliases,
                'target' => $row['target'],
            ];
        }
    }
    private function handleDefault(string $hostname): bool
    {
        $stmt = $this->database->prepare('SELECT * FROM server WHERE hostname=:hostname');
        $stmt->execute([':hostname' => $hostname]);
        $server = $stmt->fetch();
        if (!$this->certificate($hostname, $server['admin'])) {
            return false;
        }
        file_put_contents(
            '/etc/apache2/sites-available/default.conf',
            $this->twig->render('default.twig', [
                'host' => [
                    'domain' => $hostname,
                    'webroot' => "/var/www/public",
                    'root' => "/var/www",
                    'admin' => $server['admin'],
                    'aliases' => [],
                    'atatus_license_key' => $server['atatus_license_key'],
                    'user' => 'www-data',
                    'hasCoreRuleset' => is_dir('/opt/coreruleset'), // https://github.com/coreruleset/coreruleset
                ],
            ])
        );
        return true;
    }
    private function handleVirtualHosts(string $hostname, string $ip): void
    {
        $stmt = $this->database->prepare('SELECT virtualhost.aid,virtualhost.name,virtualhost.is_nextcloud,virtualhost.is_wordpress,virtualhost.extra_webroot,domain.domain,domain.is_proxied,domain.admin,owner.atatus_api_key
FROM virtualhost
INNER JOIN server ON server.aid=virtualhost.server
INNER JOIN domain ON domain.aid=virtualhost.domain
INNER JOIN owner ON owner.aid=domain.owner
WHERE server.hostname=:hostname');
        $stmt->execute([':hostname' => $hostname]);
        $virtualhosts = [];
        $this->buildHostList($stmt, $virtualhosts, $ip);
        file_put_contents(
            '/etc/apache2/sites-available/http-only.conf',
            $this->twig->render('http-only.twig', [
                'virtualhosts' => $virtualhosts,
            ])
        );
        file_put_contents(
            '/etc/apache2/sites-available/https-only.conf',
            $this->twig->render('https-only.twig', [
                'virtualhosts' => $virtualhosts
            ])
        );
    }
    private function handleRedirects(string $hostname, string $ip): void
    {
        $stmt = $this->database->prepare('SELECT link.name,domain.domain,link.target,domain.admin
FROM link
INNER JOIN server ON link.server=server.aid
INNER JOIN domain ON domain.aid=link.domain
WHERE server.hostname=:hostname');
        $stmt->execute([':hostname' => $hostname]);
        $virtualhosts = [];
        $this->buildLinkList($stmt, $virtualhosts, $ip);
        file_put_contents(
            '/etc/apache2/sites-available/http-redirect-only.conf',
            $this->twig->render('http-redirect-only.twig', [
                'virtualhosts' => $virtualhosts,
            ])
        );
        file_put_contents(
            '/etc/apache2/sites-available/https-redirect-only.conf',
            $this->twig->render('https-redirect-only.twig', [
                'virtualhosts' => $virtualhosts
            ])
        );
    }
    private function handleProxy(string $hostname, string $ip): void
    {
        $stmt = $this->database->prepare('SELECT proxy.name,domain.domain,proxy.target,domain.admin
FROM proxy
INNER JOIN server ON proxy.server=server.aid
INNER JOIN domain ON domain.aid=proxy.domain
WHERE server.hostname=:hostname');
        $stmt->execute([':hostname' => $hostname]);
        $virtualhosts = [];
        $this->buildLinkList($stmt, $virtualhosts, $ip);
        file_put_contents(
            '/etc/apache2/sites-available/http-proxy-only.conf',
            $this->twig->render('http-proxy-only.twig', [
                'virtualhosts' => $virtualhosts,
            ])
        );
        file_put_contents(
            '/etc/apache2/sites-available/https-proxy-only.conf',
            $this->twig->render('https-proxy-only.twig', [
                'virtualhosts' => $virtualhosts
            ])
        );
    }
    private function stopApache2Http(): void
    {
        foreach (self::HTTP_SITES as $site) {
            exec("a2dissite $site");
        }
        file_put_contents('/etc/apache2/ports.conf', str_replace("Listen 80\n", '', file_get_contents('/etc/apache2/ports.conf')));
        exec("service apache2 restart");
        sleep(60);
    }
    private function startApache2(): void
    {
        foreach (self::REQUIRED_APACHE2_MODULES as $module) {
            exec("a2enmod $module");
        }
        if ($this->enableSuggested) {
            foreach (self::SUGGESTED_APACHE2_MODULES as $module) {
                exec("a2enmod $module");
            }
        }
        foreach (self::HTTP_SITES as $site) {
            exec("a2ensite $site");
        }
        foreach (self::HTTPS_SITES as $site) {
            exec("a2ensite $site");
        }
        file_put_contents('/etc/apache2/ports.conf', str_replace("Listen 443\n", "Listen 80\nListen 443\n", file_get_contents('/etc/apache2/ports.conf')));
        exec("service apache2 restart");
    }
    public function create(): void
    {
        $hostname = gethostname();
        try {
            $this->database->exec("DELETE FROM force_refresh WHERE server='$hostname'");
        } catch (\PDOException $e) {
            // nothing to do here
        }
        $this->stopApache2Http();
        if (!$this->handleDefault($hostname)) {
            return;
        }
        $ip = gethostbyname($hostname);
        $this->handleVirtualHosts($hostname, $ip);
        $this->handleRedirects($hostname, $ip);
        $this->handleProxy($hostname, $ip);
        $this->startApache2();
    }
}
