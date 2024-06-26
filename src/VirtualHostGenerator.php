<?php

namespace De\Idrinth\WebRoot;

use PDO;
use PDOStatement;
use Twig\Environment;

class VirtualHostGenerator
{
    private PDO $database;
    private Environment $twig;
    private int $rotateLogDays;

    public function __construct(PDO $database, Environment $twig, int $rotateLogDays)
    {
        $this->database = $database;
        $this->twig = $twig;
        $this->rotateLogDays = $rotateLogDays;
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
            $virtualhosts[] = [
                'domain' => $vhost,
                'webroot' => $row['extra_webroot'] == '1' ? "/var/$vhost/public" : "/var/$vhost",
                'root' => "/var/$vhost",
                'admin' => $row['admin'],
                'aliases' => $aliases,
                'atatus_license_key' => $row['atatus_api_key'],
            ];
            if (!is_dir('/var/' . $vhost)) {
                mkdir('/var/' . $vhost);
                chown('/var/' . $vhost, 'www-data');
            }
            if ($row['extra_webroot'] === '1' && !is_dir('/var/' . $vhost . '/public')) {
                mkdir('/var/' . $vhost . '/public');
                chown('/var/' . $vhost . '/public', 'www-data');
            }
            $today = date('Ymd');
            if (! is_file("/var/log/$vhost-access.$today.log")) {
                rename("/var/log/$vhost-access.log", "/var/log/$vhost-access.$today.log");
            }
            if (! is_file("/var/log/$vhost-error.$today.log")) {
                rename("/var/log/$vhost-error.log", "/var/log/$vhost-error.$today.log");
            }
            $tooOld = date('Ymd', strtotime("now -{$this->rotateLogDays}days"));
            if (is_file("/var/log/$vhost-access.$tooOld.log")) {
                unlink("/var/log/$vhost-access.$tooOld.log");
            }
            if (is_file("/var/log/$vhost-error.$tooOld.log")) {
                unlink("/var/log/$vhost-error.$tooOld.log");
            }
        }
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
    public function create()
    {
        exec("a2dissite default");
        exec("a2dissite http-only");
        exec("a2dissite http-redirect-only");
        exec("a2dissite http-proxy-only");
        file_put_contents('/etc/apache2/ports.conf', str_replace("Listen 80\n", '', file_get_contents('/etc/apache2/ports.conf')));
        exec("service apache2 restart");
        sleep(60);
        $hostname = gethostname();
        $ip = gethostbyname($hostname);
        $stmt = $this->database->prepare('SELECT * FROM server WHERE hostname=:hostname');
        $stmt->execute([':hostname' => $hostname]);
        $server = $stmt->fetch();
        if (!$this->certificate($hostname, $server['admin'])) {
            return;
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
                ],
            ])
        );
        $stmt = $this->database->prepare('SELECT virtualhost.aid,virtualhost.name,virtualhost.extra_webroot,domain.domain,domain.is_proxied,domain.admin,owner.atatus_api_key
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
        exec("a2ensite default");
        exec("a2ensite http-only");
        exec("a2ensite https-only");
        exec("a2ensite http-redirect-only");
        exec("a2ensite https-redirect-only");
        exec("a2ensite http-proxy-only");
        exec("a2ensite https-proxy-only");
        file_put_contents('/etc/apache2/ports.conf', str_replace("Listen 443\n", "Listen 80\nListen 443\n", file_get_contents('/etc/apache2/ports.conf')));
        exec("service apache2 restart");
    }
}
