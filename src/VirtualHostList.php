<?php

class VirtualHostList {
    /**
     *
     * @var \PDO
     */
    protected $db;
    protected static $html = '<!DOCTYPE HTML><html><head><meta charset="utf-8"><meta name="wot-verification" content="cc2863b611487dd3791e"/><title>404 - Went wrong?</title></head><body><h1>404 - Did you misstep?</h1>
        <p>You managed to reach a domain, that is not used or unknown. Please find another domain to bother me ;)</p>
        <p>for example:</p>
        <ul>##LIST##</ul>
        <p>If you believe to see this page in error, please drop me a line at eldrim [AT] gmx [DOT] de.</p>
        <p>I\'m not tracking this domain besides the default server-logs, so I won\'t notice issues otherwise.</p>
        </body></html>';
    public function __construct() {
        $this->db = new \PDO('mysql:dbname=virtualhosts;host=localhost','virtualhosts','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');
    }
    public function show() {
        $content = '';
        foreach($this->db->query("SELECT * FROM host")->fetchAll(PDO::FETCH_CLASS,'VirtualHost') as $domain) {
            $content.=$domain->getListElement();
        }
        header('Content-Type: text/html',true,404);
        return str_replace('##LIST##',$content,self::$html);
    }
    public function build() {
        $content = '';
        foreach($this->db->query("SELECT * FROM host")->fetchAll(PDO::FETCH_CLASS,'VirtualHost') as $domain) {
            $content.=$domain->getHostEntry();
        }
        return $content . (new CatchAllVirtualHost())->getHostEntry() . (new BaseVirtualHost())->getHostEntry();
    }
}
