
<?php
require "inc/DnsUpdate.php";
 
header('Content-type: text/plain; charset=utf-8');
$updater = new \DnsUpdate\DnsUpdate_INWX();
$updater->updateDnsRecord();
?>
