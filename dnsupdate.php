
<?php
require "inc/DnsUpdate.php";
$updater = new \DnsUpdate\DnsUpdate_INWX();
$updater->updateDnsRecord();
?>
