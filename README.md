# DnsUpdate-php

This is a php-script to update DNS records through registrars API. At the moment only the registar INWX is supported.
To use this script, copy this script and the "vendor" dir to a webdir and create a php file, that calls this script.

Example: example.php
```
<?php
require "inc/DnsUpdate.php";
 
header('Content-type: text/plain; charset=utf-8');
$updater = new \DnsUpdate\DnsUpdate_INWX();
$updater->updateDnsRecord();
?>
```

Configure your Router to call this script to update the DNS Record (Dynamic DNS Function). The script may be called with the 
following parameters.
- domains = A domain or a comma seperated list without whitespaces of domains, which records should be updated.
- ip4addr = The new IPv4 address. Can be left out if not needed. Example format: 142.250.181.206
- ip6prefix = The prefix of the new IPv6 address. The prefix will be combined with given IPv6 address. 
        Can be left out if not needed. Fromat example: 2a00:1450:4005:80a::/64
- ip6addr = The new IPv6 address. If the parameter "ip6prefix" is defined, then only the identifier-part of this IP 
        will be used and combined with the prefix from the parameter "ip6prefix".
        Format example: 2a00:1450:4005:80a:0000:0000:0000:200e
- determineip6= If "true", then the IPv6 will be determined by the ip-command on the host linux machine.
        The parameter "ip6prefix" and "ip6addr" will be ignored.
- key= A key that may be needed to login into the API-account on some registrars.

This script supports three modes to determine the new IPv6 address.
1. The new address is handed over in the parameter "ip6addr".
2. The new address is formed by combining the parameters "ip6addr" and "ip6prefix".
3. The new address is determined by the command "ip" on the server itself.

Example URLs for Router Fritzbox:
- Server IP: 10.10.10.10
- Port: 80
- "http://10.10.10.10:80/path/to/script/example.php?domains=<domain>,second.domain.com,third.domain.com&ip4addr=<ipaddr>&determineip6=true"
- "http://10.10.10.10:80/path/to/script/example.php?domains=<domain>,second.domain.com&ip4addr=<ipaddr>&ip6prefix=<ip6lanprefix>&ip6addr=2a00:1450:4005:80a::200e"

The parameters in <> will be replaced by the router.

The script was tested with a Fritzbox 3390. This model does not support the newer variable <ip6lanprefix>. 
Therefore the server has to determine the IPv6 address itself. Newer models could use the variable <iP6lanprefix>.

tip:
The server needs some time to update its own ip. The script sleeps therefor a few seconds. If the script times out, then you want to increase the time the script is allowed to run. In nginx this can be done with the following parameter: fastcgi_read_timeout 140s;

Library version used:
"inwx/domrobot": "^3.2"
