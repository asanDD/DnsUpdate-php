# DnsUpdate-php


A php-script to update name server records. At the moment only the registrar INWX is supported.


### How to use this script:

Host this script and its dependencies on a php enabled webserver. All dependencies are included in the folder 'inc'.  
Call this script with your router/modem when it gets a new IP assigned.  


### Example and explanation of the URL parameters.

https://<user\>:<password\>@<webserver_ip\>:<webserver_port\>/path/to/script/dnsupdate.php
?key=<account_key\>&domain1=<domain\>,<ipv4\>,<ipv6\>,<ipv6prefix\>,<determineip6\>&domain2=<domain\>,<ipv4\>,<ipv6\>,<ipv6prefix\>,<determineip6\>&domain3=<domain\>

https://helga:12345@192.168.1.15:5555/path/to/script/dnsupdate.php
?key=4411&domain1=test1.mydomain.com,142.251.40.238,2607:f8b0:4005:808::200e,0,false&domain2=test2.mydomain.com,172.217.5.110,0,0,true&domain3= test3.mydomain.com  


### Parameter:
<pre>
key         : Not used yet.  
domain1     : Data for the first domain. Up to 50 domains are supported.  
domain2     : Data for the second domain.  
</pre>

### Placeholder:
<pre>
user            : Username of the user account.  
password        : Password of the user account.  
webserver_ip    : IP of the webserver on which the php script is hosted.  
webserver_port  : Port of the webserver on which the php script is hosted.  
account_key     : Not used yet.  
domain          : Domain name.  
ipv4            : New IPv4 address of the domain. Set to 0 if this domain has no IPv4. 
                  If left empty, then the IPv4 from the previous domain will be used. 
                  Format:  172.217.5.110  
ipv6            : New IPv6 address of the domain. Set to 0 if this domain has no IPv6. 
                  If left empty, then the IPv6 from the previous domain will be used. 
                  Format:  2607:f8b0:4005:808::200e  
ipv6prefix      : A prefix for the new IPv6 address. The new IPv6 address for the domain 
                  will be build from the given IPv6 and this prefix if the prefix was specified. 
                  Set to 0 if no prefix is needed. 
                  If left empty, then the prefix from the previous domain will be used. 
                  Format:  2611:a460:a460:808::200e/64  
determineip6    : Set to true if the new IPv6 should be determined by the server itself 
                  with the "ip" command. Else set to false.  
                  If left empty, then the boolean from the previous domain will be used.  
</pre>

### Information:

The basic auth method is used to transfer the user name and password. Be aware that the username and the password will not be encrypted if no https connection is used.  
The server needs some time to update its own IPv6 before it is able to determine its IPv6. Therefor the script sleeps a few seconds before trying to determine the IPv6. If the script times out, you want to increase the time the script is allowed to run. In nginx this can be done with the following parameter: fastcgi_read_timeout 140s;


### Information concerning router/modems Fritzbox:

The script was tested with a Fritzbox 3390 using the dyndns function of the Fritzbox.  
\- https does not work  
\- username and password can be saved in the input box.  
\- one domain name can be saved in the input box. This domain name will be used to check if the ip of the domain points to the Fritzbox.  

In the URL following placeholders can be used and will be replaced by the Fritzbox:  
<pre>
&lt;username&gt;        : User name saved in the input box.  
&lt;passwd&gt;          : Password saved in the input box.  
&lt;domain&gt;          : Will be replaced by domain saved in the input box.  
&lt;ipaddr&gt;          : Will be replaced by the current global IPv4 of the Fritzbox.  
&lt;ip6addr&gt;         : Will be replaced by the current global IPv6 of the Fritzbox.  
&lt;ip6lanprefix&gt;    : Will be replaced by the current global IPv6 prefix 
                    of the Fritzbox provided by the internet provider. 
                    This does not work with the Fritzbox 3390, 
                    but newer models support this placeholder.  
</pre>

### Example for a Fritzbox URL:

http://192.168.1.15:5555/path/to/script/dnsupdate.php
?key=4411&domain1=<domain\>,<ipaddr\>,<ip6addr\>,0,false&domain2=test2.mydomain.com,<ipaddr\>,0,0,true&domain3= test3.mydomain.com

