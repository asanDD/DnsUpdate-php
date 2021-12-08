<?php
namespace DnsUpdate;

/**
Author: ASAN
Date: 2021.09.19
Version: 001.010

This is a php-script to update DNS records through registrars API. At the moment only the registar INWX is supported.
To use this script, copy this script and the "vendor" dir to a webdir and create a php file, that calls this script.
Example: example.php
<?php
require "inc/DnsUpdate.php";
 
header('Content-type: text/plain; charset=utf-8');
$updater = new \DnsUpdate\DnsUpdate_INWX();
$updater->updateDnsRecord();
?>

Configure your Router to call this script to update the DNS Record (Dynamic DNS Function). The script may be called with the 
following parameters.

domains = A domain or a comma seperated list without whitespaces of domains, which records should be updated.
ip4addr = The new IPv4 address. Can be left out if not needed. Example format: 142.250.181.206
ip6prefix = The prefix of the new IPv6 address. The prefix will be combined with given IPv6 address. 
        Can be left out if not needed. Fromat example: 2a00:1450:4005:80a::/64
ip6addr = The new IPv6 address. If the parameter "ip6prefix" is defined, then only the identifier-part of this IP 
        will be used and combined with the prefix from the parameter "ip6prefix".
        Format example: 2a00:1450:4005:80a:0000:0000:0000:200e
determineip6= If "true", then the IPv6 will be determined by the ip-command on the host linux machine.
        The parameter "ip6prefix" and "ip6addr" will be ignored.
key= A key that may be needed to login into the API-account on some registrars.

This script supports three modes to determine the new IPv6 address.
1. The new address is handed over in the parameter "ip6addr".
2. The new address is formed by combining the parameters "ip6addr" and "ip6prefix".
3. The new address is determined by the command "ip" on the server itself.

Examples URL for Router Fritzbox:
Server IP: 10.10.10.10
Port: 80
http://10.10.10.10:80/path/to/script/example.php?domains=<domain>,second.domain.com,third.domain.com&ip4addr=<ipaddr>&determineip6=true
http://10.10.10.10:80/path/to/script/example.php?domains=<domain>,second.domain.com&ip4addr=<ipaddr>&ip6prefix=<ip6lanprefix>&ip6addr=2a00:1450:4005:80a::200e

The parameter in <> will be replaced by the Router.

The script was tested with a Fritzbox 3390. This model does not support the newer variable <ip6lanprefix>. 
Therefore the server has to determine the IPv6 address itself. Newer models could use the variable <iP6lanprefix>.

Library version used:
"inwx/domrobot": "^3.2"


tips:
The server needs some time to update its own ip. The script sleeps therefor a few seconds. If the script times out, then you want to increase the time the script is allowed to run. In nginx this can be done with the following parameter: fastcgi_read_timeout 140s;
package you may need to install: php-curl

**/


include __DIR__ . '/vendor/autoload.php';

class Exception extends \Exception {}

class ValueException extends Exception {};
class FunctionException extends Exception {};
class ConnectionException extends Exception {};

/**
* A abstract class to update DNS records through registrars API.
* To use this class, a new class that implements the registrar's API must inherit this class.
* The class DnsUpdate_INWX for the registrar INWX is defined below this class.
**/
abstract class DnsUpdate{
    
    private const CODE_BADREQUEST = 400;
    private const CODE_INTERNALSERVERERROR = 500;
    
    private const IPV6INTCOUNT = 8;
    private const IPV6INTBIT = 16;
    private const MASKONE = 0xffff;
    private const MASKZERO = 0x0000;
    
    // time to wait to give the server time to get a new ipv6 address.
    private const WAITFORNEWIP = 10; // in seconds
    // max time that communication with the api is allowed to take
    private const TIMELIMIT_API = 120; // in seconds
    
    /**
    * Update the dns record with the parameter given in the URL.
    **/
    final public function updateDnsRecord():bool {
        try {
            $domains = "";
            $ip4addr = "";
            $ip6addr = "";
            $ip6prefix = "";
            $determineip6 = false;
            $key = "";
            $user = "";
            $pass = "";
            $result = false;
            
            // GET parameter from URL
            if (isset($_GET['domains'])) {
                $domains = filter_input(INPUT_GET, 'domains', FILTER_SANITIZE_STRING);
                if ($domains != "") {
                    $domains = explode(",", $domains);
                }
            } 
            if (isset($_GET['ip4addr'])) {
                $ip4addr = filter_input(INPUT_GET, 'ip4addr', FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
            }
            if (isset($_GET['ip6addr'])) {
                $ip6addr = filter_input(INPUT_GET, 'ip6addr', FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
            }
            if (isset($_GET['ip6prefix'])) {
                $ip6prefix = filter_input(INPUT_GET, 'ip6prefix');
            }
            if (isset($_GET['determineip6'])) {
                $determineip6 = filter_input(INPUT_GET, 'determineip6', FILTER_VALIDATE_BOOLEAN);
            }
            if (isset($_GET['key'])) {
                $key = filter_input(INPUT_GET, 'key', FILTER_SANITIZE_STRING);
            }
            
            // get username and password from $_SERVER
            if (isset($_SERVER['PHP_AUTH_USER'])) {
                $user = filter_var($_SERVER['PHP_AUTH_USER'], FILTER_SANITIZE_STRING);
            } else {
                // ask client for username and password.
                header('WWW-Authenticate: Basic realm="INWX API Access"');
                header('HTTP/1.0 401 Unauthorized');
                return false;
            }
            if (isset($_SERVER['PHP_AUTH_PW'])) {
                $pass = filter_var($_SERVER['PHP_AUTH_PW'], FILTER_SANITIZE_STRING);
            } else {
                // ask client for username and password.
                header('WWW-Authenticate: Basic realm="INWX API Access"');
                header('HTTP/1.0 401 Unauthorized');
                return false;
            }
            
            // check if all needed parameter exist.
            if (count($domains) < 1) {
                $this->handleFailure(self::CODE_BADREQUEST, "No domains found in URL.");
                return false;
            }
            if (empty($ip4addr) && empty($ip6addr) && !$determineip6) {
                $this->handleFailure(self::CODE_BADREQUEST, "No IP found in URL.");
                return false;
            }
            if (empty($user)) {
                $this->handleFailure(self::CODE_BADREQUEST, "No username provided.");
                return false;
            }
            if (empty($pass)) {
                $this->handleFailure(self::CODE_BADREQUEST, "No password provided.");
                return false;
            }
            
            // Give server time to get a new ipv6 address.
            sleep(self::WAITFORNEWIP); 
            // get ipv6 via internal function
            if ($determineip6) {
                try {
                    $ip6addr = $this->getInterfaceGlobalIpv6();
                }
                catch (Exception $e) {
                    $this->handleException(self::CODE_INTERNALSERVERERROR, $e);
                    return false;
                }
            // create ipv6 with ipv6 and prefix from url-parameter
            } else if (!empty($ip6addr) && !empty($ip6prefix)) {
                try {
                    $ip6addr = $this->changePrefixOfIpv6($ip6prefix, $ip6addr);
                }  
                catch (ValueException $e) {
                    $this->handleException(self::CODE_BADREQUEST, $e);
                    return false;
                }
                catch (Exception $e) {
                    $this->handleException(self::CODE_INTERNALSERVERERROR, $e);
                    return false;
                }
            }
            // else: take ipv6 from url parameter
            
            set_time_limit(self::TIMELIMIT_API); //set timelimit for execution.
            $result = $this->sendDataViaApi($domains, $ip4addr, $ip6addr, $user, $pass, $key);
        } 
        catch (Exception $e) {
            $this->handleException(self::CODE_INTERNALSERVERERROR, $e);
            return false;
        }
        return $result;
    }
    
    
    /**
    * This function must be overwritten by classes that inherit from this class.
    * Send the data via API to update the record.
    * @param array $domains : An array of strings that contains all domain names
    * @param string $ipv4addr : The ipv4-address for the domains. May be empty.
    * @param string $ipv6addr : The ipv6-address for the domains. May be empty.
    * @param string $user : The username of the API-account.
    * @param string $pass : The password of the API-account.
    * @param string $key : A key that may be needed for the API-Account. May be empty.
    * @return : true, if dns record update was successful.
    * @throw Exception : If an error with the connection occured.
    **/
    abstract protected function sendDataViaApi(
        array $domains, 
        string $ip4addr, 
        string $ip6addr, 
        string $user, 
        string $pass, 
        string $key):bool;
    
    
    /**
    * Get the globel IPv6 of the main Interface of a Linux machine via ip command.
    * @return : a string that contains the ipv6. Format example: 2a00:1450:4005:80a:0000:0000:0000:200e
    * @throw FunctionException : if the determined ip is invalid
    */
    private function getInterfaceGlobalIpv6():string {
        $global_ipv6 = "";
        $json = json_decode(exec('/usr/sbin/ip -j -f inet6 addr show scope global -deprecated'),true);
        foreach ($json[0]['addr_info'] as $addr_info) {
            $ipv6 = $addr_info['local'];
            if (strpos($ipv6, 'fd') !== 0 && strpos($ipv6, 'fc') !== 0) {
                $global_ipv6 = $ipv6;
                break;
            } 
        }
        $global_ipv6 = filter_var($global_ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        if (!$global_ipv6) {
            throw new FunctionException('Ip determined with "ip" command is invalid.');
        }
        return $global_ipv6;
    }
    
    /**
    * Build an ipv6 from an ipv6 and a ipv6-prefix
    * @param string $ipv6prefix : The ipv6-prefix. Format example: 2a00:1200:aaaa:bbbb::/64
    * @param string $ip6addr : The ipv6 that is used as identifier. The Prefix of this ip will be changed to
    *                   the given ipv6-prefix. Format example: 2a00:1450:4005:80a:0000:0000:0000:200e
    * @return : A string that contains the combined ipv6. 
    *           Format example: 2a00:1200:aaaa:bbbb:0000:0000:0000:200e
    * @throw ValueException : if ipv6 of $ip6prefix or $ip6addr are invalid.
    * @throw FunctionException : if created ipv6 is invalid.
    */
    private function changePrefixOfIpv6(string $ip6prefix, string $ip6addr):string {
        $ipv6 = "";
        $ipv6Arr;
        $prefix = "";
        $prefixLength = 0;
        $prefixArr;
        $subnetmask;
        
        // check if $ip6addr is valid.
        $ipv6 = filter_var($ip6addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        if (!$ipv6) {
            throw new ValueException("Ip $ip6addr is not valid.");
        }
        
        // check if $ip6prefixr is valid.
        $arr = explode("/", $ip6prefix);
        if (count($arr) != 2) {
            throw new ValueException("Ip-prefix $ip6prefix is not valid.");
        }
        $prefix = $arr[0];
        $prefixLength = intval($arr[1]);
        if ($prefixLength < 1 || $prefixLength > 128) {
            throw new ValueException("Ip-prefix $ip6prefix is not valid.");
        }
        $prefix = filter_var($prefix, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        if (!$prefix) {
            throw new ValueException("Ip-prefix $ip6prefix is not valid.");
        }
        
        // convert ip and prefix to arrays that represent that the ips.
        $ipv6Arr = $this->ipStringToArray($ipv6);
        $prefixArr = $this->ipStringToArray($prefix);
        
        // create subnetmask from prefix
        // determine position of first non static bit
        $index = intdiv($prefixLength, self::IPV6INTBIT);
        $bit = $prefixLength % self::IPV6INTBIT;
        // fill subnet mask with 1
        $subnetmask = array_fill(0, self::IPV6INTCOUNT, self::MASKONE);
        $bitmask = self::MASKONE;
        // fill subnetmask with zeros beginning at the first non static bit
        if ($bit > 0) {
            $bitmask = (($bitmask << (self::IPV6INTBIT - $bit)) &  self::MASKONE);
            $subnetmask[$index] = $bitmask;
            $index++;
        }
        $bitmask = self::MASKZERO;
        for (; $index < self::IPV6INTCOUNT; $index++) {
            $subnetmask[$index] = $bitmask;
        }
        
        // combine ipv6 and prefix dependend on the subnetmask.
        for ($index = 0; $index < self::IPV6INTCOUNT; $index++) {
            $ipv6Arr[$index] = ($subnetmask[$index] & $prefixArr[$index]) | ((~ $subnetmask[$index]) & $ipv6Arr[$index]);
        }
        
        // convert the ip array back to a string
        return $this->ipArrayToString($ipv6Arr);
    }
    
    /**
    * Converts an ipv6 address string to an array that contains the ip.
    * The array contains 8 elements that contain a 16bit integer each. These elements represent
    * the ipv6. The array starts with index = 0.
    * @param string $ipv6 : ipv6 address string like 2a00:1450:4005:80a:0000:0000:0000:200e
    * @return: An array of 8 16bit integer that represent the ipv6.
    */
    private function ipStringToArray(string $ipv6):array {
        $arr = array_fill(0, self::IPV6INTCOUNT, self::MASKZERO);
        $ipParts = explode(":", $ipv6);
        $ipPartsCount = count($ipParts);
        $index = 0;
        foreach ($ipParts as $ipPart) {
            // convert ipv6 string into an array of 8 16bit integer
            if ($ipPart != "") {
                $arr[$index] = hexdec($ipPart);
                $index++;
            } else {
                // if an :: was found in inputIp, then fill with as much zeros as needed to create
                // a ipv6 with 8 16bit integer
                $zerosIndex = self::IPV6INTCOUNT - $ipPartsCount + 1 + $index;  // +1 -> One of the parts is an empty string
                for (; $index < $zerosIndex; $index++) {
                    $arr[$index] = 0;
                }
            }
        }
        return $arr;
    }
    
    /**
    * Converts an array of 8 16bit integer that represents an ipv6 to a string.
    * Format example: 2a00:1450:4005:80a:0000:0000:0000:200e
    * @param array $ipArr : The array that represents an ipv6
    * @return : A string of an ipv6.
    * @throw FunctionException : If the created ipv6 string is not valid.
    */
    private function ipArrayToString(array $ipArr):string {
        $str = "";
        $count = count($ipArr);
        $index = 1;
        $result = "";
        foreach ($ipArr as $ipPart) {
            $str .= dechex($ipPart);
            if ($index < self::IPV6INTCOUNT) {
                $str .= ":";
            }
            $index++;
        }
        $result = filter_var($str, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        if (!$result) {
            throw new FunctionException("Created ip $str is not valid.");
        }
        return $result;
    }
    
    private function handleFailure(int $httpcode, string $logmessage) {
        http_response_code($httpcode);
        if (!empty($logmessage)) {
            error_log("DnsUpdateinwx.php: Failure: $logmessage");
        }
    }
    private function handleException(int $httpcode, Exception $e) {
        http_response_code($httpcode);
        $txt = "DnsUpdateinwx.php: Exception: {$e->getFile()} : {$e->getLine()} : {$e->getMessage()}";
        error_log($txt);
    }
}


class DnsUpdate_INWX extends DnsUpdate{
    /**
    * This function must be overwritten by classes that inherit from this class.
    * Send the data via API to update the record.
    * @param array $domains : An array of strings that contains all domain names
    * @param string $ipv4addr : The ipv4-address for the domains. May be empty.
    * @param string $ipv6addr : The ipv6-address for the domains. May be empty.
    * @param string $user : The username of the API-account.
    * @param string $pass : The password of the API-account.
    * @param string $key : A key that may be needed for the API-Account. May be empty.
    * @return : true, if dns record update was successful.
    * @throw ConnectionException : If an error with the connection occured.
    **/
    protected function sendDataViaApi(
        array $domains, 
        string $ip4addr, 
        string $ip6addr, 
        string $user, 
        string $pass, 
        string $key):bool 
    {
        // connect
        $recordId = -1;
        $domrobot = new \INWX\Domrobot();
        $result = $domrobot->setLanguage('en')
            // use the OTE endpoint for testing
            // ->useOte()
            // or use the LIVE endpoint instead for real changes
            ->useLive()
            // use the JSON-RPC API
            ->useJson()
            // or use the XML-RPC API instead
            //->useXml()
            // debug will let you see everything you're sending and receiving
            // ->setDebug(true)
            ->login($user, $pass);
        
        // update record for each domain
        if ($result['code'] == 1000) {
            foreach ($domains as $domain) {
                $recordId = $this->requestRecordId($domrobot, $domain);
                if ($recordId["ipv4"] > -1 && !empty($ip4addr)) {
                    $this->updateRecord($domrobot, $recordId["ipv4"], $ip4addr);
                }
                if ($recordId["ipv6"] > -1 && !empty($ip6addr)) {
                    $this->updateRecord($domrobot, $recordId["ipv6"], $ip6addr);
                }
            }
            
            // disconnect
            $domrobot->logout();
        } else {
            throw new ConnectionException("Connection error occured.");
            return false;
        }
        return true;
    }
    
    /**
    * Requests the Nameserver-Record ID of a domain.
    *
    * @param &$domrobot : ref to connected domrobot
    * @param String $domain : the domain for which the id is requested
    * @return : An array that contains the ids for ipv6 and ipv4 records. 
    *           Key for ipv4 = "ipv4" , key for ipv6 = "ipv6"
    *           Returns an element with value -1 if record was not found.
    */
    private function requestRecordId(&$domrobot, string $domain):array {
        $recordId = array("ipv4" => -1, "ipv6" => -1);
        
        //determine domain-name and record-name.
        $domain_exploded = explode(".", $domain);
        $domain_exploded_length = count($domain_exploded);
        $domain = $domain_exploded[$domain_exploded_length - 2] . "." . $domain_exploded[$domain_exploded_length - 1];
        unset($domain_exploded[$domain_exploded_length - 1]);
        unset($domain_exploded[$domain_exploded_length - 2]);
        $name= implode(".", $domain_exploded);
        
        //do request
        $obj = "nameserver";
        $meth = "info";
        $params = array();
        $params['domain'] = $domain;
        $params['name'] = $name;
        $res = $domrobot->call($obj,$meth,$params);
        foreach ($res['resData']['record'] as $record) {
            if ($record['type'] == 'A') {
                $recordId["ipv4"] = $record['id'];
            }
            if ($record['type'] == 'AAAA') {
                $recordId["ipv6"] = $record['id'];
            }
        }
        return $recordId;
    }
    
    /**
    * Set new ip-address for nameserver-record
    *
    * @param &$domrobot : Ref to connected domrobot
    * @param int $recordId : ID of nameserver-record
    * @param string $ipAddr : new ip-address
    */
    private function updateRecord(&$domrobot, int $recordId, string $ipAddr) {
        $obj = "nameserver";
        $meth = "updateRecord";
        $params = array();
        $params['id'] = $recordId;
        $params['content'] = $ipAddr;
        $res = $domrobot->call($obj,$meth,$params);
    }

}

    
?>
