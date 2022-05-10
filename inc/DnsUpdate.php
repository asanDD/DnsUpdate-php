<?php
namespace DnsUpdate;

/**
Author:     ASAN
Date:       11.05.2022
Version:    001.022

A php-script to update name server records. At the moment only the registrar INWX is supported.


How to use this script:

Host this script and its dependencies on a php enabled webserver. All dependencies are included in the folder 'inc'.
Call this script with your router/modem when it gets a new IP assigned.


Example and explanation of the URL parameters.

https://<user>:<password>@<webserver_ip>:<webserver_port>/path/to/script/dnsupdate.php
?key=<account_key>&domain1=<domain>,<ipv4>,<ipv6>,<ipv6prefix>,<determineip6>&domain2=<domain>,<ipv4>,<ipv6>,<ipv6prefix>,<determineip6>&domain3=<domain>

https://helga:12345@192.168.1.15:5555/path/to/script/dnsupdate.php
?key=4411&domain1=test1.mydomain.com,142.251.40.238,2607:f8b0:4005:808::200e,0,false&domain2=test2.mydomain.com,172.217.5.110,0,0,true&domain3= test3.mydomain.com


Valid URL Parameter:

key         : Not used yet.
user        : Username for the registrar account.
password    : Password for the registrar account.
domain1     : Data for the first domain. Up to 50 domains are supported.
domain2     : Data for the second domain.


Placeholder:

user            : Username of the registrar account.
password        : Password of the registrar account.
webserver_ip    : IP of the webserver on which the php script is hosted.
webserver_port  : Port of the webserver on which the php script is hosted.
account_key     : Not used yet.
domain          : Domain name.
ipv4            : New IPv4 address of the domain. Set to 0 if this domain has no IPv4. If left empty, then the IPv4 from the previous domain will be used. Format:  172.217.5.110
ipv6            : New IPv6 address of the domain. Set to 0 if this domain has no IPv6. If left empty, then the IPv6 from the previous domain will be used. Format:  2607:f8b0:4005:808::200e
ipv6prefix      : A prefix for the new IPv6 address. The new IPv6 address for the domain will be build from the given IPv6 and this prefix if the prefix was specified. Set to 0 if no prefix is needed. If left empty, then the prefix from the previous domain will be used. Format:  2611:a460:a460:808::200e/64
determineip6    : Set to true if the new IPv6 should be determined by the server itself with the "ip" command. Else set to false.  If left empty, then the boolean from the previous domain will be used.


Information:

The basic auth method is used to transfer the user name and password. Be aware that the username and the password will not be encrypted if no https connection is used.
The server needs some time to update its own IPv6 before it is able to determine its IPv6. Therefor the script sleeps a few seconds before trying to determine the IPv6. If the script times out, you want to increase the time the script is allowed to run. In nginx this can be done with the following parameter: fastcgi_read_timeout 140s;


Information concerning router/modems Fritzbox:

The script was tested with a Fritzbox 3390 using the dyndns function of the Fritzbox.
- https does not work
- username and password can be saved in the input box.
- one domain name can be saved in the input box. This domain name will be used to check if the ip of the domain points to the Fritzbox.

In the URL following placeholders can be used and will be replaced by the Fritzbox:
<username>      : User name saved in the input box.
<passwd>        : Password saved in the input box.
<domain>        : Will be replaced by domain saved in the input box.
<ipaddr>        : Will be replaced by the current global IPv4 of the Fritzbox.
<ip6addr>       : Will be replaced by the current global IPv6 of the Fritzbox.
<ip6lanprefix>  : Will be replaced by the current global IPv6 prefix of the Fritzbox provided by the internet provider. This does not work with the Fritzbox 3390, but newer models support this placeholder.


Example for a Fritzbox URL:

http://192.168.1.15:5555/path/to/script/dnsupdate.php
?key=4411&domain1=<domain>,<ipaddr>,<ip6addr>,0,false&domain2=test2.mydomain.com,<ipaddr>,0,0,true&domain3=test3.mydomain.com



Library version used:
"inwx/domrobot": "3.3"
"monolog/logger": "2.3.2"
"psr/log": "^1.0.1"

**/

// autoloader for classes.
spl_autoload_register(function ($class) {
    $include_dir = 'inc/';
    $file = $include_dir . str_replace('\\', DIRECTORY_SEPARATOR, $class) . '.php';
    if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . $file)) {
        require $file;
        return true;
    }
    return false;
    
});



class Exception extends \Exception {}

class ValueException extends Exception {};
class FunctionException extends Exception {};
class ConnectionException extends Exception {};

// Data class used in the class DnsUpdate.
class DomainData {
    public string $domain = "";
    public string $ip4Addr = "0";
    public string $ip6Addr = "0";
    public string $ip6Prefix = "0";
    public int $ip6PrefixMaskLength = 0;
    public bool $determineIp6 = false;
    
    public int $ip4RecordID = -1;
    public int $ip6RecordID = -1;
    public string $ip4Old = "0";
    public string $ip6Old = "0";
}


/**
* A abstract class to update DNS records through registrars API.
* To use this class, a new class that implements the registrar's API must inherit this class.
* The class DnsUpdate_INWX for the registrar INWX is defined below this class.
**/
abstract class DnsUpdate{
    
    private const CODE_OK = 200;
    private const CODE_BADREQUEST = 400;
    private const CODE_INTERNALSERVERERROR = 500;
    
    // time to wait to give the server time to get a new ipv6 address.
    private const WAITFORNEWIP = 10; // in seconds
    // max time that communication with the api is allowed to take
    private const TIMELIMIT_API = 120; // in seconds
    // Max number of domains
    private const MAX_NUMBER_DOMAINS = 50;
    private const BEGIN_NUMBER_DOMAINS = 1; // don't change
    private const DPOS_DOMAIN = 0;
    private const DPOS_IPV4 = 1;
    private const DPOS_IPV6 = 2;
    private const DPOS_IPV6PREFIX = 3;
    private const DPOS_DETERMINEIPV6 = 4;
    private const DPOS_FIELD_COUNT = 5;   // number of fields in domain parameter.
    private const DPOS_SEPERATOR = ",";
    
    
    /**
    * Update the dns record with the parameter given in the URL.
    **/
    final public function updateDnsRecord():bool {
        try {
            $domainDataArr = array();
            $key = "";
            $user = "";
            $pass = "";
            $result = false;
            $no_following_domain = false;
            
            // GET username and password from
            if (isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW'])) {
                $user = $_SERVER['PHP_AUTH_USER'];
                $pass = $_SERVER['PHP_AUTH_PW'];
            } else {
                // try to get username and password through url parameter.
                if (isset($_GET['user']) && isset($_GET['password'])) {
                    $user = $_GET['user'];
                    $pass = $_GET['password'];
                }
            }
            if (($user == "") || ($pass == "")) {
                // ask client for username and password.
                header('WWW-Authenticate: Basic realm="INWX API Access"');
                header('HTTP/1.0 401 Unauthorized');
                header('Content-type: text/plain; charset=utf-8');
                echo 'No user or password provided.';
                return false;
            }          
            
            // GET parameter key from URL
            if (isset($_GET['key'])) {
                $key = $_GET['key'];
            }
            
            // GET and interpret domain parameters from the URL
            for ($i = self::BEGIN_NUMBER_DOMAINS; ($i <= self::MAX_NUMBER_DOMAINS) && !$no_following_domain; $i++) {
                $url_param_name = 'domain' . $i;
                if (isset($_GET[$url_param_name])) {
                    $domainDataStr = $_GET[$url_param_name];
                    $this->storeDomainParameterData($domainDataStr, $i, $domainDataArr);
                }
                else {
                    // if no following domain URL parameter is found, then break the loop.
                    $no_following_domain = true;
                } 
            }
            
            //set timelimit for execution.
            set_time_limit(self::TIMELIMIT_API);
            
            // determine the IPv6 if requested in the URL parameters.
            $this->determineIp6($domainDataArr);
            
            $result = $this->sendDataViaApi($domainDataArr, $user, $pass, $key);
        
        }
        catch (ValueException $e) {
            $this->handleException(self::CODE_BADREQUEST, $e);
            return false;
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
    *
    * @param array $domainDataArr   : Array of DomainData objects that contains all the domain data fo the API.
    * @param string $user           : The username of the API-account.
    * @param string $pass           : The password of the API-account.
    * @param string $key            : A key that may be needed for the API-Account. May be empty.
    * @return                       : true, if dns record update was successful.
    * @throw Exception              : If an error with the connection occured.
    **/
    abstract protected function sendDataViaApi(
        array $domainDataArr, 
        string $user, 
        string $pass, 
        string $key):bool;
    
    
    /**
    * Store the data of the domain data string into the given arrays.
    * Further info on the domain data:
    * String format: domain,IPv4,IPv6,IPv6prefix,determineIPv6
    * domain:          Must be provided
    * IPv4:            If empty, then the data of the previous data set will be copied. Set to 0 if this domain has no IPv4.
    * IPv6:            If empty, then the data of the previous data set will be copied. Set to 0 if this domain has no IPv6.
    * IPv6prefix:      If empty, then the data of the previous data set will be copied. Set to 0 if you don't want to provide a prefix.
    * determineIPv6:   If empty, then the data of the previous data set will be copied. Set to false if you don't want the IPv6 to be determined. Default is false.
    *
    * @param string $domainDataStr      : The string from the URL parameter that contains the domain data
    * @param int    $domainIndex        : The number of the domain data. Start with 1.
    * @param array  $domainDataArr      : DomainData object will be stored here at (domainIndex - 1). The array starts at index 0.
    * @return                           : false if domainData is empty.
    * @throw ValueException             : if a failure during the interpretation of the data occured.
    **/
    private function storeDomainParameterData(
        string $domainDataStr,
        int $domainIndex,
        array &$domainDataArr ):bool
    {
        if ($domainDataStr != "") {
            // error_log($domainDataStr);
            $domainData = new DomainData;
            $explodeArray = explode(self::DPOS_SEPERATOR, $domainDataStr, self::DPOS_FIELD_COUNT);
            $explodeArrayCount = count($explodeArray);
            for ($i = 0; $i < self::DPOS_FIELD_COUNT; $i++) {
                if ($i >= $explodeArrayCount) {
                    $explodeArray[$i] = "";
                }
                switch ($i) {
                    case self::DPOS_DOMAIN:
                        $domainData->domain = filter_var($explodeArray[$i], FILTER_VALIDATE_DOMAIN);
                        if ($domainData->domain == false) {
                            throw new ValueException('Domain' . $domainIndex . ' : Domain is not valid.');
                        }
                        if ($domainData->domain == "") {
                            throw new ValueException('Domain' . $domainIndex . ' : No domain name provided.');
                        }
                        break;
                    case self::DPOS_IPV4:
                        switch ($explodeArray[$i]) {
                            case "0":
                                break;
                            case "":
                                if ($domainIndex > 1) {
                                    $domainData->ip4Addr = $domainDataArr[$domainIndex - 2]->ip4Addr;
                                } 
                                break;
                            default:
                                $domainData->ip4Addr = filter_var($explodeArray[$i], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
                                if ($domainData->ip4Addr == false) {
                                    throw new ValueException('Domain' . $domainIndex . ' : IPv4 is not valid.');
                                }
                        }
                        break;
                    case self::DPOS_IPV6:
                        switch ($explodeArray[$i]) {
                            case "0":
                                break;
                            case "":
                                if ($domainIndex > 1) {
                                    $domainData->ip6Addr = $domainDataArr[$domainIndex - 2]->ip6Addr;
                                } 
                                break;
                            default:
                                $domainData->ip6Addr = filter_var($explodeArray[$i], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
                                if ($domainData->ip6Addr == false) {
                                    throw new ValueException('Domain' . $domainIndex . ' : IPv6 is not valid.');
                                }
                        }
                        break;
                    case self::DPOS_IPV6PREFIX:
                        switch ($explodeArray[$i]) {
                            case "0":
                                break;
                            case "":
                                if ($domainIndex > 1) {
                                    $domainData->ip6Prefix = $domainDataArr[$domainIndex - 2]->ip6Prefix;
                                    $domainData->ip6PrefixMaskLength = $domainDataArr[$domainIndex - 2]->ip6PrefixMaskLength;
                                } 
                                break;
                            default:
                                $ip6PrefixStr = $explodeArray[$i];
                                $ip6PrefixArr = explode("/", $ip6PrefixStr,2);
                                $domainData->ip6Prefix = filter_var($ip6PrefixArr[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
                                if ($domainData->ip6Prefix == false) {
                                    throw new ValueException('Domain' . $domainIndex . ' : IPv6 prefix not valid.');
                                } 
                                $domainData->ip6PrefixMaskLength = filter_var($ip6PrefixArr[1], FILTER_VALIDATE_INT);
                                if ($domainData->ip6PrefixMaskLength == false || $domainData->ip6PrefixMaskLength < 1 || $domainData->ip6PrefixMaskLength > 128) {
                                    throw new ValueException('Domain' . $domainIndex . ' : IPv6 prefix mask length is not valid.');
                                }
                        }
                        break;
                     case self::DPOS_DETERMINEIPV6:
                        switch ($explodeArray[$i]) {
                            case "":
                                if ($domainIndex > 1) {
                                    $domainData->determineIp6 = $domainDataArr[$domainIndex - 2]->determineIp6;
                                }
                                break;
                            default:
                                $domainData->determineIp6 = filter_var($explodeArray[$i], FILTER_VALIDATE_BOOLEAN);
                        }
                        break;
                    default:
                }
            }
            $domainDataArr[$domainIndex - 1] = $domainData;
            return true;
        }
        else {
            return false;
        }
    }
    
    
    /**
    * Determine IPv6 if option indicates that.
    *
    * @param array $domainDataArr   : Array of DomainData that contains all domain data from the URL.
    * @throw FunctionException      : if created ipv6 is invalid.
    **/
    private function determineIp6(array $domainDataArr)
    {
        static $ipv6 = "";
        foreach ($domainDataArr as $domainData) {
            // get ipv6 via internal function
            if ($domainData->determineIp6) {
                if ($ipv6 == "") {
                    // Give server time to get a new ipv6 address.
                    sleep(self::WAITFORNEWIP);
                    $ipv6 = $this->getInterfaceGlobalIpv6();
                }
                $domainData->ip6Addr = $ipv6;
            }
            // if a IPv6 prefix is given, then add the prefix to the ipv6 address.
            $this->changePrefixOfIpv6($domainData);
            // else: take ipv6 from url parameter
        }
    }
    
    
    /**
    * Get the globel IPv6 of the main Interface of a Linux machine via ip command.
    *
    * @return                   : a string that contains the ipv6. Format example: 2a00:1450:4005:80a:0000:0000:0000:200e
    * @throw FunctionException  : if the determined ip is invalid
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
            throw new FunctionException('The IPv6 determined by the server using the "ip" command is not valid.');
        }
        return $global_ipv6;
    }
    
    
    /**
    * Build the IPv6 address from the IPv6 address and the IPv6 prefix in the domain data.
    *
    * @param DomainData $domainData : The dataset in which the prefix of the IPv6 should be changend.
    * @throw FunctionException      : if the created IPv6 is invalid.
    */
    private function changePrefixOfIpv6(DomainData &$domainData) {
        
        if ($domainData->ip6Addr != "0" && $domainData->ip6Prefix != "0" && $domainData->ip6PrefixMaskLength != 0) {
            $ipv6 = $domainData->ip6Addr;
            $ipv6Prefix = $domainData->ip6Prefix;
            $ipv6PrefixLength = $domainData->ip6PrefixMaskLength;
            $bitsPerArrayElement = 16;
            $numberElementsIpv6Array = 8;
            $maskOne = 0xffff;
            $maskZero = 0x0000;
            $ipv6Array = unpack('n*', inet_pton($ipv6), 0); // array starts with 1
            $ipv6PrefixArray = unpack('n*', inet_pton($ipv6Prefix), 0); // array starts with 1
            
            // create the subnetmask from prefix
            // fill subnet mask with 1
            $subnetmask = array_fill(1, $numberElementsIpv6Array, $maskOne);
            // determine position of first zero in the subnetmask.
            $arrIndex = intdiv($ipv6PrefixLength, $bitsPerArrayElement) + 1;
            $bit = $ipv6PrefixLength % $bitsPerArrayElement;
            // fill subnetmask with zeros
            $bitmask = $maskOne;
            if ($bit > 0) {
                $bitmask = (($bitmask << ($bitsPerArrayElement - $bit)) & $maskOne);
                $subnetmask[$arrIndex] = $bitmask;
                $arrIndex++;
            }
            for (; $arrIndex <= $numberElementsIpv6Array; $arrIndex++) {
                $subnetmask[$arrIndex] = $maskZero;
            }
            
            // combine ipv6 and prefix based on the subnetmask.
            for ($arrIndex = 1; $arrIndex <= $numberElementsIpv6Array; $arrIndex++) {
                $ipv6Array[$arrIndex] = ($subnetmask[$arrIndex] & $ipv6PrefixArray[$arrIndex]) | ((~ $subnetmask[$arrIndex]) & $ipv6Array[$arrIndex]);
            }
            // convert IPv6 back into a readable format.
            $ipv6 = inet_ntop(pack('n*', $ipv6Array[1], $ipv6Array[2], $ipv6Array[3], $ipv6Array[4], $ipv6Array[5], $ipv6Array[6], $ipv6Array[7], $ipv6Array[8]));
            // check ipv6
            $ipv6 = filter_var($ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
            if (!$ipv6) {
                throw new FunctionException("The created IPv6 is not valid.");
            }
            else {
                $domainData->ip6Addr = $ipv6;
            }
        }
    }    
    
    
    protected function handleException(int $httpcode, Exception $e) {
        $txt = "DnsUpdateinwx.php: Exception: {$e->getFile()} : {$e->getLine()} : {$e->getMessage()}";
        error_log($txt);
        
        header('Content-type: text/plain; charset=utf-8');
        http_response_code($httpcode);
        echo $e->getMessage();
    }
}


class DnsUpdate_INWX extends DnsUpdate{
    
    /**
    * Send the data via API to update the record.
    *
    * @param array $domainDataArr   : Array of DomainData objects that contains all the domain data for the API.
    * @param string $user           : The username of the API-account.
    * @param string $pass           : The password of the API-account.
    * @param string $key            : A key that may be needed for the API-Account. May be empty.
    * @return                       : true, if dns record update was successful.
    * @throw Exception              : If an error with the connection occured.
    **/
    protected function sendDataViaApi(
        array $domainDataArr, 
        string $user, 
        string $pass, 
        string $key):bool
    {
        // connect
        $recordId = -1;
        $sharedSecret = null;
        if ($key != "") {
            $sharedSecret = $key;
        }
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
            ->login($user, $pass, $sharedSecret);
        
        // update record for each domain
        if (!empty($result) && array_key_exists('code', $result) && ($result['code'] == 1000)) {
            foreach ($domainDataArr as $domainData) {
                $this->requestRecordInfo($domrobot, $domainData);
                
                /**
                error_log($domainData->domain . " " . $domainData->ip4Addr . " " . $domainData->ip6Addr . " " . $domainData->ip6Prefix . " " . $domainData->ip6PrefixMaskLength
                . " " . ($domainData->determineIp6 ? 'true' : 'false') . " " . $domainData->ip4Old . " " . $domainData->ip4RecordID . " " . $domainData->ip6Old . " " . $domainData->ip6RecordID);
                **/
                
                // update ipv4
                if (($domainData->ip4Addr != "0") && ($domainData->ip4RecordID > -1) && ($domainData->ip4Addr != $domainData->ip4Old)) {
                    $this->updateRecord($domrobot, $domainData->ip4RecordID, $domainData->ip4Addr);
                }
                // update ipv6
                if (($domainData->ip6Addr != "0") && ($domainData->ip6RecordID > -1) && ($domainData->ip6Addr != $domainData->ip6Old)) {
                    $this->updateRecord($domrobot, $domainData->ip6RecordID, $domainData->ip6Addr);
                }
            }
            // disconnect
            $domrobot->logout();
        } else {
            throw new ConnectionException("Could not login to the account.");
            return false;
        }
        return true;
    }
    
    
    /**
    * Requests the Nameserver-Record info of a domain.
    *
    * @param &$domrobot         : ref to connected domrobot
    * @param DomainData &$domain : The DomainData for which the info should be requested. 
    */
    private function requestRecordInfo(&$domrobot, DomainData &$domainData) {
        //determine domain-name and record-name.
        $domain_exploded = explode(".", $domainData->domain);
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
                $domainData->ip4RecordID = $record['id'];
                $domainData->ip4Old = $record['content'];
            }
            if ($record['type'] == 'AAAA') {
                $domainData->ip6RecordID = $record['id'];
                $domainData->ip6Old = $record['content'];
            }
        }
    }
    
    
    /**
    * Set new ip-address for nameserver-record
    *
    * @param &$domrobot     : Ref to connected domrobot
    * @param int $recordId  : ID of nameserver-record
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
