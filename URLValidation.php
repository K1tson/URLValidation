<?php

/* Title: UrlValidation
 * Author: Jamie Kitson
 * Date: 13/01/2017
 * Email: jamie@kitson-online.co.uk
 * Website: https://www.kitson-online.co.uk
 * About: A simple class for validating URLS to ensure there secure.
 *
 * Params -
 *   URL: A URL e.g. https://www.foo.com/dfadf?fdsf or http://foo.com/adasdas
 *   Array: 1 for parsed url data and network details (IP, RBL, etc...) 
 *   Debug: Debug Text for testing purposes.
*/


class UrlValidation {

    protected $url = NULL; //URL Passing RegEx
    protected $cDomain = NULL; //Cleansed URL e.g. www.foo.com or foo.com
    
    //Modes
    protected $debug = 0; //Debug Mode
    protected $array = 0; //Data returned as Array
    
    //Added Return Values
    protected $dataArr;
    
    
    public function domain($url, $array=0,$debug=0) { 
        
        $this->dataArr = []; //Reset Array
        
        $this->debug = ($debug === 1) ? 1 : 0; //Return Debug Text if True (1)
        $this->array = ($array === 1) ? 1 : 0; //Return Array Values if True (1)
        
        $result = $this->regChk($url);

        if($result >= 1 && $this->debug === 1) { //Debug Mode Enabled
            
            return $this->error($result);
            
        } elseif($result >= 1 && $array == 1) { //Error - Return Array
            
            return $this->dataArr;
            
        } elseif($result >= 1) {
            
            return false;
            
        }

        
        if($array === 1) {
            
            return $this->dataArr;
            
        }
        
        return true;
    }
    
    protected function regChk($domain) {
        
        $result = preg_match('/^(http:\/\/|https:\/\/)(|\..{3,}).{3,}\.(.{3,10}|.{3,10}\.{3,10})(|\/.+)/', $domain);
        
        if ($result === 1) {
            
           $this->url = $domain; //Set URL Property
           $this->dataArr += ['url' => $domain]; //Additonal Values Array
           return $this->findDomain();

        }
        
        return 1; //Error
        
    }
    
    protected function findDomain() {
        
        $strip_http = explode("//", $this->url);
        $strip_param = explode("/", $strip_http[1]);
        $result = filter_var(gethostbyname($strip_param[0]), FILTER_VALIDATE_IP);
        
        if ($result === FALSE) {
            
            return 2;
            
        }
        
        $this->dataArr += ['domain' => $strip_param[0], 'ip' => gethostbyname($strip_param[0])];
        return $this->ipVal();

    }
    
    protected function ipVal() {
        
        //RBL Array -> Use format below to add further RBL servers **Note** Dont forget preceeding dot
        
        define('rblArr', [
            ['provider' => 'Barracuda', 'query' => '.b.barracudacentral.org'],
            ['provider' => 'Protected Sky', 'query' => '.bad.psky.me'],
            ['provider' => 'Spamhaus ZEN', 'query' => '.zen.spamhaus.org'],
            ['provider' => 'Spam Cannibal', 'query' => '.bl.spamcannibal.org'],
        ]);
        
        //RBL - Reverse IP format for RBL Query e.g. 192.168.0.1 -> 1.0.168.192
        $ipArr = explode('.', $this->dataArr['ip']);
        $ipRev = array_reverse($ipArr);
        $ip = implode('.',$ipRev);

        foreach(rblArr as $v) {
            
            $query = $ip . $v['query'];
            $result = gethostbyname($query);
            
            if ($result !== $query) { //Add to DataArr if Failed with Return Code
                $this->dataArr += ['rblcheck' => ['provider' => $v['provider'], 'return' => $result]];
                return 3;
            }  
        }

        return 0;
 
    }

    protected function error($code) {
                
        $errorArr = [
            'Unknown Error Code: ',
            'Failed Regex Match!',
            'Failed DNS Lookup!',
            'Failed RBL Check',
            ];
        
        if(isset($errorArr[$code])) {
            
            $this->dataArr += ['Error' => $errorArr[$code]];
            return $this->dataArr; 
        }
        
        $this->dataArr += ['Error' => $errorArr[0]] . $code;
        return $this->dataArr;
    }
}

