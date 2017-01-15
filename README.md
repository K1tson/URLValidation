# URLValidation
A simple class which validates URL's using Regex and popular RBL's for PHP

## Requirements
1. PHP 5 and above!
2. A DNS server which responds to RBL queries (Google Fails) 

## Installation
Simply add the .php to your project like so: `require 'URLValidation.php';`

## Why use URLValidation?
At present, there is nothing built into PHP which validates a given URL correctly and then cross-checks this against external sources. Understandably you can use `filter_var($url, FILTER_VALIDATE_URL)` to see if a URL looks legit, but certain malicious strings can be passed like `'javascript://comment%0Aalert(1)"hello'` which can be dangerous. 	

URLValidation firstly checks if a URL is correct by using RegEx. After passing this check, the given domain is the cross-checked against RBL servers like Spamhaus ZEN to see if the site is listed. It will either return true or false. 

##Usage

Create the Object instance:

```php
require 'URLValidation.php';
$urlVal = new UrlValidation();
```
Add a URL as the parameter of the `domain()` method and check the the return.

```php
$urlArray = ['http://www.bokranzr.com/test.php?test=foo&test=dfdf', 'https://en-gb.facebook.com', 'https://www.google.com'];
foreach ($urlArray as $k=>$v) {
    
    echo var_dump($urlVal->domain($v)) . ' URL: ' . $v . '<br>';
    
}
```

Output:

```
bool(false) URL: http://www.bokranzr.com/test.php?test=foo&test=dfdf
bool(true) URL: https://en-gb.facebook.com
bool(true) URL: https://www.google.com
```
As you can see above, `www.bokranzr.com` is listed as malicious website so the domain was returned as false. 

##Detailed Output (Debug):

You can also output the results as an array by adding a `1` after your url parameter:

```php

$url = 'http://www.bokranzr.com/test.php?test=foo&test=dfdf';
$ReturnArray = 1; // Use 1 to return results as an Array

var_dump($urlVal->domain($url, $ReturnArray));

```

The results are outputted as an array. If the URL was able to get as far as the RBL check, it will also show you the provider which caused the fail along with the return code. 

```
array(4) {
	["url"] => string(51)
	"http://www.bokranzr.com/test.php?test=foo&test=dfdf" ["domain"] => string(16)
	"www.bokranzr.com" ["ip"] => string(12)
	"199.7.110.88" ["rblcheck"] => array(2) {
		["provider"] => string(13)
		"Protected Sky" ["return"] => string(9)
		"127.0.0.2"
	}
}

```

