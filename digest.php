<?php

if (!defined('IN_RPTOOLS')) die("Hacking attempt");

define('DIGEST_METHOD', "sha512");

/**
 * Various digest-related functions are in this module.
 *
 * calcDigest($obj, $salt = 0)
 * 	Given an object, converts it to JSON using json_encode() and
 * 	then calculates and returns the digest of the resulting string.
 * 	If a salt value is provided, it is used as the basis for the
 * 	digest calculation.
 */

function calcDigest($obj, $salt = "RPTools.net")
{
    if (is_string($obj))
	$json_string = $obj;
    else
	$json_string = json_encode($obj);

    $methods = hash_algos();
    if (in_array(DIGEST_METHOD, $methods)) {
	return hash_hmac(DIGEST_METHOD, $json_string, $salt);
    } else {
	failure("Missing digest method?");
    }
}

function generateKeyPair() {
    $config = array(
	"digest_alg" => OPENSSL_ALGO_SHA512,
	"private_key_bits" => 2048,
	// Would prefer DSA here but docs say "unimplemented"
	// RSA has been mathematically shown to be vulnerable, although
	// no known exploits have been found.  Yet. [circa 2016]
	"private_key_type" => OPENSSL_KEYTYPE_RSA,
    );
    global $php_errormsg;
    $res = openssl_pkey_new();
    print "php_errormsg: '$php_errormsg'\n";
    while ($msg = openssl_error_string())
	echo "\t$msg\n";
    if (!$res)
	failure("Can't create keypair?!");
    openssl_pkey_export($res, $privKey);
    $pubKey = openssl_pkey_get_details($res);
    $pubKey = $pubKey["key"];
    return array($privKey, $pubKey);
}

function encryptWithPublic($msg, $pubKey = FALSE)
{
    openssl_public_encrypt($msg,
	$encrypted,
	$pubKey ? $pubKey : $_SESSION["pubKey"]);
    return $encrypted;
}

function decryptWithPrivate($encrypted, $privKey = FALSE)
{
    openssl_private_decrypt($encrypted,
	$msg,
	$privKey ? $privKey : $_SESSION["privKey"]);
    return $msg;
}

?>
