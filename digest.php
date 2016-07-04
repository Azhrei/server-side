<?php

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
?>
