<?php

define('IN_RPTOOLS', 1);	// Global flag set in all entry points
include_once("getVar.php");
include_once("digest.php");

/**
 * This module represents an AJAX interface to be used by MapTool when
 * it wants to upload a stacktrace such as that produced by a Java
 * exception.
 *
 * The overall flow is that MT contacts this script and provides its
 * version number, a timestamp, and a checksum of the unencrypted
 * stacktrace text.  If we already have that checksum in our database,
 * it means the crash is a duplicate and we can tell MT not to bother
 * sending it.  A digest of the above using some string built into MT as
 * the salt ensures the request is valid (a spammer wouldn't know how to
 * build the digest without MT source code so we can eliminate the fake
 * request early).
 *
 *	{ "body": {
 *		"version": "1.4.0.1",
 *		"clienttime": 123456789,
 *		"checksum": 987654321
 *		},
 *	  "digest": "7a6f548e9237d990c876a"
 *	}
 *
 * The server then generates a public/private key and sends back to MT
 * the public key, a hash of MT's version+timestamp (using a shared
 * secret), the server's timestamp, and the URL of where to send the ZIP
 * file with the stacktrace in it.  The URL will be this script plus a
 * QUERY_STRING parameter that contains a random number.  MT can check
 * the hash of the version+timestamp; if it's not as expected, the
 * server isn't who we think it is and MT breaks the connection.  (The
 * server's timestamp need not match MT's.  They're only used on each
 * end for timeouts enforced on that end.)
 *
 *	{ "body": {
 *		"publickey": "12345abcdef6789",
 *		"hash": "827648d9a866f8e9c",
 *		"timestamp": 123458294,
 *		"url": "/this_script.php?_=12345"
 *		},
 *	  "digest": "2345263456345"
 *	}
 *
 * Now MT encrypts the ZIP file using the public key and POSTs it to the
 * server.  The server can verify the checksum of the stacktrace inside
 * the ZIP and compare it to the checksum in the first exchange.  If
 * they don't match, we can ignore the uploaded file and send an error
 * back to MT.
 *
 * Throughout all of the above steps, there should be a relatively short
 * time span involved, perhaps 15 minutes.  Both ends will embed their
 * starting timestamp into the conversation so that either end can
 * timeout without acknowledgment from the other end.  MT should
 * probably only try once or twice to upload the file and should forget
 * about the upload if unsuccessful in the first couple of attempts.
 *
 * Once we have the uploaded ZIP file, we arrange to get it to the
 * developers, perhaps by attaching it to a github issue?  The ZIP file
 * should include two files:  the sanitized output from the Help>Debug
 * menu option within MT, and the UTF-8 text contents of the stacktrace
 * itself.  Over time we may find it necessary to add more info.
 */

/**
 * First, we need a class to encapsulate storing the actual data.
 */
class StackTrace {
    private $zip_name;		// Uploaded zip filename
    private $stacktrace;	// Stacktrace text read from zip file
    private $checksum;		// Checksum of $stacktrace
    private $mt_info;		// From the Help>Debug option in MapTool
};

function failure($msg) {
    print "$msg\n";
    exit(1);
}

// Incoming request.  Determine whether it's part of Phase 1 or Phase 2
// and forward it to the right routine.
session_start();
if (!isset($_SESSION["MT_VERSION"])) {
    // Phase 1 -- initial connection.

    $data = getFormVar("json");	// Checks SESSION->POST->GET->CmdLine
    if (!$data)
	failure("Empty POST");

    // Requires that POST data use double quotes around all keys, not
    // single quotes.
    $json = json_decode($data, true);
    if (!isset($json) || !isset($json["body"]) || !isset($json["digest"]))
	failure("Badly formed JSON1: $data");

    $body = $json["body"];
    if (!isset($body["version"]) || !isset($body["clienttime"]) || !isset($body["checksum"]))
	failure("Badly formed JSON2: $data");
    print_r($json);

    // If all of the above is correct, calculate the hash digest and
    // compare it against what just came in.  If they match, begin Phase
    // 2.  If they don't match, destroy this session and ignore the
    // incoming request -- don't even send an error message back.  We
    // may as well let an attack just linger. :)
    $digest = calcDigest($body);
    if ($digest !== $json["digest"]) {
	print_r($digest);
	failure("Digest mismatch");
    }
    print "Success.  So far. :)\n";

    // If we get here, then the Phase 1a (incoming Phase 1) message is
    // validated.  Now we generate a public/private key and send it back
    // to the client, as follows:
    //	{ "body": {
    //		"publickey": "...",
    //		"clienttime": "...",
    //		"servertime": "...",
    //		"url": "..."
    //	  },
    //	  "digest": "..."
    //	}

    // Begin Phase 1b:  sending our response.
    $keys = generateKeyPair();
    $_SESSION["privKey"] = $keys[0];
    $_SESSION["pubKey"] = $keys[1];
    $_SESSION["servertime"] = time();

    $random = calcDigest($_SESSION["pubKey"]);
    $random = substr($random, 0, 16);

    $body = array(
	"publickey"  => $_SESSION["pubKey"],
	"clienttime" => $body["clienttime"],
	"servertime" => $_SESSION["servertime"],
	"url"        => $_SERVER["SCRIPT_FILENAME"] + "?r=" + $random
    );
    $json = array(
	"body"   => $body,
	"digest" => calcDigest($body),
    );
    print($json);
    print "\n";


}

?>
