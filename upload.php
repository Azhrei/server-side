<?php

define('IN_RPTOOLS', 1);	// Global flag set in all entry points
include_once("getVar.php");
include_once("digest.php");
include_once("recordKeeping.php");

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
 *		"servertime": 123456789,
 *		"servertime": 123458294,
 *		"url": "/this_script.php?r=<hash_of_pubkey>"
 *		},
 *	  "digest": "2345263456345"
 *	}
 *
 * Now MT encrypts the ZIP file using the public key and PUT's it to the
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
    print("$msg\n");
    exit(1);
}

// Incoming request.  Determine whether it's part of Phase 1 or Phase 2
// and forward it to the right routine.
$random = getFormVar_GET("r");
if (!isset($random)) {
    // Initial contact.  Create session and validate POST data.
    session_destroy();
    session_start();

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
    // 1b.  If they don't match, destroy this session and ignore the
    // incoming request -- don't even send an error message back.  We
    // may as well let an attack just linger. :)
    $digest = calcDigest($body);
    if ($digest !== $json["digest"]) {
	session_destroy();
	print_r($digest);		// Remove all output later...
	failure("Digest mismatch");
    }
    // Look in the database to see if we already have this
    // version/checksum because if we do, we can refuse this new one...
    if (checkForRecord("maptool", $body["version"], $body["checksum"])) {
	print("Nothing to do.\n");
	exit(0);
    }
    print "Success.  So far. :)\n";

    // If we get here, then the Phase 1a (incoming Phase 1) message is
    // validated.  Now we generate a public/private key and send the
    // public half back to the client, as follows:
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
    $_SESSION["version"] = $body["version"];
    $_SESSION["checksum"] = $body["checksum"];

    $random = calcDigest($_SESSION["pubKey"]);
    //$random = substr($random, 0, 16);

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
    exit(0);
}
// Only get here if we are invoked with "?r=..." in the URL.
// The client should send us the encrypted data.  We decrypt it
// and process it appropriately.  For this application, that
// means verifying the checksum of the info inside the ZIP and
// then adding it to a developer-visible area.

// If we don't have anything in $_FILES, this is invalid.
if (!isset($_FILES) || count($_FILES) != 1)
    failure("Protocol error 1.");	// Must have POST-uploaded file
if (!isset($_FILES["zipfile"]))
    failure("Protocol error 2.");	// Field name must be "zipfile"
if ($_FILES["zipfile"]["error"] != UPLOAD_ERR_OK)
    failure("Protocol error 3.");	// Upload must be successful

$fobj = $_FILES["zipfile"];
$arr = explode(".", $fobj["name"]);
if ($arr[ count($arr)-1 ] != "zip")
    failure("Protocol error 4.");	// Filename extension must be "zip"

// Access the session and verify it has the correct fields in it.
session_start();
$fields = ["pubKey", "privKey", "servertime", "version", "checksum"];
foreach ($fields as $f) {
    if (!isset($_SESSION[$f])) {
	//session_destroy();
	failure("Corrupt session.");
    }
}
if ($random !== calcDigest($_SESSION["pubKey"])) {
    session_destroy();
    failure("Invalid parameter.");
}
// Since the hash has been validated, we know the pubKey comes from us,
// which means the session variables should be valid.  Which means the
// code above (Phase 1a) has already executed and we've determined that
// this entry is not already in the database.  However, it's possible
// someone else uploaded the same stacktrace while we were, so we check
// it again, just to be sure, and create the record immediately.
//
// There's no race condition here because we will attempt to insert a
// new record and check the error status to determine if it's already
// there, but we don't want to do this unless our other validations
// succeed, since db access is going to be a potential bottleneck.
//
// We specifically start a transaction so that if we don't commit it
// ourselves at the end of this script, it will automaitcally be rolled
// back and we don't have to delete the record ourselves. :)
DB::start_transaction();
if (DB::checkAndCreateRecord("maptool",
    $_SESSION["version"], $_SESSION["checksum"])) {
	session_destroy();
	failure("Duplicate stacktrace.");
}

// Uploaded data looks good and it's not a duplicate.  Let's process it!
$upload_dir = "./logs";
$upload_file = $upload_dir . basename($_FILES["zipfile"]["name"]);
if (!move_uploaded_file($_FILES["zipfile"]["tmp_name"], $upload_file)) {
    DB::removeRecord("maptool", $_SESSION["version"], $_SESSION["checksum"]);
    session_destroy();
    failure("Couldn't move uploaded file.");
}

// Decrypt the original file and write the new one right back on top of
// the original!
$encrypted = file_get_contents($upload_file);
$decrypted = decryptWithPrivate($encrypted);
file_put_contents($upload_file, $decrypted);

$debuginfo = file_get_contents("zip://${upload_file}#debuginfo.txt");
$exception = file_get_contents("zip://${upload_file}#exception.txt");

// Make sure the client isn't trying to pull a fast one; verify that our
// checksum matches what we expect it to be.
$checksum = calcDigest($exception);
if ($_SESSION["checksum"] !== $checksum) {
    DB::removeRecord("maptool", $_SESSION["version"], $_SESSION["checksum"]);
    session_destroy();
    failure("Checksums don't match.");
}

// Everything looks good, so write the stacktrace where the developers
// can find it.
DB::updateRecord("maptool", $_SESSION["version"], $checksum,
    $debuginfo, $exception);

print("Success.\n");
session_destroy();
exit(0);
?>
