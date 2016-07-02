<?php
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
 *		"timestamp": 123456789,
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
?>
