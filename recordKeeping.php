<?php
// vi:set tw=72:

if (!defined('IN_RPTOOLS')) die("Hacking attempt");

/**
 * The code in this file is used to maintain a database that
 * tracks which stacktraces we've seen before and which we haven't.
 * The database connection info is supplied in the above configuration
 * file.
 *
 * The database should support transactions, but doesn't have to.  For
 * example, MySQL InnoDB tables *DO* support transaction, while MyISAM
 * do *NOT*.
 */

class DB {
    private static $mysql = "mysql:host=localhost;dbname=test";
    private static $db;

    private static function openDB() {
	if (!isset($self::db)) {
	    try {
		$self::db = new PDO($mysql, "frank", "test");
	    }
	    catch (PDOException $e) {
		session_destroy();
		failure("Can't connect to database: " . $e->getMessage());
	    }
	}
    }

    /**
     * Checks to see if an existing database record already exists for the
     * given tool name, version, and checksum.  Returns TRUE if it does,
     * FALSE otherwise.
     */
    public static function checkForRecord($tool, $vers, $chksm)
    {
	$sql = "SELECT date FROM upload_log
		WHERE toolname = ?
		  AND version  = ?
		  AND checksum = ?";
	self::openDB();
	$stmt = $self::db->prepare($sql);
	if ($stmt->execute( [$tool, $vers, $chksm] )) {
	    $row = $stmt->fetch();
	    $stmt->closeCursor();
	    return $row[0];
	}
	$stmt->closeCursor();
	return null;
    }

    /**
     * This method creates a new record in the database representing the
     * passed in parameters and returns TRUE if it succeeds and FALSE if
     * there's an error (such as duplicate key).  This gives us an
     * atomic way to check if a record exists in the database and
     * creating it if it doesn't.
     */
    public static function checkAndCreateRecord($tool, $vers, $chksm)
    {
	// Note that "date" will automatically be set to the current
	// date/time.  This is necessary because checkRecord() returns
	// the timestamp when the record already exists, and the calling
	// code y use the timestamp to determine whether to timeout the
	// current conversation.
	$sql = "INSERT INTO upload_log
		(toolname, version, checksum, date)
		VALUES (?, ?, ?, NULL)";
	self::openDB();
	$stmt = $self::db->prepare($sql);
	$result = !!$stmt->execute( [$tool, $vers, $chksm] );
	$stmt->closeCursor();
	return $result;
    }

    /**
     * Once the conversation has progressed to the point where we trust
     * the incoming data, we need to save that information somewhere.
     * For now we use the database, but creating a GitHub issue and
     * attaching the debug+stacktrace data makes the most sense.
     */
    public static function updateRecord($tool, $vers, $chksm, $debug, $exc)
    {
	$sql = "UPDATE upload_log
		SET debuginfo = ?,
		    stacktrace = ?
		WHERE toolname = ?
		  AND version  = ?
		  AND checksum = ?";
	self::openDB();
	$stmt = $self::db->prepare($sql);
	$result = !!$stmt->execute( [$debug, $exc, $tool, $vers, $chksm] );
	$stmt->closeCursor();
	return $result;
    }

    /**
     * Remove the given record.  Will become a ROLLBACK in situations
     * where there's an open transaction and a DELETE statement when
     * there's not.
     */
    public static function removeRecord($tool, $vers, $chksm)
    {
	if ($self::db->inTransaction()) {
	    $self::db->rollBack();
	    return TRUE;
	} else {
	    $sql = "DELETE FROM upload_log
		    WHERE toolname = ?
		      AND version  = ?
		      AND checksum = ?";
	    $params = [$tool, $vers, $chksm];
	    self::openDB();
	    $stmt = $self::db->prepare($sql);
	    $result = !!$stmt->execute( $params );
	    $stmt->closeCursor();
	    return $result;
	}
    }

    public static function startTransaction()
    {
	$self::db->beginTransaction();
    }
};

?>
