<?php
// vi:set tw=72:

if (!defined('IN_RPTOOLS')) die("Hacking attempt");

define('SESSION_OVERRIDES_FORM', 1);	// Which source is checked first when
define('FORM_OVERRIDES_SESSION', 2);	// using the getFormVar() functions.

/**
 * These next functions retrieve information from the script's 
 * environment.  The environment consists of three areas, data coming from 
 * a submitted HTML form, data coming from a session variable, and data 
 * coming from the command line (not used in web-based applications).
 *
 * getCmdLineParam($name)	Checks $_SERVER['argv']
 * getFormVar_POST($name)	Checks $_POST[]
 * getFormVar_GET($name)	Checks $_GET[], then calls getCmdLineParam()
 * getSessionVar($name)		Checks $_SESSION[]
 * getSessionVarN($name)	Same as previous, but returns null if !numeric
 * getFormVar($name[, $prec])	SESSION, then POST, then GET
 * getFormVarN($name[, $prec])	Same as previous, but returns null if !numeric
 *
 * Most applications will want to use getFormVar(), or it's numeric 
 * version, since they check SESSION->POST->GET->CmdLine, in that order.
 */

/**
 * Session variables are similar to GET and POST, but are stored as 
 * state information on the server.  Whether this type of information 
 * overrides the GET and POST is up to the individual PHP script.  Some 
 * scripts will consider session data higher precedence while others 
 * will consider it lower precedence.  Each is correct in different 
 * circumstances.  We resolve this difference by checking a global 
 * variable that indicates what the precedence order should be.
 *
 * @param $name the string representing the variable name
 * @return the value of the variable, or null if not found
 */
function getSessionVar($name) {
    return isset($_SESSION[$name]) ? $_SESSION[$name] : null;
}

/**
 * This function also retrieves a session variable, but it ensures that 
 * the variable is numeric.  If it is, a number is returned.  If not, 
 * null is returned.
 *
 * @param $name the string representing the variable name
 * @return the value of the variable, or null if not found
 */
function getSessionVarN($name) {
    $var = getSessionVar($name);
    return is_numeric($var) ? ($var+0) : null;
}

/**
 * Checks the PHP command line looking for '$name' as a parameter.  This 
 * is different from looking inside one of the SUPERGLOBAL arrays, since 
 * each element of $_SERVER['argv'] will be in the format 'name=value' 
 * and that means there's a little extra work to be done.
 *
 * @param $name the string representing the variable name
 * @return the value of the variable, or null if not found
 */
function getCmdLineParam($name) {
    $param = $name . "=";
    $len = strlen($param);
    foreach ($_SERVER['argv'] as $arg) {
	if (strncmp($arg, $param, $len) == 0)
	    return substr($arg, $len);
    }
    return null;
}

/**
 * This function checks the URL used to invoke the PHP script looking
 * for GET parameters and command line parameters.  In a production
 * environment, we might want to disable this function so that all data
 * must come in via POST requests, since they are slightly more secure
 * -- the data doesn't appear in server log files.
 *
 * @param $name the string representing the variable name
 * @return the value of the variable, or null if not found
 */
function getFormVar_GET($name) {
    if (isset($_GET[$name]))
	return $_GET[$name];
    if (array_key_exists('argv', $_SERVER)) {
//	print "Array key exists\n";
	if (is_array($_SERVER['argv'])) {
//	    print "is_array is TRUE\n";
	    return getCmdLineParam($name);
	}
    }
    return null;
}

/**
 * Data entering the script via POST.  Does not check any other sources.
 *
 * @param $name the string representing the variable name
 * @return the value of the variable, or null if not found
 */
function getFormVar_POST($name) {
    return isset($_POST[$name]) ? $_POST[$name] : null;
}

/**
 * This function checks first for session variables, then for HTML form
 * variables.  It prefers session vars, then POST vars, then GET vars,
 * and last, command line parameters.
 *
 * @param $name the string representing the variable name
 * @param $precedence either <b>SESSION_OVERRIDES_FORM</b> (the default)
 * or <b>FORM_OVERRIDES_SESSION</b>; optional
 * @return the value of the variable, or null if not found
 */
function getFormVar($name, $precedence = SESSION_OVERRIDES_FORM) {
    if ($precedence == SESSION_OVERRIDES_FORM) {
	$var = getSessionVar($name);
	if (isset($var))
	    return $var;
	$var = getFormVar_POST($name);
	return isset($var) ? $var : getFormVar_GET($name);
    } else {
	$var = getFormVar_POST($name);
	if (isset($var))
	    return $var;
	$var = getFormVar_GET($name);
	return isset($var) ? $var : getSessionVar($name);
    }
}

/**
 * This function also retrieves a form variable, but it ensures that 
 * the variable is numeric.  If it is, a number is returned.  If not, 
 * null is returned.
 *
 * @param $name the string representing the variable name
 * @param $precedence either <b>SESSION_OVERRIDES_FORM</b> (the default)
 * or <b>FORM_OVERRIDES_SESSION</b>
 * @return the value of the variable, or null if not found
 */
function getFormVarN($name, $precedence = SESSION_OVERRIDES_FORM) {
    $var = getFormVar($name, $precedence);
    return is_numeric($var) ? ($var+0) : null;
}
?>
