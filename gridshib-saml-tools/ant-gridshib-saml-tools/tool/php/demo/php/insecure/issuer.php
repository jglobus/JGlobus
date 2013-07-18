<?php

/* GridShib SAML Tools demo script for TeraGrid 08
 *
 * This script does the following:
 * 1. Writes a dynamic config file with attributes into a tmp user directory.
 * 2. Invokes the SAML Assertion Issuer Tool on this config file.
 * 3. Self-issues a SAML assertion
 * 4. Writes the output (SAML or X.509) into the tmp user directory.
 * 5. Returns the output in the browser window.
 */

require 'gst-tg08-demo-config.inc';

ob_start();
header('Content-Type: text/html');
echo "<body>\n";
if ($DEBUG == TRUE) echo "<pre>\n";
if ($DEBUG == TRUE) echo "Debugging...\n";

// BEGIN config_file_template
$config_file = <<< config_file_template
IdP.entityID=%%ENTITYID%%

NameID.Format=%%FORMAT%%
NameID.Format.template=%%TEMPLATE%%

# FriendlyName="isMemberOf"
Attribute.isMemberOf.Name=%%IS_MEMBER_OF_NAME%%
Attribute.isMemberOf.Value=%%IS_MEMBER_OF_VALUE%%
config_file_template;
// END config_file_template

// variable template parameters:
$entityID = $_GET['entityID'];
$format = $_GET['nameid_format'];
$formatting_template = $_GET['nameid_format_template'];
$isMemberOfName = $_GET['attribute_ismemberof_name'];
$isMemberOfValue = $_GET['attribute_ismemberof_value'];

// substitute placeholders in the config file template:
$config_file =
  str_replace('%%ENTITYID%%', $entityID, $config_file);
$config_file =
  str_replace('%%FORMAT%%', $format, $config_file);
$config_file =
  str_replace('%%TEMPLATE%%', $formatting_template, $config_file);
$config_file =
  str_replace('%%IS_MEMBER_OF_NAME%%', $isMemberOfName, $config_file);
$config_file =
  str_replace('%%IS_MEMBER_OF_VALUE%%', $isMemberOfValue, $config_file);

if ($DEBUG == TRUE) {
  echo "BEGIN config_file_template\n";
  echo "$config_file\n";
  echo "END config_file_template\n";
}

// create a user directory:
$user = $_GET['username'];
$formatted_user = str_replace('%PRINCIPAL%', $user, $formatting_template);
$userdir = "$TMPDIR/$formatted_user";  // sanitize?
if (file_exists($userdir)) {
  if ($DEBUG == TRUE) echo "User dir already exists ($userdir)\n";
} else {
  if ($DEBUG == TRUE) echo "Creating user dir ($userdir)\n";
  if (!mkdir($userdir , 0777, TRUE)) {  // recursive
    if ($DEBUG == TRUE) echo "</pre>\n";
    echo "<p><strong>Unable to create user directory</strong></p>\n";
    echo "</body>\n";
    ob_end_flush();
    exit;
  }
}
$config_file_path = "$userdir/tg-gateway-config.properties";

// write the config file to disk:
umask(077);
if ($DEBUG == TRUE) echo "Opening config file ($config_file_path)\n";
if ($handle = fopen($config_file_path, 'w')) {
  if (!fwrite($handle, $config_file)) {
    fclose($handle);
    if ($DEBUG == TRUE) echo "</pre>\n";
    echo "<p><strong>Unable to write config file</strong></p>\n";
    echo "</body>\n";
    ob_end_flush();
    exit;
  }
  fclose($handle);
} else {
  if ($DEBUG == TRUE) echo "</pre>\n";
  echo "<p><strong>Unable to open config file</strong></p>\n";
  echo "</body>\n";
  ob_end_flush();
  exit;
}

$authnMethod = $_GET['authnMethod'];
$authnInstant = $_GET['authnInstant'];
$address = $_GET['address'];
$mailName = $_GET['attribute_mail_name'];
$mailValue = $_GET['attribute_mail_value'];

// initialize command line invocation string:
$cmd  = '$GRIDSHIB_HOME/bin/gridshib-saml-issuer ';
if ($DEBUG == TRUE) $cmd .= '--debug ';
$cmd .= "--user $user --sender-vouches --config file://$config_file_path ";

// specify the authentication context:
$cmd .= "--authn ";
$cmd .= "--authnMethod  $authnMethod ";
$cmd .= "--authnInstant $authnInstant ";
$cmd .= "--address $address ";

// specify an attribute:
$cmd .= "--properties ";
$cmd .= "Attribute.mail.Name=$mailName ";
$cmd .= "Attribute.mail.Value=$mailValue ";

// determine output file format:
if ($_GET['outfile_type'] == 'X509') {
  $cmd .= "--x509 ";
  $outfile = "$userdir/testproxy.pem";
} else {
  $outfile = "$userdir/testassertion.xml";
}
if (unlink($outfile)) {
  if ($DEBUG == TRUE) echo "Deleted old output file ($outfile)\n";
}
$cmd .= "--outfile $outfile";

if ($DEBUG == TRUE) echo "$cmd\n";

// save environment:
$old_JAVA_HOME = getenv("JAVA_HOME");
if ($DEBUG == TRUE) echo "JAVA_HOME=$old_JAVA_HOME\n";
//$old_ANT_HOME = getenv("ANT_HOME");
//if ($DEBUG == TRUE) echo "ANT_HOME=$old_ANT_HOME\n";
$old_GRIDSHIB_HOME = getenv("GRIDSHIB_HOME");
if ($DEBUG == TRUE) echo "GRIDSHIB_HOME=$old_GRIDSHIB_HOME\n";

// create new environment:
putenv("JAVA_HOME=$JAVA_HOME");
if ($DEBUG == TRUE) echo "JAVA_HOME=" . getenv("JAVA_HOME") . "\n";
//putenv("ANT_HOME=$ANT_HOME");
//if ($DEBUG == TRUE) echo "ANT_HOME=" . getenv("ANT_HOME") . "\n";
putenv("GRIDSHIB_HOME=$GRIDSHIB_HOME");
if ($DEBUG == TRUE) echo "GRIDSHIB_HOME=" . getenv("GRIDSHIB_HOME") . "\n";

// invoke SAML Assertion Issuer Tool:
exec($cmd, $results, $status);

// restore environment:
putenv("JAVA_HOME=$old_JAVA_HOME");
//putenv("ANT_HOME=$old_ANT_HOME");
putenv("GRIDSHIB_HOME=$old_GRIDSHIB_HOME");

// error check:
if ($status) {
  if ($DEBUG == TRUE) echo "</pre>\n";
  echo "<p><strong>Nonzero status code: $status</strong></p>\n";
  echo "<p>" . join("<br>", $results) . "</p>\n";
  echo "</body>\n";
  ob_end_flush();
  exit;
}

// sanity check:
if (!file_exists($outfile)) {
  if ($DEBUG == TRUE) echo "</pre>\n";
  echo "<p><strong>Unable to issue credential</strong></p>\n";
  echo "</body>\n";
  ob_end_flush();
  exit;
}

// formulate HTTP response:
if ($_GET['outfile_type'] == 'X509') {
  if ($DEBUG == TRUE) echo "</pre>\n";
  $initial_content = ob_get_contents();
  ob_clean();
  passthru("$OPENSSL x509 -text -in $outfile");
  $content = ob_get_contents();
  ob_clean();
  echo $initial_content;
  $escaped_content = htmlspecialchars($content);
  echo "<pre>$escaped_content</pre>\n";
  echo "</body>\n";
  ob_end_flush();
} else {
  if ($DEBUG == TRUE) {
    echo "</pre>\n";
    $debug_content = ob_get_contents();
    ob_clean();
    passthru("$CAT $outfile");
    $content = ob_get_contents();
    ob_clean();
    echo $debug_content;
    $escaped_content = htmlspecialchars($content);
    echo "<pre>$escaped_content</pre>\n";
    echo "</body>\n";
  } else {
    // replace previous content-type header:
    header('Content-type: text/xml; charset="utf-8"');
    $declaration = '<?xml version="1.0" encoding="utf-8"?>';
    ob_clean();
    passthru("$CAT $outfile");
    $content = ob_get_contents();
    ob_clean();
    echo "$declaration\n$content";
  }
  ob_end_flush();
}

?>