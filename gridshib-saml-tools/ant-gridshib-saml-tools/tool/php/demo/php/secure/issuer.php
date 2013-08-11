<?php

/* GridShib SAML Tools demo script
 *
 * This script does the following:
 * 1. Writes a dynamic config file with attributes into a tmp user directory.
 * 2. Invokes the SAML Assertion Issuer Tool on this config file.
 * 3. Nests an SSO assertion in a self-issued SAML assertion.
 * 4. Writes the output (SAML or X.509) into the tmp user directory.
 * 5. Returns the output in the browser window.
 */

require 'gst-demo-config.inc';

ob_start();
header('Content-Type: text/html');
echo "<body>\n";
if ($DEBUG == TRUE) echo "<pre>\n";
if ($DEBUG == TRUE) echo "Debugging...\n";

// BEGIN config_file_template
$config_file = <<< config_file_template
Format=%%FORMAT%%
formatting.template=%%TEMPLATE%%

# FriendlyName="isMemberOf"
Attribute.isMemberOf.Namespace=urn:mace:shibboleth:1.0:attributeNamespace:uri
Attribute.isMemberOf.Name=urn:oid:1.3.6.1.4.1.5923.1.5.1.1
Attribute.isMemberOf.Value=%%IS_MEMBER_OF%%

# FriendlyName="countryName"
Attribute.countryName.Namespace=urn:mace:shibboleth:1.0:attributeNamespace:uri
Attribute.countryName.Name=urn:oid:2.5.4.6
Attribute.countryName.Value=%%COUNTRY_NAME%%
config_file_template;
// END config_file_template

// variable template parameters:
$format = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
$formatting_template = '%PRINCIPAL%';
if (isset($_GET['isMemberOf']) && $_GET['isMemberOf'] != '') {
  $isMemberOf = $_GET['isMemberOf'];  // sanitize?
} else {
  $isMemberOf = 'UNKNOWN';
}
if (isset($_GET['countryName']) && $_GET['countryName'] != '') {
  $countryName = $_GET['countryName'];  // sanitize?
} else {
  $countryName = '??';
}

// substitute placeholders in the config file template:
$config_file = str_replace('%%FORMAT%%', $format, $config_file);
$config_file = str_replace('%%TEMPLATE%%', $formatting_template, $config_file);
$config_file = str_replace('%%IS_MEMBER_OF%%', $isMemberOf, $config_file);
$config_file = str_replace('%%COUNTRY_NAME%%', $countryName, $config_file);

if ($DEBUG == TRUE) echo "$config_file\n";

// create a user directory:
if (!($user = $_SERVER['REMOTE_USER'])) {
  if ($DEBUG == TRUE) echo "</pre>\n";
  echo "<p><strong>REMOTE_USER not found</strong></p>\n";
  echo "</body>\n";
  ob_end_flush();
  exit;
}
$userdir = "$TMPDIR/$user";  // sanitize?
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
$config_file_path = "$userdir/gridshib-saml-issuer.properties";
$sso_response_path = "$userdir/sso-response.xml";

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

// initialize command line invocation string:
$cmd  = '$GRIDSHIB_HOME/bin/gridshib-saml-issuer ';
if ($DEBUG == TRUE) $cmd .= '--debug ';
$cmd .= "--user $user --sender-vouches --config file://$config_file_path ";

// write SSO Response to disk:
if ($encoded_response = $_SERVER['HTTP_SHIB_ATTRIBUTES']) {
  if ($response = base64_decode($encoded_response)) {
    if ($DEBUG == TRUE) echo "Opening SSO response ($sso_response_path)\n";
    if ($handle = fopen($sso_response_path, 'w')) {
      if (!fwrite($handle, $response)) {
        fclose($handle);
        if ($DEBUG == TRUE) echo "Unable to write SSO response\n";
      }
      fclose($handle);
      $cmd .= "--ssoResponse file://$sso_response_path ";
    } else {
      if ($DEBUG == TRUE) echo "Unable to open SSO response\n";
    }
  } else {
    if ($DEBUG == TRUE) echo "Unable to decode SSO response\n";
  }
} else {
  if ($DEBUG == TRUE) echo "No SSO response found\n";
}

// determine output file format:
if ($_GET['outfile-type'] == 'X509') {
  $cmd .= "--x509 ";
  $outfile = "$userdir/testproxy.pem";
} else {
  $outfile = "$userdir/testassertion.xml";
}
if (is_file($outfile) && unlink($outfile)) {
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
if ($_GET['outfile-type'] == 'X509') {
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