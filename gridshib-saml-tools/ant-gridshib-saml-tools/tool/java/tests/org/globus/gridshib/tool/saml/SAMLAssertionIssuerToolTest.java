/*
 * Copyright 2008-2009 University of Illinois
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.globus.gridshib.tool.saml;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.cli.BaseCLI;
import org.globus.gridshib.config.BootstrapConfigLoader;
import org.globus.gridshib.saml.SAMLToolsTestCase;
import org.globus.gridshib.security.util.GSIUtil;

import org.globus.gsi.X509Credential;

import org.globus.opensaml11.saml.SAMLAuthenticationStatement;

/**
 * Test the SAML Assertion Issuer Tool.  See
 * <a href="http://gridshib.globus.org/docs/gridshib-saml-tools/user-guide.html"></a>
 * for an explanation of the various command-line options
 * used here.
 *
 * @since 0.5.0
 */
public class SAMLAssertionIssuerToolTest extends SAMLToolsTestCase {

    private static final Class CLASS = SAMLAssertionIssuerToolTest.class;
    private static final String CLASSNAME = CLASS.getName();

    private static Log logger = LogFactory.getLog(CLASSNAME);

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CLASS);
    }

    public SAMLAssertionIssuerToolTest(String name) {
        super(name);
    }

    /**
     * @see SAMLToolsTestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();
    }

    /**
     * @see SAMLToolsTestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    public void testInstallation() throws Exception {

        String[] args;
        SAMLAssertionVerifyTool verifier = null;

        // verify installation test #1:
        args = new String[]{"--debug"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getInstallationErrorMsg(1, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify installation test #2:
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--holder-of-key"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getInstallationErrorMsg(2, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify installation test #3:
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--sender-vouches"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getInstallationErrorMsg(3, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify installation test #4:
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--sender-vouches",
                            "--outfile", "testassertion.xml"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getInstallationErrorMsg(4, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify installation test #6:
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--sender-vouches",
                            "--asn1",
                            "--outfile", "testextension.der"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getInstallationErrorMsg(6, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify installation test #8:
        String pattern = "yyyy-MM-dd'T'HH:mm:ssZ";
        SimpleDateFormat formatter = new SimpleDateFormat(pattern);
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
        String now = formatter.format(new Date());
        String prop = "dateTime.pattern=" + pattern;
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--sender-vouches",
                            "--authn",
                            "--authnInstant", now,
                            "--properties", prop,
                            "--x509",
                            "--outfile", "testproxy3.pem"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getInstallationErrorMsg(8, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify installation test #9:
        String props =
            "Attribute.mail.Name=urn:oid:0.9.2342.19200300.100.1.3 " +
            "Attribute.mail.Value=trscavo@gmail.com";
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--sender-vouches",
                            "--authn",
                            "--authnInstant", now,
                            "--properties", prop,
                            "--address", "255.255.255.255",
                            "--properties", props,
                            "--x509",
                            "--outfile", "testgatewayproxy.pem"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getInstallationErrorMsg(9, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);
    }

    private String getInstallationErrorMsg(int testNum, int exitCode) {

        return "Failed installation test #" + testNum +
               " (exit code " + exitCode + ")";
    }

    public void testUserGuideExamples() throws Exception {

        String[] args;
        SAMLAssertionVerifyTool verifier = null;

        // verify User Guide example #1:
        args = new String[]{"--debug"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getUserGuideErrorMsg(1, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify User Guide example #2:
        args = new String[]{"--debug",
                            "--holder-of-key"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getUserGuideErrorMsg(2, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify User Guide example #3:
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--holder-of-key"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getUserGuideErrorMsg(3, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify User Guide example #4:
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--sender-vouches"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getUserGuideErrorMsg(4, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify User Guide example #5:
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--sender-vouches",
                            "--saml"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getUserGuideErrorMsg(5, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify User Guide example #6:
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--sender-vouches",
                            "--saml",
                            "--outfile", "testassertion.xml"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getUserGuideErrorMsg(6, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify User Guide example #7:
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--sender-vouches",
                            "--x509",
                            "--outfile", "testproxy.pem"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getUserGuideErrorMsg(7, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify User Guide example #8:
        String pattern = "yyyy-MM-dd'T'HH:mm:ssZ";
        SimpleDateFormat formatter = new SimpleDateFormat(pattern);
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
        String now = formatter.format(new Date());
        String prop = "dateTime.pattern=" + pattern;
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--sender-vouches",
                            "--authn",
                            "--authnInstant", now,
                            "--properties", prop,
                            "--saml",
                            "--outfile", "testassertion.xml"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getUserGuideErrorMsg(8, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify User Guide example #9:
        String authnMethod =
            SAMLAuthenticationStatement.AuthenticationMethod_Password;
        String address = "255.255.255.255";
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--sender-vouches",
                            "--authn",
                            "--authnInstant", now,
                            "--authnMethod", authnMethod,
                            "--address", address,
                            "--properties", prop,
                            "--saml",
                            "--outfile", "testassertion.xml"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getUserGuideErrorMsg(9, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // test --ssoResponse here

        // verify User Guide example #10:
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--sender-vouches",
                            "--asn1",
                            "--outfile", "testextension.der"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getUserGuideErrorMsg(10, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify User Guide example #11:
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--sender-vouches",
                            "--asn1"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getUserGuideErrorMsg(11, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify User Guide example #12:
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--sender-vouches",
                            "--saml"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getUserGuideErrorMsg(12, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // copy default config to temporary file:
        File configFileDefault = BootstrapConfigLoader.getConfigFileDefault();
        String configFilename = "gridshib-saml-tools-config.properties";
        File configFile = File.createTempFile(configFilename, null);
        InputStream in = new FileInputStream(configFileDefault);
        OutputStream out = new FileOutputStream(configFile);
        byte[] buf = new byte[1024];
        int len;
        while ((len = in.read(buf)) > 0) {
            out.write(buf, 0, len);
        }
        in.close();
        out.close();

        // verify User Guide example #13:
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--sender-vouches",
                            "--outfile", "testassertion.xml",
                            "--config", configFile.getPath()};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getUserGuideErrorMsg(13, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify User Guide example #14:
        String name = "Attribute.mail.Name=urn:oid:0.9.2342.19200300.100.1.3";
        String value = "Attribute.mail.Value=trscavo@gmail.com";
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--holder-of-key",
                            "--outfile", "testassertion.xml",
                            "--properties", name, value};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getUserGuideErrorMsg(14, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify User Guide example #15:
        X509Credential cred = BootstrapConfigLoader.getCredentialDefault();
        String credFilename = "testcredential.pem";
        File credFile = File.createTempFile(credFilename, null);
        try {
            GSIUtil.writeCredentialToFile(cred, credFile);
        } catch (Exception e) {
            String msg = "Unable to write credential to file";
            logger.error(msg, e);
            fail(msg);
        }
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--holder-of-key",
                            "--outfile", "testassertion.xml",
                            "--certPath", credFile.getPath(),
                            "--keyPath", credFile.getPath()};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getUserGuideErrorMsg(15, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);
    }

    private String getUserGuideErrorMsg(int testNum, int exitCode) {

        return "Failed User Guide example #" + testNum +
               " (exit code " + exitCode + ")";
    }
}


