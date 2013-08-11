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

package org.globus.gridshib.tool.x509;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.cli.ApplicationRuntimeException;
import org.globus.gridshib.common.cli.BaseCLI;
import org.globus.gridshib.config.BootstrapConfigLoader;
import org.globus.gridshib.saml.SAMLToolsTestCase;
import org.globus.gridshib.security.x509.SAMLX509Extension;
import org.globus.gridshib.security.util.GSIUtil;
import org.globus.gridshib.tool.saml.SAMLAssertionExtractionTool;
import org.globus.gridshib.tool.saml.SAMLAssertionIssuerTool;
import org.globus.gridshib.tool.saml.SAMLAssertionVerifyTool;

import org.globus.gsi.X509Credential;

import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLSubjectAssertion;

/**
 * Test the X.509 Binding Tool.  See
 * <a href="http://gridshib.globus.org/docs/gridshib-saml-tools/user-guide.html"></a>
 * for an explanation of the various command-line options
 * used here.
 *
 * @since 0.5.0
 */
public class X509BindingToolTest extends SAMLToolsTestCase {

    private static final Class CLASS = X509BindingToolTest.class;
    private static final String CLASSNAME = CLASS.getName();

    private static Log logger = LogFactory.getLog(CLASSNAME);

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CLASS);
    }

    public X509BindingToolTest(String name) {
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

    public void testRoundTripSAML() throws Exception {

        String[] args = null;

        ByteArrayInputStream inBytes;
        ByteArrayOutputStream outBytes;

        // save stdin and stdout:
        InputStream in = System.in;
        PrintStream out = System.out;

        // output a SAML assertion to stdout:
        outBytes = new ByteArrayOutputStream();
        args = new String[]{"--debug"};
        try {
            System.setOut(new PrintStream(outBytes));
            SAMLAssertionIssuerTool cli = new SAMLAssertionIssuerTool(args);
            cli.run();
        } catch (ApplicationRuntimeException e) {
            String msg = "SAMLAssertionIssuerTool failed";
            logger.error(msg, e);
            fail(msg);
        } finally {
            System.setOut(out);
        }
        logger.debug(outBytes.toString());

        // convert the output to an InputStream:
        inBytes = new ByteArrayInputStream(outBytes.toByteArray());

        SAMLSubjectAssertion assertion1 = null;
        try {
            assertion1 = new SAMLSubjectAssertion(inBytes);
        } catch (SAMLException e) {
            String msg = "Unable to instantiate SAMLSubjectAssertion";
            logger.error(msg, e);
            fail(msg);
        }
        logger.debug(assertion1.toString());

        // convert the output to an InputStream:
        inBytes = new ByteArrayInputStream(outBytes.toByteArray());

        // output an X.509 proxy credential to stdout:
        outBytes = new ByteArrayOutputStream();
        String oid = SAMLX509Extension.OID;
        args = new String[]{"--debug", "--oid", oid, "--saml"};
        try {
            System.setIn(inBytes);
            System.setOut(new PrintStream(outBytes));
            X509BindingTool cli = new X509BindingTool(args);
            cli.run();
        } catch (ApplicationRuntimeException e) {
            String msg = "X509BindingTool failed";
            logger.error(msg, e);
            fail(msg);
        } finally {
            System.setIn(in);
            System.setOut(out);
        }
        logger.debug(outBytes.toString());

        // convert the output to an InputStream:
        inBytes = new ByteArrayInputStream(outBytes.toByteArray());

        // output a SAML assertion to stdout:
        outBytes = new ByteArrayOutputStream();
        args = new String[]{"--debug"};
        try {
            System.setIn(inBytes);
            System.setOut(new PrintStream(outBytes));
            SAMLAssertionExtractionTool cli =
                new SAMLAssertionExtractionTool(args);
            cli.run();
        } catch (ApplicationRuntimeException e) {
            String msg = "SAMLAssertionExtractionTool failed";
            logger.error(msg, e);
            fail(msg);
        } finally {
            System.setIn(in);
            System.setOut(out);
        }
        logger.debug(outBytes.toString());

        // convert the output to an InputStream:
        inBytes = new ByteArrayInputStream(outBytes.toByteArray());

        SAMLSubjectAssertion assertion2 = null;
        try {
            assertion2 = new SAMLSubjectAssertion(inBytes);
        } catch (SAMLException e) {
            String msg = "Unable to instantiate SAMLSubjectAssertion";
            logger.error(msg, e);
            fail(msg);
        }
        logger.debug(assertion2.toString());

        assertTrue("testRoundTripSAML failed",
                   assertion1.getId().equals(assertion2.getId()));
    }

    public void testUserGuideExamples() throws Exception {

        String OID = SAMLX509Extension.OID;

        String[] args;
        SAMLAssertionVerifyTool verifier = null;
        X509BindingToolRunner runner = null;

        // create DER-encoded ASN.1 structure for testing:
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--sender-vouches",
                            "--asn1",
                            "--outfile", "testextension.der"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getSetupErrorMsg(1, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify User Guide example #1:
        args = new String[]{"--debug",
                            "--oid", OID,
                            "--infile", "testextension.der"};
        runner = new X509BindingToolRunner(args);
        assertTrue(getUserGuideErrorMsg(1, runner.getExitCode(true)),
                   runner.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify User Guide example #2:
        args = new String[]{"--debug",
                            "--oid", OID,
                            "--asn1",
                            "--infile", "testextension.der",
                            "--x509"};
        runner = new X509BindingToolRunner(args);
        assertTrue(getUserGuideErrorMsg(2, runner.getExitCode(true)),
                   runner.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // create SAML assertion for testing:
        args = new String[]{"--debug",
                            "--user", "trscavo",
                            "--sender-vouches",
                            "--saml",
                            "--outfile", "testassertion.xml"};
        verifier = new SAMLAssertionVerifyTool(args);
        assertTrue(getSetupErrorMsg(2, verifier.getExitCode(true)),
                   verifier.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify User Guide example #3:
        args = new String[]{"--debug",
                            "--oid", OID,
                            "--saml",
                            "--infile", "testassertion.xml"};
        runner = new X509BindingToolRunner(args);
        assertTrue(getUserGuideErrorMsg(3, runner.getExitCode(true)),
                   runner.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify User Guide example #4:
        args = new String[]{"--debug",
                            "--oid", OID,
                            "--saml",
                            "--infile", "testassertion.xml",
                            "--outfile", "testproxy.pem"};
        runner = new X509BindingToolRunner(args);
        assertTrue(getUserGuideErrorMsg(4, runner.getExitCode(true)),
                   runner.getExitCode(true) == BaseCLI.SUCCESS_CODE);

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

        // verify User Guide example #5:
        args = new String[]{"--debug",
                            "--oid", OID,
                            "--asn1",
                            "--infile", "testextension.der",
                            "--outfile", "testproxy2.pem",
                            "--config", configFile.getPath()};
        runner = new X509BindingToolRunner(args);
        assertTrue(getUserGuideErrorMsg(5, runner.getExitCode(true)),
                   runner.getExitCode(true) == BaseCLI.SUCCESS_CODE);

        // verify User Guide example #6:
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
                            "--oid", OID,
                            "--saml",
                            "--infile", "testassertion.xml",
                            "--outfile", "testproxy.pem",
                            "--certPath", credFile.getPath(),
                            "--keyPath", credFile.getPath()};
        runner = new X509BindingToolRunner(args);
        assertTrue(getUserGuideErrorMsg(6, runner.getExitCode(true)),
                   runner.getExitCode(true) == BaseCLI.SUCCESS_CODE);
    }

    private String getSetupErrorMsg(int testNum, int exitCode) {

        return "Failed setup test #" + testNum +
               " (exit code " + exitCode + ")";
    }

    private String getUserGuideErrorMsg(int testNum, int exitCode) {

        return "Failed User Guide example #" + testNum +
               " (exit code " + exitCode + ")";
    }
}
