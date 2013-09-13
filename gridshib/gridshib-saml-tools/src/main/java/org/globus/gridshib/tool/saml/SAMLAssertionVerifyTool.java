/*
 * Copyright 2008-2009 University of Illinois
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.globus.gridshib.tool.saml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.cli.ApplicationRuntimeException;
import org.globus.gridshib.saml.SAMLToolsCLI;
import org.globus.gridshib.tool.saml.SAMLAssertionTestingTool;

import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLSubjectAssertion;

/**
 * This is the SAML Assertion Verify Tool.  It has exactly
 * the same command-line interface as the SAML Assertion
 * Issuer Tool.  The Verify Tool invokes the SAML Assertion
 * Testing Tool to obtain a SAML assertion.  It then uses
 * the SAML Assertion Verifier to verify that the assertion
 * agrees with the command-line arguments and the configuration
 * parameters available to the Issuer Tool.
 * <p>
 * The Verify Tool emits exit code 0 if and only if the
 * verification succeeds.  It has no other output.
 *
 * @see org.globus.gridshib.tool.saml.SAMLAssertionTestingTool
 * @see org.globus.gridshib.tool.saml.SAMLAssertionVerifier
 *
 * @since 0.5.0
 */
public class SAMLAssertionVerifyTool extends SAMLToolCLI
                                  implements SAMLToolsCLI {

    private static Log logger =
        LogFactory.getLog(SAMLAssertionVerifyTool.class.getName());

    protected String scriptName = "gridshib-saml-verify";
    protected String description =
        "Description: Verifies that the output of the " +
        "SAML Assertion Issuer Tool agrees with the " +
        "given command-line arguments and config parameters";

    public SAMLAssertionVerifyTool(String[] args) {
        super(args);
    }

    public static void main(String[] args) {

        SAMLAssertionVerifyTool cli = new SAMLAssertionVerifyTool(args);

        try {
            cli.run();
        } catch (ApplicationRuntimeException e) {
            String msg = " (exit code " + cli.getExitCode() + ")";
            logger.error(e.getMessage() + msg, e);
            if (!cli.wantQuiet()) { System.err.println(e.getMessage()); }
        }

        System.exit(cli.getExitCode());
    }

    public void run() throws ApplicationRuntimeException {

        logger.info("Begin execution of SAMLAssertionVerifyTool");

        ByteArrayInputStream inBytes;
        ByteArrayOutputStream outBytes;

        // save stdout:
        PrintStream out = System.out;

        // output a SAML assertion to stdout:
        outBytes = new ByteArrayOutputStream();
        try {
            System.setOut(new PrintStream(outBytes));
            SAMLAssertionTestingTool cli =
                new SAMLAssertionTestingTool(this.getArgs());
            cli.run();
        } finally {
            System.setOut(out);
        }
        logger.debug(outBytes.toString());

        // convert the output to an InputStream:
        inBytes = new ByteArrayInputStream(outBytes.toByteArray());

        SAMLSubjectAssertion assertion = null;
        try {
            assertion = new SAMLSubjectAssertion(inBytes);
        } catch (SAMLException e) {
            this.setExitCode(APPLICATION_ERROR);
            String msg = "Unable to instantiate SAMLSubjectAssertion";
            throw new ApplicationRuntimeException(msg, e);
        }
        logger.debug(assertion.toString());

        new SAMLAssertionVerifier(this).verify(assertion);

        this.setExitCode(SUCCESS_CODE);

        logger.info("End execution of SAMLAssertionVerifyTool");
    }
}
