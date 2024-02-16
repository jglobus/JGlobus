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

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.cli.ApplicationRuntimeException;
import org.globus.gridshib.saml.SAMLToolsCLI;
import org.globus.gridshib.security.x509.SAMLX509Extension;
import org.globus.gridshib.tool.saml.SAMLAssertionExtractionTool;
import org.globus.gridshib.tool.saml.SAMLAssertionIssuerTool;
import org.globus.gridshib.tool.x509.X509BindingTool;

import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLSubjectAssertion;

/**
 * The SAML Assertion Testing Tool invokes the SAML Assertion
 * Issuer Tool on a set of arguments.  Unlike the Issuer Tool,
 * however, invoking the Testing Tool <strong>always</strong>
 * outputs a SAML assertion to stdout (unless there's an error
 * of course).
 * <p>
 * Even though the Testing Tool outputs to stdout, it still
 * processes any output arguments given on the command line.
 * If the arguments given to the {@link run(String[])} method
 * include the <code>--x509</code> option, the Testing Tool
 * invokes the SAML Assertion Extraction Tool on the output
 * of the Issuer Tool.  If the arguments include the
 * <code>--asn1</code> option, the Testing Tool invokes the
 * X.509 Binding Tool on the output of the Issuer Tool, and
 * then invokes the Extraction Tool.  If the arguments
 * include neither the <code>--x509</code> nor the
 * <code>--asn1</code> options, the Testing Tool invokes the
 * Issuer Tool only.  In all cases, the result is a SAML
 * assertion, which is output to stdout.
 *
 * @since 0.5.0
 */
public class SAMLAssertionTestingTool extends SAMLToolCLI
                                   implements SAMLToolsCLI {

    private static Log logger =
        LogFactory.getLog(SAMLAssertionTestingTool.class.getName());

    protected String scriptName = "gridshib-saml-test";
    protected String description =
        "Description: Invokes the SAML Assertion Issuer Tool " +
        "on its input but always outputs a SAML assertion to " +
        "stdout regardless of the chosen output option";

    public SAMLAssertionTestingTool(String[] args) {
        super(args);
    }

    public static void main(String[] args) {

        SAMLAssertionTestingTool cli =
            new SAMLAssertionTestingTool(args);

        try {
            cli.run();
        } catch (ApplicationRuntimeException e) {
            String msg = " (exit code " + cli.getExitCode() + ")";
            logger.error(e.getMessage() + msg, e);
            if (!cli.wantQuiet()) { System.err.println(e.getMessage()); }
        }

        System.exit(cli.getExitCode());
    }

    /**
     * <ul>
     *   <li>Adds the <code>--debug</code> option if not
     *   already included.</li>
     * </ul>
     */
    public void run() throws ApplicationRuntimeException {

        logger.info("Begin execution of SAMLAssertionTestingTool");

        runIssuerTool();
        this.setExitCode(SUCCESS_CODE);

        logger.info("End execution of SAMLAssertionTestingTool");
    }

    /**
     * Runs the SAML Assertion Issuer Tool
     */
    private void runIssuerTool() throws ApplicationRuntimeException {

        ByteArrayInputStream inBytes;
        ByteArrayOutputStream outBytes;

        // save stdin and stdout:
        InputStream in = System.in;
        PrintStream out = System.out;

        // run the SAMLAssertionIssuerTool:
        SAMLAssertionIssuerTool issuer =
            new SAMLAssertionIssuerTool(this.getArgs());
        outBytes = new ByteArrayOutputStream();
        if (this.getOutputPath() == null) {
            try {
                System.setOut(new PrintStream(outBytes));
                issuer.run();
            } finally {
                System.setOut(out);
            }
        } else {
            issuer.run();

            // read the output file:
            File infile = new File(this.getOutputPath());
            if (infile != null) {
                logger.debug("Processing infile " + infile);
                BufferedInputStream is = null;
                try {
                    is = new BufferedInputStream(new FileInputStream(infile));
                } catch (FileNotFoundException e) {
                    this.setExitCode(APPLICATION_ERROR);
                    String msg = "Unable to locate input file";
                    throw new ApplicationRuntimeException(msg, e);
                } catch (SecurityException e) {
                    this.setExitCode(APPLICATION_ERROR);
                    String msg = "Unable to read from file";
                    throw new ApplicationRuntimeException(msg, e);
                }
                try {
                    int c;
                    while ((c = is.read()) != -1) {
                        outBytes.write(c);
                    }
                } catch (IOException e) {
                    this.setExitCode(APPLICATION_ERROR);
                    String msg = "Unable to read bytes from input stream";
                    throw new ApplicationRuntimeException(msg, e);
                } finally {
                    if (is != null) {
                        try { is.close(); } catch (IOException e) { }
                    }
                }
            }
        }
        logger.debug(outBytes.toString());

        // run the X509BindingTool if necessary:
        if (this.indicatesSAML() || this.indicatesASN1()) {

            String inOpt = null;
            if (this.indicatesSAML()) {
                logger.debug("Input SAML into Binding Tool");
                inOpt = "--saml";
            } else {
                logger.debug("Input DER-encoded ASN.1 into Binding Tool");
                inOpt = "--asn1";
            }

            // output an X.509 proxy credential to stdout:
            inBytes = new ByteArrayInputStream(outBytes.toByteArray());
            outBytes = new ByteArrayOutputStream();
            try {
                System.setIn(inBytes);
                System.setOut(new PrintStream(outBytes));
                String oid = SAMLX509Extension.OID;
                X509BindingTool cli = new X509BindingTool(
                        new String[]{"--debug", "--oid", oid, inOpt});
                cli.run();
            } finally {
                System.setIn(in);
                System.setOut(out);
            }
            logger.debug(outBytes.toString());
        } else {
            logger.debug("No input to Binding Tool");
        }

        // extract and output a SAML assertion to stdout:
        inBytes = new ByteArrayInputStream(outBytes.toByteArray());
        outBytes = new ByteArrayOutputStream();
        try {
            System.setIn(inBytes);
            System.setOut(new PrintStream(outBytes));
            SAMLAssertionExtractionTool cli =
                new SAMLAssertionExtractionTool(new String[]{"--debug"});
            cli.run();
        } finally {
            System.setIn(in);
            System.setOut(out);
        }
        logger.debug(outBytes.toString());

        System.out.println(outBytes.toString());

        // sanity check:
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
    }
}
