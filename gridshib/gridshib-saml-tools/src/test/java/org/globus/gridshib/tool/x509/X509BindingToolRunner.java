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

package org.globus.gridshib.tool.x509;

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
import org.globus.gridshib.tool.saml.SAMLAssertionVerifier;
import org.globus.gridshib.tool.x509.X509BindingTool;

import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLSubjectAssertion;

/**
 * This runner invokes the X.509 Binding Tool on a set of
 * arguments.  Unlike the Binding Tool, however, this
 * runner <strong>always</strong> outputs a SAML assertion
 * to stdout (unless there's an error of course).
 *
 * @since 0.5.0
 */
public class X509BindingToolRunner extends X509ToolCLI
                                implements SAMLToolsCLI {

    private static Log logger =
        LogFactory.getLog(X509BindingToolRunner.class.getName());

    public X509BindingToolRunner(String[] args) {
        super(args);
    }

    /**
     * Runs the X.509 Binding Tool
     */
    public void run() throws ApplicationRuntimeException {

        logger.info("Begin execution of X509BindingToolRunner");

        // TODO: add the --debug option if not already included

        runBindingTool();
        this.setExitCode(SUCCESS_CODE);

        logger.info("End execution of X509BindingToolRunner");
    }

    private void runBindingTool() throws ApplicationRuntimeException {

        ByteArrayInputStream inBytes;
        ByteArrayOutputStream outBytes;

        // save stdin and stdout:
        InputStream in = System.in;
        PrintStream out = System.out;

        // check input path:
        if (!this.getCommandLine().hasOption("f")) {
            this.setExitCode(APPLICATION_ERROR);
            String msg = "Option --infile required";
            throw new ApplicationRuntimeException(msg);
        }

        // run the X509BindingTool:
        X509BindingTool bindingTool = new X509BindingTool(this.getArgs());
        outBytes = new ByteArrayOutputStream();
        if (this.getOutputPath() == null) {
            try {
                System.setOut(new PrintStream(outBytes));
                bindingTool.run();
            } finally {
                System.setOut(out);
            }
        } else {
            bindingTool.run();

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
