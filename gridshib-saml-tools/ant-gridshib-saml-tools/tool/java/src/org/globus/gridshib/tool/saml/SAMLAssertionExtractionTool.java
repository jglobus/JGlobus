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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.cert.X509Certificate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.cli.ApplicationRuntimeException;
import org.globus.gridshib.common.cli.Testable;
import org.globus.gridshib.security.util.GSIUtil;
import org.globus.gridshib.security.x509.SAMLX509Extension;

import org.globus.gsi.X509Credential;
import org.globus.gsi.CredentialException;
import org.globus.util.Util;

import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLSubjectAssertion;

/**
 * This is the SAML Assertion Extraction Tool.  It takes
 * a path to a Globus credential on the command line and
 * outputs the SAML assertion contained in that credential.
 *
 * @since 0.5.0
 */
public class SAMLAssertionExtractionTool extends ExtractionToolCLI
                                      implements Testable {

    private static Log logger =
        LogFactory.getLog(SAMLAssertionExtractionTool.class.getName());

    // the input Globus credential:
    private static X509Credential credential = null;

    public SAMLAssertionExtractionTool(String[] args) {
        super(args);
    }

    public static void main(String[] args) {

        SAMLAssertionExtractionTool cli =
            new SAMLAssertionExtractionTool(args);

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

        logger.info("Begin execution of SAMLAssertionExtractionTool");

        BufferedInputStream in = null;
        if (this.getInputPath() == null) {
            logger.debug("Processing infile as stdin");
            in = new BufferedInputStream(System.in);
        } else {
            logger.debug("Processing infile " + this.getInputPath());
            File infile = new File(this.getInputPath());
            try {
                in = new BufferedInputStream(new FileInputStream(infile));
            } catch (FileNotFoundException e) {
                this.setExitCode(APPLICATION_ERROR);
                String msg = "Unable to locate input file: " + e.getMessage();
                throw new ApplicationRuntimeException(msg, e);
            } catch (SecurityException e) {
                this.setExitCode(APPLICATION_ERROR);
                String msg = "Unable to read from file: " + e.getMessage();
                throw new ApplicationRuntimeException(msg, e);
            }
        }
        try {
            credential = GSIUtil.getCredential(in);
        } catch (CredentialException e) {
            this.setExitCode(COMMAND_LINE_ERROR);
            String msg = "Unable to obtain Globus credential: " +
                         e.getMessage();
            throw new ApplicationRuntimeException(msg, e);
        }

        X509Certificate cert = credential.getCertificateChain()[0];

        SAMLSubjectAssertion assertion = null;
        try {
            assertion = SAMLX509Extension.getSAMLAssertion(cert);
        } catch (IOException e) {
            this.setExitCode(APPLICATION_ERROR);
            String msg = "Unable to decode the certificate extension";
            throw new ApplicationRuntimeException(msg, e);
        } catch (SAMLException e) {
            this.setExitCode(APPLICATION_ERROR);
            String msg = "unable to parse the SAML assertion";
            throw new ApplicationRuntimeException(msg, e);
        }

        if (assertion == null) {
            String msg = "Credential does not contain a SAML assertion";
            logger.info(msg);
            logger.info("End execution of SAMLAssertionExtractionTool");
            return;
        }

        String assertionStr = assertion.toString();
        logger.debug(assertionStr);

        if (this.getOutputPath() == null) {
            System.out.println(assertionStr);
        } else {
            PrintWriter out = null;
            try {
                File outputFile = Util.createFile(this.getOutputPath());
                out = new PrintWriter(new FileOutputStream(outputFile));
                out.println(assertionStr);
                out.flush();
                out.close();
            } catch (Exception e) {
                this.setExitCode(APPLICATION_ERROR);
                String msg = "Unable to write output: " + e.getMessage();
                throw new ApplicationRuntimeException(msg, e);
            }
        }

        this.setExitCode(SUCCESS_CODE);

        logger.info("End execution of SAMLAssertionExtractionTool");
    }
}
