/*
 * Copyright 2007-2009 University of Illinois
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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.cli.ApplicationRuntimeException;
import org.globus.gridshib.common.cli.Testable;
import org.globus.gridshib.common.mapper.GridShibEntityMapper;
import org.globus.gridshib.common.mapper.TrivialEntityMap;
import org.globus.gridshib.security.SAMLSecurityContext;
import org.globus.gridshib.security.util.CertUtil;
import org.globus.gridshib.security.util.GSIUtil;
import org.globus.gridshib.security.util.SAMLUtil;
import org.globus.gridshib.security.x509.SAMLX509Extension;

import org.globus.gsi.X509Credential;
import org.globus.gsi.CredentialException;
import org.globus.util.Util;

import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLSubjectAssertion;

/**
 * This is the SAML Security Info Tool.  It takes a path
 * to a Globus credential on the command line and outputs
 * the SAML security information contained in that credential.
 *
 * @since 0.3.0
 */
public class SAMLSecurityInfoTool extends InfoToolCLI
                               implements Testable {

    private static Log logger =
        LogFactory.getLog(SAMLSecurityInfoTool.class.getName());

    // the input Globus credential:
    private static X509Credential credential = null;

    private SAMLSecurityInfoTool(String[] args) {
        super(args);
    }

    public static void main(String[] args) {

        SAMLSecurityInfoTool cli = new SAMLSecurityInfoTool(args);

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
     * @since 0.5.0
     */
    public void run() throws ApplicationRuntimeException {

        logger.info("Begin execution of SAMLSecurityInfoTool");

        if (this.wantsExtract()) {
            ArrayList arglist = new ArrayList(Arrays.asList(this.getArgs()));
            arglist.remove("-" + EXTRACT.getOpt());
            arglist.remove("--" + EXTRACT.getLongOpt());
            String[] newargs = (String[])(arglist.toArray(new String[0]));
            SAMLAssertionExtractionTool cli =
                new SAMLAssertionExtractionTool(newargs);
            cli.run();
            this.setExitCode(cli.getExitCode());
            logger.info("End execution of SAMLSecurityInfoTool");
            return;
        }

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

        this.initializeEntityMapping();

        String info = this.consumeX509BoundSAML(this.isVerbose());
        logger.debug(info);
        if (this.getOutputPath() == null) {
            System.out.println(info);
        } else {
            PrintWriter out = null;
            try {
                File outputFile = Util.createFile(this.getOutputPath());
                out = new PrintWriter(new FileOutputStream(outputFile));
                out.println(info);
                out.flush();
                out.close();
            } catch (Exception e) {
                this.setExitCode(APPLICATION_ERROR);
                String msg = "Unable to write output: " + e.getMessage();
                throw new ApplicationRuntimeException(msg, e);
            }
        }

        this.setExitCode(SUCCESS_CODE);

        logger.info("End execution of SAMLSecurityInfoTool");
    }

    /**
     * Initializes an entity mapping, that is, a mapping of SAML
     * issuers to X.509 issuers.  For each bound SAML assertion,
     * add a map from the issuer of the SAML assertion to the
     * issuer of the containing certificate (which may be an
     * EEC or a proxy certificate).
     *
     * Note: In practice, a consumer depends on a static entity
     * map configured into the runtime environment.  In GridShib
     * for GT, for instance, entity mappings are stored in the
     * file system and loaded when the container initializes.
     */
    private void initializeEntityMapping() throws ApplicationRuntimeException {

        // a trivial mapping from SAML entities to X.509 entities:
        TrivialEntityMap entityMap = new TrivialEntityMap();

        /* Predetermine the proxy issuer, which is the EEC subject,
         * by definition.
         */
        X509Certificate[] certs = credential.getCertificateChain();
        X509Certificate eec = null;
        try {
            logger.debug("Getting end entity cert...");
            eec = CertUtil.getEEC(certs);
        } catch (CertificateException e) {
            this.setExitCode(APPLICATION_ERROR);
            String msg = "Unable to determine if certificate is an " +
                         "impersonation proxy";
            throw new ApplicationRuntimeException(msg, e);
        }
        if (eec == null) {
            this.setExitCode(APPLICATION_ERROR);
            String msg = "Unable to find end entity certificate";
            throw new ApplicationRuntimeException(msg);
        }
        logger.debug("End entity cert: " + eec.toString());
        X500Principal eecSubject = eec.getSubjectX500Principal();
        String eecSubjectDN = eecSubject.getName(X500Principal.RFC2253);
        logger.debug("EEC subject: " + eecSubjectDN);

        /* Traverse the certificate chain and add an entity
         * map for each bound SAML assertion.
         */
        for (int i = 0; i < certs.length; i++) {
            logger.debug("Processing certificate " + i + ": " +
                         certs[i].toString());

            String entityID = null;
            SAMLSubjectAssertion assertion = null;
            try {
                assertion = SAMLX509Extension.getSAMLAssertion(certs[i]);
            } catch (IOException e) {
                this.setExitCode(APPLICATION_ERROR);
                String msg = "Unable to decode certificate extension";
                throw new ApplicationRuntimeException(msg, e);
            } catch (SAMLException e) {
                this.setExitCode(APPLICATION_ERROR);
                String msg = "Unable to convert extension to SAMLAssertion";
                throw new ApplicationRuntimeException(msg, e);
            }
            if (assertion == null) {
                logger.debug("Certificate " + i +
                             " does not contain a SAML assertion");
            } else {
                logger.debug("Bound SAML assertion: " + assertion.toString());
                entityID = assertion.getIssuer();
            }

            try {
                if (!CertUtil.isImpersonationProxy(certs[i])) {
                    if (assertion != null) {
                        assert (entityID != null);
                        // map the SAML issuer to the certificate issuer:
                        X500Principal certIssuer =
                            certs[i].getIssuerX500Principal();
                        String dn = certIssuer.getName(X500Principal.RFC2253);
                        logger.debug("Mapping SAML issuer to " +
                                     "certificate issuer: " + dn);
                        entityMap.addMapping(entityID, dn);
                    }
                    logger.debug("All certificates processed");
                    break;
                } else {
                    if (assertion != null) {
                        assert (entityID != null);
                        // map the SAML issuer to the proxy issuer:
                        logger.debug("Mapping SAML issuer to " +
                                     "proxy issuer: " + eecSubjectDN);
                        entityMap.addMapping(entityID, eecSubjectDN);
                    }
                    continue;
                }
            } catch (CertificateException e) {
                this.setExitCode(APPLICATION_ERROR);
                String msg = "Unable to determine if certificate is an " +
                             "impersonation proxy";
                throw new ApplicationRuntimeException(msg, e);
            }
        }

        GridShibEntityMapper.register(entityMap);
    }

    /**
     * Creates a security context from the SAML assertions bound
     * to the certificate chain.
     *
     * @return a string representation of the resulting SAML
     *         security context
     */
    private String consumeX509BoundSAML(boolean verbose)
                                 throws ApplicationRuntimeException {

        /* Get a security context for the subject and
         * add the certificate chain of the credential
         * to the security context.
         */
        Subject subject = new Subject();
        SAMLSecurityContext secCtx =
           SAMLSecurityContext.getSAMLSecurityContext(subject);
        assert (secCtx != null);
        secCtx.addCertificateChain(credential.getCertificateChain());

        try {
            SAMLUtil.consumeSAMLAssertions(subject);
        } catch (IOException e) {
            this.setExitCode(APPLICATION_ERROR);
            String msg = "Unable to decode extension";
            throw new ApplicationRuntimeException(msg, e);
        } catch (SAMLException e) {
            this.setExitCode(APPLICATION_ERROR);
            String msg = "Unable to convert extension to SAMLAssertion";
            throw new ApplicationRuntimeException(msg, e);
        } catch (CertificateException e) {
            this.setExitCode(APPLICATION_ERROR);
            String msg = "Unable to determine if certificate is an " +
                         "impersonation proxy";
            throw new ApplicationRuntimeException(msg, e);
        }

        return secCtx.toString(verbose);
    }
}
