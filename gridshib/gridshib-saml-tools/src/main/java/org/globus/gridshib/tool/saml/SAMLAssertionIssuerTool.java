/*
 * Copyright 1999-2007 University of Chicago
 * Copyright 2006-2009 University of Illinois
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

import java.io.File;
import java.io.IOException;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.cli.ApplicationRuntimeException;
import org.globus.gridshib.saml.SAMLToolsCLI;
import org.globus.gridshib.security.saml.GlobusSAMLException;
import org.globus.gridshib.security.saml.SelfIssuedAssertion;
import org.globus.gridshib.security.x509.GlobusSAMLCredential;
import org.globus.gridshib.security.x509.SAMLX509Extension;
import org.globus.gridshib.security.util.GSIUtil;

import org.globus.gsi.X509Credential;
import org.globus.gsi.CredentialException;

/**
 * This is the SAML Assertion Issuer Tool.  It issues a
 * SAML assertion and optionally encodes the assertion
 * as a DER-encoded X.509 certificate extensionan or
 * binds the assertion to a non-critical extension of
 * an X.509 proxy certificate.
 */
public class SAMLAssertionIssuerTool extends SAMLToolCLI
                                  implements SAMLToolsCLI {

    private static Log logger =
        LogFactory.getLog(SAMLAssertionIssuerTool.class.getName());

    private static final int SENDER_VOUCHES =
        GlobusSAMLCredential.SENDER_VOUCHES;
    private static final int HOLDER_OF_KEY =
        GlobusSAMLCredential.HOLDER_OF_KEY;

    /**
     * @since 0.5.0
     */
    public SAMLAssertionIssuerTool(String[] args) {
        super(args);
    }

    public static void main(String[] args) {

        SAMLAssertionIssuerTool cli = new SAMLAssertionIssuerTool(args);

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

        logger.info("Begin execution of SAMLAssertionIssuerTool");

        GlobusSAMLCredential credential = null;
        if (this.indicatesVouches()) {
            try {
                credential =
                    new GlobusSAMLCredential(this.getUser(), SENDER_VOUCHES);
            } catch (GlobusSAMLException e) {
                this.setExitCode(APPLICATION_ERROR);
                String msg = "Unable to create Globus SAML credential " +
                             "with sender-vouches subject confirmation";
                throw new ApplicationRuntimeException(msg, e);
            }
            credential.setSAMLLifetime(this.getLifetime());
            if (this.getSSOResponse() != null) {
                credential.setSSOResponseFile(this.getSSOResponse());
            } else {
                String authnMethod = this.getAuthnMethod();
                Date authnInstant = this.getAuthnInstant();
                if (authnMethod != null && authnInstant != null) {
                    credential.setAuthnContext(
                            authnMethod, authnInstant, this.getSubjectIP());
                }
            }
        } else {
            try {
                credential =
                    new GlobusSAMLCredential(this.getUser(), HOLDER_OF_KEY);
            } catch (GlobusSAMLException e) {
                this.setExitCode(APPLICATION_ERROR);
                String msg = "Unable to create Globus SAML credential " +
                             "with holder-of-key subject confirmation";
                throw new ApplicationRuntimeException(msg, e);
            }
            credential.setSAMLLifetime(this.getLifetime());
        }
        if (this.getInputPath() != null) {
            credential.setXMLFile(new File(this.getInputPath()));
        }

        // use issuing credential on the command line (if any):
        if (this.getIssuingCredential() != null) {
            credential.setCredential(this.getIssuingCredential());
        }

        SelfIssuedAssertion assertion = null;
        try {
            assertion = credential.getSAMLToken();
        } catch (GlobusSAMLException e) {
            this.setExitCode(APPLICATION_ERROR);
            String msg = "Unable to get a SAML token";
            throw new ApplicationRuntimeException(msg, e);
        }

        // output appropriate format (SAML, ASN.1, or X.509):
        if (this.indicatesX509() || this.indicatesASN1()) {
            if (this.indicatesASN1()) {
                logger.debug("Output DER-encoded ASN.1");
                SAMLX509Extension ext = null;
                try {
                    ext = credential.getSAMLExtension();
                } catch (GlobusSAMLException e) {
                    this.setExitCode(APPLICATION_ERROR);
                    String msg = "Unable to get the SAML token";
                    throw new ApplicationRuntimeException(msg, e);
                } catch (IOException e) {
                    this.setExitCode(APPLICATION_ERROR);
                    String msg = "Unable to create SAML X.509 Extension";
                    throw new ApplicationRuntimeException(msg, e);
                }
                try {
                    if (this.getOutputPath() == null) {
                        logger.debug("Output to stdout");
                        ext.printValue();
                    } else {
                        String msg =
                            "Output to file " + this.getOutputPath();
                        logger.debug(msg);
                        ext.writeValueToFile(this.getOutputPath());
                    }
                } catch (IOException e) {
                    this.setExitCode(APPLICATION_ERROR);
                    String msg = "Unable to print SAML X.509 Extension";
                    throw new ApplicationRuntimeException(msg, e);
                }
            } else {
                logger.debug("Output PEM-encoded X.509 proxy credential");
                // bind extension to X.509 proxy certificate:
                X509Credential proxy = null;
                try {
                    int lifetime = this.getX509Lifetime();
                    if (lifetime == 0) {
                        proxy = credential.issue();
                    } else {
                        credential.setX509Lifetime(lifetime);
                        proxy = credential.issue();
                    }
                } catch (GlobusSAMLException e) {
                    this.setExitCode(APPLICATION_ERROR);
                    String msg = "Unable to get the SAML token";
                    throw new ApplicationRuntimeException(msg, e);
                } catch (CredentialException e) {
                    this.setExitCode(APPLICATION_ERROR);
                    String msg = "Unable to bind the SAML token to proxy cert";
                    throw new ApplicationRuntimeException(msg, e);
                }
                // output X.509 proxy credential:
                try {
                    if (this.getOutputPath() == null) {
                        logger.debug("Output to stdout");
                        //proxy.save(System.out);
                        GSIUtil.printCredential(proxy);
                    } else {
                        String msg =
                            "Output to file " + this.getOutputPath();
                        logger.debug(msg);
                        GSIUtil.writeCredentialToFile(proxy, this.getOutputPath());
                    }
                } catch (Exception e) {
                    this.setExitCode(APPLICATION_ERROR);
                    String msg = "Unable to output proxy credential";
                    throw new ApplicationRuntimeException(msg, e);
                }
            }
        } else {
            logger.debug("Output SAML assertion");
            try {
                if (this.getOutputPath() == null) {
                    logger.debug("Output to stdout");
                    System.out.println(assertion.toString());
                } else {
                    String msg =
                        "Output to file " + this.getOutputPath();
                    logger.debug(msg);
                    assertion.writeToFile(this.getOutputPath());
                }
            } catch (Exception e) {
                this.setExitCode(APPLICATION_ERROR);
                String msg = "Error writing SAML assertion";
                throw new ApplicationRuntimeException(msg, e);
            }
        }

        this.setExitCode(SUCCESS_CODE);

        logger.info("End execution of SAMLAssertionIssuerTool");
    }
}
