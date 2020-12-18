/*
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

package org.globus.gridshib.saml;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.OptionBuilder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.security.util.GSIUtil;

import org.globus.gsi.X509Credential;
import org.globus.gsi.CredentialException;

/**
 * Common command-line options used by components
 * of the GridShib SAML Tools.
 *
 * @see org.globus.gridshib.common.BasicConfigCLI
 *
 * @since 0.3.0
 */
public abstract class CommonCLI extends BasicConfigCLI
                             implements SAMLToolsCLI {

    private static Log logger =
        LogFactory.getLog(CommonCLI.class.getName());

    /**
     * Description of <code>--x509</code> option.
     */
    protected static String X509_DESCRIPTION =
        "Indicates the output is a PEM-encoded " +
        "X.509 proxy credential";

    /**
     * Description of <code>--asn1</code> option.
     */
    protected static String ASN1_DESCRIPTION =
        "Indicates the input is " +
        "a DER-encoded ASN.1 structure";

    /**
     * Description of <code>--saml</code> option.
     */
    protected static String SAML_DESCRIPTION =
        "Indicates the input is a SAML assertion";

    /**
     * Description of <code>--x509Lifetime</code> option.
     */
    protected static String X509LIFETIME_DESCRIPTION =
        "Lifetime (in seconds) of the issued proxy certificate " +
        "(requires --x509 option)";

    /**
     * Description of <code>--certPath</code> option.
     *
     * @since 0.5.3
     */
    protected static String CERT_PATH_DESCRIPTION =
        "Path to certificate of the issuing credential";

    /**
     * Description of <code>--keyPath</code> option.
     *
     * @since 0.5.3
     */
    protected static String KEY_PATH_DESCRIPTION =
        "Path to private key of the issuing credential";

    /**
     * The <code>--x509</code> option.
     */
    protected static Option X509;

    /**
     * The <code>--asn1</code> option.
     */
    protected static Option ASN1;

    /**
     * The <code>--saml</code> option.
     */
    protected static Option SAML;

    /**
     * The <code>--x509Lifetime</code> option.
     */
    protected static Option X509LIFETIME;

    /**
     * The <code>--certPath</code> option.
     *
     * @since 0.5.3
     */
    protected static Option CERT_PATH;

    /**
     * The <code>--keyPath</code> option.
     *
     * @since 0.5.3
     */
    protected static Option KEY_PATH;

    private boolean x509 = false;
    private boolean asn1 = false;
    private boolean saml = false;
    private int x509Lifetime = 0;
    private X509Credential issuingCred = null;

    protected boolean indicatesX509() { return this.x509; }
    protected boolean indicatesASN1() { return this.asn1; }
    protected boolean indicatesSAML() { return this.saml; }
    protected int getX509Lifetime() { return this.x509Lifetime; }

    /**
     * @since 0.5.3
     */
    protected X509Credential getIssuingCredential() {
        return this.issuingCred;
    }

    protected CommonCLI(String[] args) {

        super(args);
        this.addOptions();
    }

    private void addOptions() {

        X509 =
            OptionBuilder.hasArg(false)
            .withDescription(X509_DESCRIPTION)
            .withLongOpt("x509").create("X");

        ASN1 =
            OptionBuilder.hasArg(false)
            .withDescription(ASN1_DESCRIPTION)
            .withLongOpt("asn1").create("A");

        SAML =
            OptionBuilder.hasArg(false)
            .withDescription(SAML_DESCRIPTION)
            .withLongOpt("saml").create("S");

        X509LIFETIME =
            OptionBuilder.withArgName("secs").hasArg()
            .withDescription(X509LIFETIME_DESCRIPTION)
            .withLongOpt("x509Lifetime").create("E");

        CERT_PATH =
            OptionBuilder.withArgName("path").hasArg()
            .withDescription(CERT_PATH_DESCRIPTION)
            .withLongOpt("certPath").create("c");

        KEY_PATH =
            OptionBuilder.withArgName("path").hasArg()
            .withDescription(KEY_PATH_DESCRIPTION)
            .withLongOpt("keyPath").create("k");

        Options options = getOptions();
        options.addOption(X509);
        options.addOption(ASN1);
        options.addOption(SAML);
        options.addOption(X509LIFETIME);
        options.addOption(CERT_PATH);
        options.addOption(KEY_PATH);
    }

    protected void validate() throws Exception {

        super.validate();
        CommandLine line = this.getCommandLine();

        // is an X.509 proxy credential desired?
        if (line.hasOption(X509.getOpt())) {
            this.x509 = true;
            logger.debug("Option x509 set");
        } else {
            logger.debug("Option x509 not set");
        }

        // is a DER-encoded ASN.1 structure expected?
        if (line.hasOption(ASN1.getOpt())) {
            this.asn1 = true;
            logger.debug("Option asn1 set");
        } else {
            logger.debug("Option asn1 not set");
        }

        // is a SAML assertion expected?
        if (line.hasOption(SAML.getOpt())) {
            this.saml = true;
            logger.debug("Option saml set");
        } else {
            logger.debug("Option saml not set");
        }

        if (this.asn1 && this.saml) {
            String msg = "Both options asn1 and saml not allowed";
            logger.error(msg);
            if (!wantQuiet()) { System.err.println(msg); }
            System.exit(COMMAND_LINE_ERROR);
        }

        // what is the lifetime of the proxy certificate?
        if (line.hasOption(X509LIFETIME.getOpt())) {
            if (line.hasOption(X509.getOpt())) {
                this.x509Lifetime =
                    Integer.parseInt(line.getOptionValue(X509LIFETIME.getOpt()).trim());
                logger.debug("Option x509Lifetime: " + this.x509Lifetime);
            } else {
                String msg = "--x509 option is required";
                logger.error(msg);
                if (!wantQuiet()) { System.err.println(msg); }
                System.exit(COMMAND_LINE_ERROR);
            }
        } else {
            logger.debug("Option x509Lifetime is not set");
        }

        // issuing credential specified on the command line?
        if (line.hasOption(CERT_PATH.getOpt()) &&
            line.hasOption(KEY_PATH.getOpt())) {

            String certPath =
                line.getOptionValue(CERT_PATH.getOpt()).trim();
            String keyPath =
                line.getOptionValue(KEY_PATH.getOpt()).trim();
            try {
                this.issuingCred = GSIUtil.getCredential(certPath, keyPath);
            } catch (CredentialException e) {
                String msg = "Unable to obtain issuing credential";
                logger.error(msg, e);
                if (!wantQuiet()) { System.err.println(msg); }
                System.exit(COMMAND_LINE_ERROR);
            }
        } else if (!line.hasOption(CERT_PATH.getOpt()) &&
                   !line.hasOption(KEY_PATH.getOpt())) {

            logger.debug("Options certPath and keyPath not set");
        } else {
            String msg = "Both options certPath and keyPath are required";
            logger.error(msg);
            if (!wantQuiet()) { System.err.println(msg); }
            System.exit(COMMAND_LINE_ERROR);
        }
    }
}

