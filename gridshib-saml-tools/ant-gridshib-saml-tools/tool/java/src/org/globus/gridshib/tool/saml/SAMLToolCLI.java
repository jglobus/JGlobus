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

package org.globus.gridshib.tool.saml;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.FileLocation;
import org.globus.gridshib.common.GridShibConfigException;
import org.globus.gridshib.config.SAMLToolsConfig;
import org.globus.gridshib.config.SAMLToolsConfigLoader;
import org.globus.gridshib.saml.SAMLBasicCLI;

import org.globus.opensaml11.saml.SAMLAuthenticationStatement;

/**
 * Command-line interface for the SAML Assertion Issuer Tool.
 * Parses the command line and then loads a configuration file.
 *
 * @see org.globus.gridshib.common.SAMLBasicCLI
 */
public abstract class SAMLToolCLI extends SAMLBasicCLI {

    private static Log logger =
        LogFactory.getLog(SAMLToolCLI.class.getName());

    private static final String DEFAULT_AUTHNMETHOD =
        SAMLAuthenticationStatement.AuthenticationMethod_Unspecified;

    static {

        // Override description of <code>--infile</code> option:
        INPUT_DESCRIPTION =
            "The path to arbitrary XML content to be bound to " +
            "the SAML assertion's <Advice> element";

        // Override description of <code>--saml</code> option:
        SAML_DESCRIPTION =
            "Indicates the output is a SAML assertion " +
            "(the default output option)";
    }

    /**
     * Description of <code>--lifetime</code> option.
     */
    private static final String LIFETIME_DESCRIPTION =
        "Lifetime (in seconds) of the SAML assertion";

    /**
     * Description of <code>--authn</code> option.
     */
    private static final String AUTHN_DESCRIPTION =
        "Indicates a <saml:AuthenticationStatement> element is to " +
        "be issued (requires the --sender-vouches option and " +
        "is mutually exclusive of the --ssoResponse option)";

    /**
     * Description of <code>--authnMethod</code> option.
     */
    private static final String AUTHNMETHOD_DESCRIPTION =
        "SAML AuthenticationMethod URI (requires the --authn option)";

    /**
     * Description of <code>--authnInstant</code> option.
     */
    private static final String AUTHNINSTANT_DESCRIPTION =
        "SAML AuthenticationInstant (requires and is required by " +
        "the --authn option)";

    /**
     * Description of <code>--address</code> option.
     */
    private static final String ADDRESS_DESCRIPTION =
        "Subject IP address (requires --authn option)";

    /**
     * Description of <code>--ssoResponse</code> option.
     */
    private static final String SSO_RESPONSE_DESCRIPTION =
        "The path to a SAML Web Browser SSO Response " +
        "(requires the --sender-vouches option and is " +
        "mutually exclusive of the --authn option)";

    private static final Option LIFETIME =
        OptionBuilder.withArgName("secs").hasArg()
        .withDescription(LIFETIME_DESCRIPTION)
        .withLongOpt("lifetime").create("e");

    private static final Option AUTHN =
        OptionBuilder.hasArg(false)
        .withDescription(AUTHN_DESCRIPTION)
        .withLongOpt("authn").create("a");

    private static final Option AUTHNMETHOD =
        OptionBuilder.withArgName("URI").hasArg()
        .withDescription(AUTHNMETHOD_DESCRIPTION)
        .withLongOpt("authnMethod").create("M");

    private static final Option AUTHNINSTANT =
        OptionBuilder.withArgName("dateTime").hasArg()
        .withDescription(AUTHNINSTANT_DESCRIPTION)
        .withLongOpt("authnInstant").create("I");

    private static final Option ADDRESS =
        OptionBuilder.withArgName("IPAddress").hasArg()
        .withDescription(ADDRESS_DESCRIPTION)
        .withLongOpt("address").create("i");

    private static final Option RESPONSE =
        OptionBuilder.withArgName("path").hasArg()
        .withDescription(SSO_RESPONSE_DESCRIPTION)
        .withLongOpt("ssoResponse").create("R");

    private static SAMLToolsConfig config = null;

    /**
     * @since 0.5.0
     */
    public SAMLToolsConfig getConfig() { return config; }

    // command-line options:
    private int lifetime = 0;
    private boolean authn = false;
    private String authnMethod = null;
    private Date authnInstant = null;
    private String subjectIP = null;
    private File ssoResponse = null;

    // trivial getter methods:
    protected int getLifetime() { return this.lifetime; }
    protected boolean wantsAuthn() { return this.authn; }
    protected String getAuthnMethod() { return this.authnMethod; }
    protected Date getAuthnInstant() { return this.authnInstant; }
    protected String getSubjectIP() { return this.subjectIP; }
    protected File getSSOResponse() { return this.ssoResponse; }

    // the raw dateTime string on the command line:
    private String dateTime = null;

    /**
     * This command-line interface defaults to SAML output.
     *
     * @since 0.5.0
     */
    protected boolean indicatesSAML() {
        return !(indicatesX509() || indicatesASN1());
    }

    protected SAMLToolCLI(String[] args) {

        super(args);

        Options options = getOptions();
        options.addOption(LIFETIME);
        options.addOption(AUTHN);
        options.addOption(AUTHNMETHOD);
        options.addOption(AUTHNINSTANT);
        options.addOption(ADDRESS);
        options.addOption(RESPONSE);

        // parse the command line:
        try {
            parse();
        } catch (ParseException e) {
            logger.error("Parse error", e);
            if (!wantQuiet()) { System.err.println(e.getMessage()); }
            System.exit(COMMAND_LINE_ERROR);
        } catch (Exception e) {
            logger.error("Error", e);
            if (!wantQuiet()) { System.err.println(e.getMessage()); }
            System.exit(COMMAND_LINE_ERROR);
        }

        // load the config file specified on the command line:
        try {
            logger.info("Loading config file: " + this.getConfigFile());
            SAMLToolsConfigLoader.load(this.getConfigFile());
        } catch (GridShibConfigException e) {
            logger.error("Error loading config file", e);
            if (!wantQuiet()) { System.err.println(e.getMessage()); }
            System.exit(CONFIG_FILE_ERROR);
        }

        // load any config props specified on the command line:
        if (this.getConfigProperties() != null) {
            logger.info("Loading dynamic config properties: " +
                        this.getConfigProperties());
            byte[] bytes = this.getConfigProperties().getBytes();
            try {
                SAMLToolsConfigLoader.overlay(new ByteArrayInputStream(bytes));
            } catch (GridShibConfigException e) {
                logger.error("Error processing config properties", e);
                if (!wantQuiet()) { System.err.println(e.getMessage()); }
                System.exit(CONFIG_FILE_ERROR);
            }
        } else {
            logger.debug("No dynamic config properties to load");
        }

        // get the config:
        try {
            config = SAMLToolsConfigLoader.getToolConfig();
        } catch (GridShibConfigException e) {
            logger.error("Error getting config", e);
            if (!wantQuiet()) { System.err.println(e.getMessage()); }
            System.exit(CONFIG_FILE_ERROR);
        }

        // now that we have the config, parse the dateTime string:
        if (dateTime != null && !dateTime.equals("")) {
            Date date = null;
            try {
                String pat = this.config.getDateTimePattern();
                date = new SimpleDateFormat(pat).parse(dateTime);
                if ((new Date()).compareTo(date) > 0) {
                    logger.debug("Option authnInstant parsed: " +
                                 date.toString());
                    this.authnInstant = date;
                } else {
                    String msg = "Future authnInstant ignored: " +
                                 dateTime;
                    logger.warn(msg);
                    if (!wantQuiet()) { System.err.println(msg); }
                }
            } catch (java.text.ParseException e) {
                String msg = "Unable to parse authnInstant: " +
                             dateTime;
                logger.error(msg, e);
                if (!wantQuiet()) { System.err.println(msg); }
                System.exit(CONFIG_FILE_ERROR);
            }
        }
    }

    protected void validate() throws Exception {

        super.validate();
        CommandLine line = this.getCommandLine();

        // what is the assertion lifetime?
        if (line.hasOption(LIFETIME.getOpt())) {
            // TODO: Validate lifetime
            this.lifetime =
                Integer.parseInt(line.getOptionValue(LIFETIME.getOpt()).trim());
            logger.debug("Option lifetime: " + this.lifetime + " seconds");
        } else {
            logger.debug("Option lifetime not set");
        }

        // is an AuthenticationStatement desired?
        if (line.hasOption(AUTHN.getOpt())) {
            if (!line.hasOption(AUTHNINSTANT.getOpt())) {
                String msg = "--authnInstant option is required";
                logger.error(msg);
                if (!wantQuiet()) { System.err.println(msg); }
                System.exit(COMMAND_LINE_ERROR);
            }
            this.authn = true;
            logger.debug("Option authn set");
            this.authnMethod = DEFAULT_AUTHNMETHOD;
            logger.debug("Default authnMethod: " + this.authnMethod);
            if (line.hasOption(RESPONSE.getOpt())) {
                String msg = "Options --authn and --ssoResponse " +
                             "are mutually exclusive";
                logger.warn(msg);
                if (!wantQuiet()) { System.err.println(msg); }
            }
        } else {
            logger.debug("Option authn not set");
        }

        if (this.wantsAuthn() && this.indicatesHOK()) {
            String msg = "Both options authn and holder-of-key not allowed";
            logger.error(msg);
            if (!wantQuiet()) { System.err.println(msg); }
            System.exit(COMMAND_LINE_ERROR);
        }

        // what is the authentication method?
        if (line.hasOption(AUTHNMETHOD.getOpt())) {
            if (line.hasOption(AUTHN.getOpt())) {
                this.authnMethod =
                    line.getOptionValue(AUTHNMETHOD.getOpt()).trim();
                logger.debug("Overriding default authnMethod: " +
                          this.authnMethod);
            } else {
                String msg = "--authn option is required";
                logger.error(msg);
                if (!wantQuiet()) { System.err.println(msg); }
                System.exit(COMMAND_LINE_ERROR);
            }
        } else {
            logger.debug("Option authnMethod not set");
        }

        // what is the authentication instant?
        if (line.hasOption(AUTHNINSTANT.getOpt())) {
            if (line.hasOption(AUTHN.getOpt())) {
                dateTime = line.getOptionValue(AUTHNINSTANT.getOpt()).trim();
                logger.debug("Option authnInstant: " + dateTime);
            } else {
                String msg = "--authn option is required";
                logger.error(msg);
                if (!wantQuiet()) { System.err.println(msg); }
                System.exit(COMMAND_LINE_ERROR);
            }
        } else {
            logger.debug("Option authnInstant not set");
        }

        // what is the IP address?
        if (line.hasOption(ADDRESS.getOpt())) {
            if (line.hasOption(AUTHN.getOpt())) {
                this.subjectIP =
                    line.getOptionValue(ADDRESS.getOpt()).trim();
                logger.debug("Option address: " + this.subjectIP);
            } else {
                String msg = "--authn option is required";
                logger.error(msg);
                if (!wantQuiet()) { System.err.println(msg); }
                System.exit(COMMAND_LINE_ERROR);
            }
        } else {
            logger.debug("Option address not set");
        }

        // where is the SSO Response?
        if (line.hasOption(RESPONSE.getOpt())) {
            String ssoResponse =
                line.getOptionValue(RESPONSE.getOpt()).trim();
            logger.debug("Option ssoResponse: " + ssoResponse);
            // checking URL for backward compatibility:
            try {
                this.ssoResponse = new FileLocation(ssoResponse).toFile();
            } catch (IOException e1) {
                logger.debug("SSO Response is not a FileLocation resource: " +
                          e1.getMessage());
                this.ssoResponse = new File(ssoResponse);
                logger.debug("SSO Response is a system-dependent file path");
            }
        } else {
            logger.debug("Option ssoResponse not set");
        }

        if (this.getSSOResponse() != null && this.indicatesHOK()) {
            String msg = "Both options ssoResponse and holder-of-key not allowed";
            logger.error(msg);
            if (!wantQuiet()) { System.err.println(msg); }
            System.exit(COMMAND_LINE_ERROR);
        }
    }

    /**
     * @since 0.5.0
     */
    protected String scriptName = "gridshib-saml-issuer";

    /**
     * @since 0.5.0
     */
    protected String description =
        "Description: Self-issues a SAML assertion and " +
        "optionally binds this assertion to an X.509 proxy certificate";

    protected void displayUsage() {

        String usage1 = this.scriptName + " --" + HELP.getLongOpt();

        String usage2 = this.scriptName +
            " [[--" + USER.getLongOpt() + " <" + USER.getArgName() + ">]" +
            " --" + HOK.getLongOpt() + "]" +
            " [--" + LIFETIME.getLongOpt() + " <" + LIFETIME.getArgName() + ">]" +
            " [--" + SAML.getLongOpt() +
            " | --" + ASN1.getLongOpt() +
            " | --" + X509.getLongOpt() +
            " [--" + X509LIFETIME.getLongOpt() + " <" + X509LIFETIME.getArgName() + ">]]" +
            " [--" + CONFIG.getLongOpt() + " <" + CONFIG.getArgName() + ">]" +
            " [--" + PROPERTIES.getLongOpt() + " <" + PROPERTIES.getArgName() + "> ...]" +
            " [--" + CERT_PATH.getLongOpt() + " <" + CERT_PATH.getArgName() + ">" +
            " --" + KEY_PATH.getLongOpt() + " <" + KEY_PATH.getArgName() + ">]" +
            " [--" + INPUT.getLongOpt() + " <" + INPUT.getArgName() + ">]" +
            " [--" + OUTPUT.getLongOpt() + " <" + OUTPUT.getArgName() + ">]" +
            " [--" + DEBUG.getLongOpt() + "]" +
            " [--" + QUIET.getLongOpt() + "]";

        String usage3 = this.scriptName +
            " --" + USER.getLongOpt() + " <" + USER.getArgName() + ">" +
            " --" + SV.getLongOpt() +
            " [--" + LIFETIME.getLongOpt() + " <" + LIFETIME.getArgName() + ">]" +
            " [--" + RESPONSE.getLongOpt() + " <" + RESPONSE.getArgName() + ">" +
            " | --" + AUTHN.getLongOpt() +
            " --" + AUTHNINSTANT.getLongOpt() + " <" + AUTHNINSTANT.getArgName() + ">" +
            " [--" + AUTHNMETHOD.getLongOpt() + " <" + AUTHNMETHOD.getArgName() + ">]" +
            " [--" + ADDRESS.getLongOpt() + " <" + ADDRESS.getArgName() + ">]]" +
            " [--" + SAML.getLongOpt() +
            " | --" + ASN1.getLongOpt() +
            " | --" + X509.getLongOpt() +
            " [--" + X509LIFETIME.getLongOpt() + " <" + X509LIFETIME.getArgName() + ">]]" +
            " [--" + CONFIG.getLongOpt() + " <" + CONFIG.getArgName() + ">]" +
            " [--" + PROPERTIES.getLongOpt() + " <" + PROPERTIES.getArgName() + "> ...]" +
            " [--" + CERT_PATH.getLongOpt() + " <" + CERT_PATH.getArgName() + ">" +
            " --" + KEY_PATH.getLongOpt() + " <" + KEY_PATH.getArgName() + ">]" +
            " [--" + INPUT.getLongOpt() + " <" + INPUT.getArgName() + ">]" +
            " [--" + OUTPUT.getLongOpt() + " <" + OUTPUT.getArgName() + ">]" +
            " [--" + DEBUG.getLongOpt() + "]" +
            " [--" + QUIET.getLongOpt() + "]";

        HelpFormatter formatter = new HelpFormatter();
        PrintWriter out = new PrintWriter(System.out);
        formatter.printWrapped(
                out, HelpFormatter.DEFAULT_WIDTH, 0, this.description);
        out.println();
        formatter.printUsage(out, HelpFormatter.DEFAULT_WIDTH, usage1);
        formatter.printUsage(out, HelpFormatter.DEFAULT_WIDTH, usage2);
        formatter.printUsage(out, HelpFormatter.DEFAULT_WIDTH, usage3);
        out.println();
        formatter.printOptions(
                out, HelpFormatter.DEFAULT_WIDTH, getOptions(),
                HelpFormatter.DEFAULT_DESC_PAD,
                HelpFormatter.DEFAULT_LEFT_PAD);

        out.flush();
        out.close();
    }
}

