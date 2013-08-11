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

package org.globus.gridshib.tool.x509;

import java.io.ByteArrayInputStream;
import java.io.PrintWriter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.GridShibConfigException;
import org.globus.gridshib.config.SAMLToolsConfig;
import org.globus.gridshib.config.SAMLToolsConfigLoader;
import org.globus.gridshib.saml.CommonCLI;

/**
 * Command-line interface for the X.509 Binding Tool.
 * Loads a configuration file and then parses the command line.
 *
 * @see org.globus.gridshib.common.CommonCLI
 *
 * @since 0.3.0
 */
public abstract class X509ToolCLI extends CommonCLI {

    private static Log logger =
        LogFactory.getLog(X509ToolCLI.class.getName());

    static {

        // Override description of <code>--infile</code> option:
        INPUT_DESCRIPTION =
            "Path to arbitrary extension content to be bound " +
            "to the proxy certificate (if omitted, defaults to stdin)";

        // Override description of <code>--asn1</code> option:
        ASN1_DESCRIPTION =
            "Indicates the input is " +
            "a DER-encoded ASN.1 structure (the default input option)";
    }

    /**
     * Description of the <code>--oid</code> option.
     */
    protected static final String OID_DESCRIPTION =
        "OID of non-critical certificate extension ";

    /**
     * The <code>--oid</code> option.
     *
     * @since 0.3.0
     */
    protected static final Option OID =
        OptionBuilder.withArgName("oid").hasArg()
        .withDescription(OID_DESCRIPTION)
        .withLongOpt("oid").create("O");

    private static SAMLToolsConfig config = null;
    public SAMLToolsConfig getConfig() { return config; }

    private String oid = null;
    protected String getOID() { return this.oid; }

    protected X509ToolCLI(String[] args) {

        super(args);

        Options options = getOptions();
        options.addOption(OID);

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

        // load the config file:
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
        }

        // get the config:
        try {
            config = SAMLToolsConfigLoader.getToolConfig();
        } catch (GridShibConfigException e) {
            logger.error("Error getting config", e);
            if (!wantQuiet()) { System.err.println(e.getMessage()); }
            System.exit(CONFIG_FILE_ERROR);
        }
    }

    protected void validate() throws Exception {

        super.validate();
        CommandLine line = this.getCommandLine();

        // what is the OID?
        if (line.hasOption(OID.getOpt())) {
            this.oid = line.getOptionValue(OID.getOpt()).trim();
            logger.debug("Option oid: " + this.oid);
        } else {
            String msg = "OID is required";
            logger.error(msg);
            if (!wantQuiet()) { System.err.println(msg); }
            System.exit(COMMAND_LINE_ERROR);
        }
    }

    protected void displayUsage() {

        String usage1 = "gridshib-proxy-bind" + " --" + HELP.getLongOpt();

        String usage2 = "gridshib-proxy-bind" +
            " --" + OID.getLongOpt() + " <" + OID.getArgName() + ">" +
            " [--" + SAML.getLongOpt() +
            " | --" + ASN1.getLongOpt() + "]" +
            " [--" + X509.getLongOpt() +
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
                out, HelpFormatter.DEFAULT_WIDTH, 0,
                "Description: Binds arbitrary content to a non-critical " +
                "extension of an X.509 proxy certificate");
        out.println();
        formatter.printUsage(out, HelpFormatter.DEFAULT_WIDTH, usage1);
        formatter.printUsage(out, HelpFormatter.DEFAULT_WIDTH, usage2);
        out.println();
        formatter.printOptions(
                out, HelpFormatter.DEFAULT_WIDTH, getOptions(),
                HelpFormatter.DEFAULT_DESC_PAD,
                HelpFormatter.DEFAULT_LEFT_PAD);

        out.flush();
        out.close();
    }
}

