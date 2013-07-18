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

/**
 * Basic command-line interface for the GridShib SAML Tools.
 *
 * @see org.globus.gridshib.common.CommonCLI
 */
public abstract class SAMLBasicCLI extends CommonCLI {

    private static Log logger =
        LogFactory.getLog(SAMLBasicCLI.class.getName());

    static {

        // Override description of <code>--asn1</code> option:
        ASN1_DESCRIPTION =
            "Indicates the output is to be " +
            "a DER-encoded ASN.1 structure";

        // Override description of <code>--saml</code> option:
        SAML_DESCRIPTION =
            "Indicates the output is to be a SAML assertion";

    }

    /**
     * Description of the <code>--holder-of-key</code> option.
     */
    protected static String HOK_DESCRIPTION =
        "Indicates holder-of-key subject confirmation " +
        "(the default subject confirmation option)";

    /**
     * Description of the <code>--user</code> option.
     */
    protected static String USER_DESCRIPTION =
        "Local principal name (i.e., username)";

    /**
     * Description of the <code>--sender-vouches</code> option.
     */
    protected static String SV_DESCRIPTION =
        "Indicates sender-vouches subject confirmation " +
        "(requires --user option)";

    /**
     * The <code>--holder-of-key</code> option.
     *
     * @since 0.3.0
     */
    protected static Option HOK;

    /**
     * The <code>--user</code> option.
     */
    protected static Option USER;

    /**
     * The <code>--sender-vouches</code> option.
     *
     * @since 0.3.0
     */
    protected static Option SV;

    private boolean hok = false;
    private String user = null;
    private boolean vouches = false;

    protected boolean indicatesHOK() { return this.hok; }
    protected String getUser() { return this.user; }
    protected boolean indicatesVouches() { return this.vouches; }

    protected SAMLBasicCLI(String[] args) {

        super(args);
        this.addOptions();
    }

    private void addOptions() {

        HOK =
            OptionBuilder.hasArg(false)
            .withDescription(HOK_DESCRIPTION)
            .withLongOpt("holder-of-key").create("K");

        USER =
            OptionBuilder.withArgName("name").hasArg()
            .withDescription(USER_DESCRIPTION)
            .withLongOpt("user").create("u");

        SV =
            OptionBuilder.hasArg(false)
            .withDescription(SV_DESCRIPTION)
            .withLongOpt("sender-vouches").create("V");

        Options options = getOptions();
        options.addOption(HOK);
        options.addOption(USER);
        options.addOption(SV);
    }

    protected void validate() throws Exception {

        super.validate();
        CommandLine line = this.getCommandLine();

        // is holder-of-key desired?
        if (line.hasOption(HOK.getOpt())) {
            this.hok = true;
            logger.debug("Option holder-of-key set");
        } else {
            logger.debug("Option holder-of-key not set");
        }

        // what is the local principal name?
        if (line.hasOption(USER.getOpt())) {
            this.user = line.getOptionValue(USER.getOpt()).trim();
            logger.debug("Option user: " + this.user);
        } else {
            logger.debug("Option user not set");
        }

        // is sender-vouches desired?
        if (line.hasOption(SV.getOpt())) {
            this.vouches = true;
            logger.debug("Option sender-vouches set");
        } else {
            logger.debug("Option sender-vouches not set");
        }

        if (this.indicatesVouches() && this.indicatesHOK()) {
            String msg = "Both options sender-vouches and holder-of-key " +
                         "not allowed";
            logger.error(msg);
            if (!wantQuiet()) { System.err.println(msg); }
            System.exit(COMMAND_LINE_ERROR);
        }

        if (this.getUser() != null &&
            !this.indicatesVouches() && !this.indicatesHOK()) {
            String msg = "Exactly one of sender-vouches or holder-of-key " +
                         "required";
            logger.error(msg);
            if (!wantQuiet()) { System.err.println(msg); }
            System.exit(COMMAND_LINE_ERROR);
        }

        if (this.indicatesVouches() && this.getUser() == null ) {
            String msg = "The sender-vouches option requires the user option";
            logger.error(msg);
            if (!wantQuiet()) { System.err.println(msg); }
            System.exit(COMMAND_LINE_ERROR);
        }

        if (this.indicatesX509() && this.indicatesSAML()) {
            String msg = "Both options x509 and saml not allowed";
            logger.error(msg);
            if (!wantQuiet()) { System.err.println(msg); }
            System.exit(COMMAND_LINE_ERROR);
        } else if (this.indicatesX509() && this.indicatesASN1()) {
            String msg = "Both options x509 and asn1 not allowed";
            logger.error(msg);
            if (!wantQuiet()) { System.err.println(msg); }
            System.exit(COMMAND_LINE_ERROR);
        }
    }
}

