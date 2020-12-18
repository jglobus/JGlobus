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

import java.io.PrintWriter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.saml.BaseLoggingCLI;

/**
 * Command-line interface for the SAML Security Information Tool.
 *
 * @see org.globus.gridshib.common.BaseLoggingCLI
 *
 * @since 0.5.0
 */
public abstract class InfoToolCLI extends BaseLoggingCLI {

    private static Log logger =
        LogFactory.getLog(InfoToolCLI.class.getName());

    static {

        // Override description of <code>--infile</code> option:
        INPUT_DESCRIPTION =
            "Path to a Globus credential (defaults to stdin)";

        // Override description of <code>--outfile</code> option:
        OUTPUT_DESCRIPTION =
            "Send the output to this file (defaults to stdout)";
    }

    /**
     * Description of the <code>--verbose</code> option.
     */
    protected static String VERBOSE_DESCRIPTION =
        "Indicates verbose mode " +
        "(precludes the extract option)";

    /**
     * Description of the <code>--extract</code> option.
     */
    protected static String EXTRACT_DESCRIPTION =
        "Indicates a SAML assertion is to be extracted " +
        "(precludes the verbose option)";

    protected static final Option VERBOSE =
        OptionBuilder.hasArg(false)
        .withDescription(VERBOSE_DESCRIPTION)
        .withLongOpt("verbose").create("v");

    protected static final Option EXTRACT =
        OptionBuilder.hasArg(false)
        .withDescription(EXTRACT_DESCRIPTION)
        .withLongOpt("extract").create("e");

    private boolean verbose = false;
    private boolean extract = false;
    protected boolean isVerbose() { return this.verbose; }
    protected boolean wantsExtract() { return this.extract; }

    protected InfoToolCLI(String[] args) {

        super(args);

        Options options = getOptions();
        options.addOption(VERBOSE);
        options.addOption(EXTRACT);

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
    }

    protected void validate() throws Exception {

        super.validate();
        CommandLine line = this.getCommandLine();

        if (line.hasOption(VERBOSE.getOpt())) {
            this.verbose = true;
            logger.debug("Option verbose set");
        } else {
            logger.debug("Option verbose not set");
        }

        if (line.hasOption(EXTRACT.getOpt())) {
            this.extract = true;
            logger.debug("Option extract set");
        } else {
            logger.debug("Option extract not set");
        }

        if (this.isVerbose() && this.wantsExtract()) {
            String msg = "Both options verbose and extract " +
                         "not allowed";
            logger.error(msg);
            if (!wantQuiet()) { System.err.println(msg); }
            System.exit(COMMAND_LINE_ERROR);
        }
    }

    protected void displayUsage( ) {

        String usage = "gridshib-saml-info " +
            "[--" + HELP.getLongOpt() +
            " |" +
            " [--" + INPUT.getLongOpt() + " <" + INPUT.getArgName() + ">]" +
            " [--" + OUTPUT.getLongOpt() + " <" + OUTPUT.getArgName() + ">]" +
            " [--" + DEBUG.getLongOpt() + "]" +
            " [--" + QUIET.getLongOpt() + "]" +
            " [--" + VERBOSE.getLongOpt() +
            " | --" + EXTRACT.getLongOpt() + "]" +
            "]";

        HelpFormatter formatter = new HelpFormatter();
        PrintWriter out = new PrintWriter(System.out);
        formatter.printWrapped(
                out, HelpFormatter.DEFAULT_WIDTH, 0,
                "Description: Prints the SAML security information " +
                "bound to the specified credential");
        out.println();
        formatter.printUsage(out, HelpFormatter.DEFAULT_WIDTH, usage);
        out.println();
        formatter.printOptions(
                out, HelpFormatter.DEFAULT_WIDTH, getOptions(),
                HelpFormatter.DEFAULT_DESC_PAD,
                HelpFormatter.DEFAULT_LEFT_PAD);

        out.flush();
        out.close();
    }
}

