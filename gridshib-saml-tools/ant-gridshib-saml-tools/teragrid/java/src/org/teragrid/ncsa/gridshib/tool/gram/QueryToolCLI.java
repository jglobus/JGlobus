/*
 * Copyright 2009 University of Illinois
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

package org.teragrid.ncsa.gridshib.tool.gram;

import java.io.PrintWriter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Command-line interface for the GRAM Audit Query Tool.
 *
 * @see org.teragrid.ncsa.gridshib.tool.gram.GRAMAuditToolsCLI
 *
 * @since 0.5.5
 */
public abstract class QueryToolCLI extends GRAMAuditToolsCLI {

    private static Log logger =
        LogFactory.getLog(QueryToolCLI.class.getName());

    /**
     * Description of <code>--GJID</code> option.
     */
    protected static String GJID_DESCRIPTION =
        "The string representation of a " +
        "resource endpoint reference (EPR)";

    /**
     * The <code>--GJID</code> option.
     */
    protected static Option GJID;
    protected static String GJID_ARGNAME = "EPR";
    protected static String GJID_LONGOPT = "GJID";
    protected static String GJID_OPT = "E";

    protected String epr;
    protected String getEPR() { return this.epr; }

    protected QueryToolCLI(String[] args) {

        super(args);
        this.addOptions();

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

    private void addOptions() {

        GJID =
            OptionBuilder.withArgName(GJID_ARGNAME).hasArg()
            .withDescription(GJID_DESCRIPTION)
            .withLongOpt(GJID_LONGOPT).create(GJID_OPT);

        Options options = this.getOptions();
        options.addOption(GJID);
    }

    protected void validate() throws Exception {

        super.validate();
        CommandLine line = this.getCommandLine();

        // what is the EPR?
        if (line.hasOption(GJID.getOpt())) {
            this.epr = line.getOptionValue(GJID.getOpt()).trim();
            logger.debug("Option EPR: " + this.epr);
        } else {
            logger.debug("Option EPR not set");
        }
    }

    protected void displayUsage() {

        String about = "Description: Inspect the contents " +
                       "of the GRAM Audit table";

        String usage1 = "get-audit-records" + " --" + HELP.getLongOpt();

        String usage2 = "get-audit-records" +
            " [--" + MAXDELTA.getLongOpt() + " <" + MAXDELTA.getArgName() + ">" +
            " | --" + GJID.getLongOpt() + " <" + GJID.getArgName() + ">]" +
            " [--" + UTC.getLongOpt() + "]" +
            " [--" + CONFIG.getLongOpt() + " <" + CONFIG.getArgName() + ">]" +
            " [--" + DEBUG.getLongOpt() + "]" +
            " [--" + QUIET.getLongOpt() + "]";

        Options queryOptions = new Options();
        queryOptions.addOption(MAXDELTA);
        queryOptions.addOption(GJID);
        queryOptions.addOption(UTC);
        queryOptions.addOption(CONFIG);
        queryOptions.addOption(DEBUG);
        queryOptions.addOption(HELP);
        queryOptions.addOption(QUIET);

        PrintWriter out = new PrintWriter(System.out);

        HelpFormatter formatter = new HelpFormatter();
        formatter.printWrapped(out, HelpFormatter.DEFAULT_WIDTH, 0, about);
        out.println();
        formatter.printUsage(out, HelpFormatter.DEFAULT_WIDTH, usage1);
        formatter.printUsage(out, HelpFormatter.DEFAULT_WIDTH, usage2);
        out.println();
        formatter.printOptions(
                out, HelpFormatter.DEFAULT_WIDTH,
                queryOptions,
                HelpFormatter.DEFAULT_DESC_PAD,
                HelpFormatter.DEFAULT_LEFT_PAD);

        out.flush();
        out.close();
    }
}

