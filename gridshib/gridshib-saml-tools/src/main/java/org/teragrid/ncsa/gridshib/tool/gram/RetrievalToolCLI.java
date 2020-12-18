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
import java.text.SimpleDateFormat;
import java.util.TimeZone;

import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Command-line interface for the GRAM Audit Retrieval Tool.
 *
 * @see org.teragrid.ncsa.gridshib.tool.gram.GRAMAuditToolsCLI
 *
 * @since 0.5.5
 */
public abstract class RetrievalToolCLI extends GRAMAuditToolsCLI {

    private static Log logger =
        LogFactory.getLog(RetrievalToolCLI.class.getName());

    static {

        // Override description of <code>--infile</code> option:
        INPUT_DESCRIPTION =
            "Take the input from this file (defaults to stdin)";

        // Override description of <code>--outfile</code> option:
        OUTPUT_DESCRIPTION =
            "Send the output to this file (defaults to stdout)";

        // Override description of <code>--maxDelta</code> option.
        MAXDELTA_DESCRIPTION =
            "Selects all jobs created within the given number of hours " +
            "of the input dateTime string " +
            "(defaults to " + MAX_DELTA_HRS + ")";
    }

    protected SimpleDateFormat firstFormat;
    protected SimpleDateFormat secondFormat;
    protected SimpleDateFormat getFirstDateFormat() {
        return this.firstFormat;
    }
    protected SimpleDateFormat getSecondDateFormat() {
        return this.secondFormat;
    }
    protected void reverseDateFormats() {
        SimpleDateFormat tempFormat = this.firstFormat;
        this.firstFormat = this.secondFormat;
        this.secondFormat = tempFormat;
    }

    protected RetrievalToolCLI(String[] args) {

        super(args);

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

        // initialize the date formats:
        this.firstFormat = new SimpleDateFormat(UTC_DATETIME_PATTERN);
        this.firstFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        this.secondFormat = new SimpleDateFormat(DEFAULT_DATETIME_PATTERN);
        this.secondFormat.setTimeZone(TimeZone.getDefault());
    }

    protected void displayUsage() {

        String about = "Description: Resolves attributes " +
                       "from the GRAM Audit database";

        String usage1 =
            "resolve-gram-attributes" + " --" + HELP.getLongOpt();

        String usage2 = "resolve-gram-attributes" +
            " [--" + MAXDELTA.getLongOpt() + " <" + MAXDELTA.getArgName() + ">]" +
            " [--" + CONFIG.getLongOpt() + " <" + CONFIG.getArgName() + ">]" +
            " [--" + INPUT.getLongOpt() + " <" + INPUT.getArgName() + ">]" +
            " [--" + OUTPUT.getLongOpt() + " <" + OUTPUT.getArgName() + ">]" +
            " [--" + DEBUG.getLongOpt() + "]" +
            " [--" + QUIET.getLongOpt() + "]";

        Options retrievalOptions = new Options();
        retrievalOptions.addOption(CONFIG);
        retrievalOptions.addOption(INPUT);
        retrievalOptions.addOption(OUTPUT);
        retrievalOptions.addOption(MAXDELTA);
        retrievalOptions.addOption(DEBUG);
        retrievalOptions.addOption(HELP);
        retrievalOptions.addOption(QUIET);

        PrintWriter out = new PrintWriter(System.out);

        HelpFormatter formatter = new HelpFormatter();
        formatter.printWrapped(out, HelpFormatter.DEFAULT_WIDTH, 0, about);
        out.println();
        formatter.printUsage(out, HelpFormatter.DEFAULT_WIDTH, usage1);
        formatter.printUsage(out, HelpFormatter.DEFAULT_WIDTH, usage2);
        out.println();
        formatter.printOptions(
                out, HelpFormatter.DEFAULT_WIDTH,
                retrievalOptions,
                HelpFormatter.DEFAULT_DESC_PAD,
                HelpFormatter.DEFAULT_LEFT_PAD);

        out.flush();
        out.close();
    }
}

