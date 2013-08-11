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

import java.io.PrintWriter;

import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.ParseException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.saml.BaseLoggingCLI;

/**
 * Command-line interface for the SAML Assertion Extraction Tool.
 *
 * @see org.globus.gridshib.common.BaseLoggingCLI
 *
 * @since 0.5.0
 */
public abstract class ExtractionToolCLI extends BaseLoggingCLI {

    private static Log logger =
        LogFactory.getLog(ExtractionToolCLI.class.getName());

    static {

        // Override description of <code>--infile</code> option:
        INPUT_DESCRIPTION =
            "Path to a Globus credential (defaults to stdin)";

        // Override description of <code>--outfile</code> option:
        OUTPUT_DESCRIPTION =
            "Send the output to this file (defaults to stdout)";
    }

    protected ExtractionToolCLI(String[] args) {

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
    }

    protected void displayUsage( ) {

        String usage = "gridshib-saml-extract " +
            "[--" + HELP.getLongOpt() +
            " |" +
            " [--" + INPUT.getLongOpt() + " <" + INPUT.getArgName() + ">]" +
            " [--" + OUTPUT.getLongOpt() + " <" + OUTPUT.getArgName() + ">]" +
            " [--" + DEBUG.getLongOpt() + "]" +
            " [--" + QUIET.getLongOpt() + "]" +
            "]";

        HelpFormatter formatter = new HelpFormatter();
        PrintWriter out = new PrintWriter(System.out);
        formatter.printWrapped(
                out, HelpFormatter.DEFAULT_WIDTH, 0,
                "Description: Outputs the SAML assertion " +
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

