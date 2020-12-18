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

import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Command-line interface for the GRAM Audit Test Tool.
 *
 * @see org.teragrid.ncsa.gridshib.tool.gram.GRAMAuditToolsCLI
 *
 * @since 0.5.5
 */
public abstract class TestToolCLI extends GRAMAuditToolsCLI {

    private static Log logger =
        LogFactory.getLog(TestToolCLI.class.getName());

    protected TestToolCLI(String[] args) {

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

    protected void displayUsage() {

        String about = "Description: Test a connection " +
                       "to a GRAM Audit database";

        String usage1 = "test-gram-audit" + " --" + HELP.getLongOpt();

        String usage2 = "test-gram-audit" +
            " [--" + MAXDELTA.getLongOpt() + " <" + MAXDELTA.getArgName() + ">]" +
            " [--" + UTC.getLongOpt() + "]" +
            " [--" + CONFIG.getLongOpt() + " <" + CONFIG.getArgName() + ">]" +
            " [--" + DEBUG.getLongOpt() + "]" +
            " [--" + QUIET.getLongOpt() + "]";

        Options testOptions = new Options();
        testOptions.addOption(CONFIG);
        testOptions.addOption(MAXDELTA);
        testOptions.addOption(UTC);
        testOptions.addOption(DEBUG);
        testOptions.addOption(HELP);
        testOptions.addOption(QUIET);

        PrintWriter out = new PrintWriter(System.out);

        HelpFormatter formatter = new HelpFormatter();
        formatter.printWrapped(out, HelpFormatter.DEFAULT_WIDTH, 0, about);
        out.println();
        formatter.printUsage(out, HelpFormatter.DEFAULT_WIDTH, usage1);
        formatter.printUsage(out, HelpFormatter.DEFAULT_WIDTH, usage2);
        out.println();
        formatter.printOptions(
                out, HelpFormatter.DEFAULT_WIDTH,
                testOptions,
                HelpFormatter.DEFAULT_DESC_PAD,
                HelpFormatter.DEFAULT_LEFT_PAD);

        out.flush();
        out.close();
    }
}

