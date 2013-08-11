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

package org.globus.gridshib.common.cli;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.PosixParser;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.BaseLogging;

/**
 * A basic command-line interface with common options used
 * by all GridShib tools and clients. This abstract class
 * should be extended by a concrete CLI implementation
 * that may add command-line options of its own.
 * <p>
 * The subclass must fulfill the following contract:
 * <ul>
 *   <li>the {@link #BaseCLI(String[])} constructor must be invoked</li>
 *   <li>the {@link #parse()} method must be called</li>
 *   <li>the abstract {@link #displayUsage()} method must be implemented</li>
 *   <li>the {@link org.globus.gridshib.common.BaseLogging} interface
 *   must be implemented</li>
 *   <li>the abstract {@link #run()} method of the
 *   {@link org.globus.gridshib.common.cli.Testable} interface must
 *   be implemented</li>
 * </ul>
 * After all the options have been added, the subclass must
 * call the parse() method of this class.
 * The validate() method should be overridden so that any
 * newly added options are validated as well.
 * <p>
 * Note: Some members of this class go all the way back to
 * GridShib SAML Tools&nbsp;v0.1.0.  See the
 * <a href="http://gridshib.globus.org/docs/gridshib-saml-tools/user-guide.html">User
 * Guide</a> for details.
 *
 * @see org.globus.gridshib.common.BaseLogging
 * @see org.globus.gridshib.common.cli.Testable
 *
 * @since 0.5.0
 */
public abstract class BaseCLI implements BaseLogging, Testable {

    private static Log logger =
        LogFactory.getLog(BaseCLI.class.getName());

    /**
     * Description of the <code>--infile</code> option.
     */
    protected static String INPUT_DESCRIPTION =
        "Take input from this file";

    /**
     * Description of the <code>--outfile</code> option.
     */
    protected static String OUTPUT_DESCRIPTION =
        "Send the output to this file";

    /**
     * The <code>--infile</code> option.
     * <p>
     * This option was introduced in GS-ST&nbsp;v0.3.0.
     */
    protected static Option INPUT;

    /**
     * The <code>--outfile</code> option.
     * <p>
     * This option was introduced in GS-ST&nbsp;v0.1.0.
     */
    protected static Option OUTPUT;

    /**
     * The <code>--debug</code> option.
     * <p>
     * This option was introduced in GS-ST&nbsp;v0.1.0.
     */
    protected static Option DEBUG;

    /**
     * The <code>--quiet</code> option.
     * <p>
     * This option was introduced in GS-ST&nbsp;v0.1.0.
     */
    protected static Option QUIET;

    /**
     * The <code>--help</code> option.
     * <p>
     * This option was introduced in GS-ST&nbsp;v0.1.0.
     */
    protected static Option HELP;

    private String inputPath = null;
    private String outputPath = null;
    private boolean debug = false;
    private boolean quiet = false;

    protected String getInputPath() { return this.inputPath; }
    protected String getOutputPath() { return this.outputPath; }
    protected boolean isDebug() { return this.debug; }
    protected boolean wantQuiet() { return this.quiet; }

    private Options options = new Options();
    private CommandLine commandLine = null;

    protected Options getOptions() { return options; }
    public CommandLine getCommandLine() { return commandLine; }

    private String[] args = null;
    private int exitCode;

    public String[] getArgs() { return this.args; }

    public abstract void run() throws ApplicationRuntimeException;

    /**
     * If this method is called before calling the
     * {@link #setExitCode(int)} method, this
     * method returns {@link #SECURITY_ERROR}.
     * This helps prevent unintended exit codes.
     */
    public int getExitCode() {

        return getExitCode(false);
    }

    /**
     * This method is equivalent to
     *
     * <pre>this.run();
     * int exitCode = this.getExitCode();</pre>
     *
     * If the {@link #run()} method throws an exception, this
     * method logs an error message and returns the exit
     * code.  For this reason, this method is mainly useful
     * in unit tests.
     */
    public int getExitCode(boolean forceRun) {

        if (forceRun) {
            try {
                this.run();
            } catch (ApplicationRuntimeException e) {
                String msg = "Unable to run this application";
                logger.error(msg, e);
            }
        }

        return this.exitCode;
    }

    public void setExitCode(int exitCode) {

        switch (exitCode) {
            case SUCCESS_CODE:
                this.exitCode = SUCCESS_CODE;
                logger.debug("Set success exit code: " + exitCode);
                break;
            case SECURITY_ERROR:
                this.exitCode = SECURITY_ERROR;
                logger.debug("Set security error code: " + exitCode);
                break;
            case CONFIG_FILE_ERROR:
                this.exitCode = CONFIG_FILE_ERROR;
                logger.debug("Set config file error code: " + exitCode);
                break;
            case COMMAND_LINE_ERROR:
                this.exitCode = COMMAND_LINE_ERROR;
                logger.debug("Set command line error code: " + exitCode);
                break;
            case APPLICATION_ERROR:
                this.exitCode = APPLICATION_ERROR;
                logger.debug("Set application error code: " + exitCode);
                break;
            default:
                this.exitCode = exitCode;
                String msg = "Unrecognizable exit code: " + exitCode;
                logger.warn(msg);
                break;
        }
    }

    /**
     * A subclass MUST invoke this constructor.
     *
     * @param args an array of command-line arguments
     */
    protected BaseCLI(String[] args) {

        this.args = args;
        this.addOptions();
        this.exitCode = SECURITY_ERROR;
    }

    private void addOptions() {

        INPUT =
            OptionBuilder.withArgName("path").hasArg()
            .withDescription(INPUT_DESCRIPTION)
            .withLongOpt("infile").create("f");

        OUTPUT =
            OptionBuilder.withArgName("path").hasArg()
            .withDescription(OUTPUT_DESCRIPTION)
            .withLongOpt("outfile").create("o");

        DEBUG =
            OptionBuilder.hasArg(false)
            .withDescription("Indicates debugging mode")
            .withLongOpt("debug").create("d");

        QUIET =
            OptionBuilder.hasArg(false)
            .withDescription("Indicates quiet mode")
            .withLongOpt("quiet").create("q");

        HELP =
            OptionBuilder.hasArg(false)
            .withDescription("Displays help message")
            .withLongOpt("help").create("h");

        options.addOption(INPUT);
        options.addOption(OUTPUT);
        options.addOption(DEBUG);
        options.addOption(QUIET);
        options.addOption(HELP);
    }

    /**
     * A subclass MUST call this method.
     *
     * @exception java.lang.Exception
     *            If command-line parsing fails
     */
    protected final void parse() throws Exception {

        CommandLineParser parser = new PosixParser();
        //this.commandLine = parser.parse(this.options, this.args, true);
        this.commandLine = parser.parse(this.options, this.args, false);
        Option[] options = this.commandLine.getOptions();

        StringBuffer b = new StringBuffer();
        for (int i = 0; i < options.length; i++) {
            b.append(options[i].getLongOpt() + " ");
        }
        logger.info("Options processed: " + b.toString());

        if (this.commandLine.hasOption(DEBUG.getOpt())) {
            this.debug = true;
            setDebugLogLevel();
            logger.debug("Option debug set");
        } else {
            logger.debug("Option debug not set");
        }
        if (this.commandLine.hasOption(QUIET.getOpt())) {
            this.quiet = true;
            logger.debug("Option quiet set");
        } else {
            logger.debug("Option quiet not set");
        }

        this.validate();
    }

    /**
     * If a subclass adds its own command-line options,
     * this method will most likely be overridden.
     *
     * @exception java.lang.Exception
     *            If validation fails
     */
    protected void validate() throws Exception {

        CommandLine line = this.getCommandLine();

        // help?
        if (line.hasOption(HELP.getOpt())) {
            displayUsage();
            System.exit(0);
        }

        // where is the input file?
        if (line.hasOption(INPUT.getOpt())) {
            String inputPath = line.getOptionValue(INPUT.getOpt()).trim();
            logger.debug("Option infile: " + inputPath);
            this.inputPath = inputPath;
        } else {
            logger.debug("Option infile not set");
        }

        // where is the output file?
        if (line.hasOption(OUTPUT.getOpt())) {
            String outputPath = line.getOptionValue(OUTPUT.getOpt()).trim();
            logger.debug("Option outfile: " + outputPath);
            this.outputPath = outputPath;
        } else {
            logger.debug("Option outfile not set");
        }
    }

    /**
     * A concrete subclass MUST implement this method.
     */
    protected abstract void displayUsage();
}

