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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.Writer;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.text.ParseException;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.cli.ApplicationRuntimeException;

import org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException;
import org.teragrid.ncsa.gridshib.gram.GRAMAuditV1;
import org.teragrid.ncsa.gridshib.gram.GRAMAuditV1Connection;

/**
 * A filter that batch processes an input file and repeatedly
 * queries a GRAM audit database.  Consult the user
 * documentation for details:
 * <blockquote>
 * <a href="http://www.teragridforum.org/mediawiki/index.php?title=GRAM_Audit_Tools">GRAM Audit Tools</a>
 * </blockquote>
 * This application is intended for use by TeraGrid
 * accounting administrators.
 *
 * @since 0.5.5
 *
 * @see org.teragrid.ncsa.gridshib.tool.gram.RetrievalToolCLI
 *
 */
public class GRAMAuditRetrievalTool extends RetrievalToolCLI {

    private static Log logger =
        LogFactory.getLog(GRAMAuditRetrievalTool.class.getName());

    /**
     * An <code>UNQUOTED_FORM</code> is a field that has
     * no embedded whitespace, so it need not be quoted.
     */
    final private static String UNQUOTED_FORM =
        "([^ \\t]+)";

    /**
     * A regular expression used to parse the first
     * field of each line of the input file.  The first
     * field is an <code>UNQUOTED_FORM</code> preceded
     * by arbitrary whitespace.
     */
    final private static String FIRST_FIELD_REGEX =
        "[ \\t]*" + UNQUOTED_FORM;

    /**
     * A regular expression used to parse the next
     * field (starting with the second field) of each
     * line of the input file.  This regular expression
     * is identical to <code>FIRST_FIELD_REGEX</code>
     * except that the next field must be preceded by
     * at least one whitespace character.
     */
    final private static String NEXT_FIELD_REGEX =
        "[ \\t]" + FIRST_FIELD_REGEX;

    /**
     * A regular expression used to parse a complete
     * line of input.  An input line consists of a
     * sequence of three fields, essentially
     * <pre>FIRST_FIELD_REGEX + NEXT_FIELD_REGEX
     *                        + NEXT_FIELD_REGEX</pre>
     * There may be arbitary whitespace at the end of
     * an input line, which is of course ignored.
     */
    final private static String INPUT_LINE_REGEX =
        "^" + FIRST_FIELD_REGEX + NEXT_FIELD_REGEX +
                                  NEXT_FIELD_REGEX + "[ \\t]*$";

    /**
     * The compiled regular expression used to parse
     * <code>INPUT_LINE_REGEX</code>.
     */
    final private static Pattern INPUT_LINE_PATTERN;

    static {

        // compile the regular expression:
        try {
            INPUT_LINE_PATTERN = Pattern.compile(INPUT_LINE_REGEX);
        } catch (PatternSyntaxException e) {
            logger.error("Invalid regex: " + INPUT_LINE_REGEX);
            throw e;
        }
    }

    private Reader in;
    private Writer out;

    private GRAMAuditV1Connection connection;
    private PreparedStatement statement;

    public GRAMAuditRetrievalTool(String[] args) {

        super(args);

        this.in = null;
        this.out = null;

        this.connection = null;
        this.statement = null;
    }

    public static void main(String[] args) {

        GRAMAuditRetrievalTool cli = new GRAMAuditRetrievalTool(args);

        try {
            cli.run();
        } catch (ApplicationRuntimeException e) {
            String msg = " (exit code " + cli.getExitCode() + ")";
            logger.error(e.getMessage() + msg, e);
            if (!cli.wantQuiet()) { System.err.println(e.getMessage()); }
        }

        System.exit(cli.getExitCode());
    }

    public void run() throws ApplicationRuntimeException {

        logger.info("Begin execution of GRAMAuditRetrievalTool");

        try {
            this.connection = new GRAMAuditV1Connection(this.getConfigFile());
        } catch (GRAMAuditSQLException e) {
            this.setExitCode(e.getErrorCode());
            String msg = "Unable to get database connection";
            throw new ApplicationRuntimeException(msg, e);
        }

        try {
            this.runFilter();
        } catch (SQLException e) {
            this.setExitCode(e.getErrorCode());
            String msg = "Application run failed";
            throw new ApplicationRuntimeException(msg, e);
        }

        try {
            this.connection.close();
        } catch (GRAMAuditSQLException e) {
            logger.warn("Unable to close database connection: " +
                        e.getMessage());
        }

        this.setExitCode(SUCCESS_CODE);

        logger.info("End execution of GRAMAuditRetrievalTool");
    }

    private void runFilter() throws SQLException,
                                    ApplicationRuntimeException {

        // input source:
        if (this.getInputPath() == null) {
            logger.debug("Processing infile as stdin");
            this.in = new BufferedReader(new InputStreamReader(System.in));
        } else {
            logger.debug("Processing infile " + this.getInputPath());
            File infile = new File(this.getInputPath());
            try {
                this.in = new BufferedReader(new FileReader(infile));
            } catch (FileNotFoundException e) {
                this.setExitCode(APPLICATION_ERROR);
                String msg = "Unable to locate input file";
                throw new ApplicationRuntimeException(msg, e);
            }
        }

        // output sink:
        if (this.getOutputPath() == null) {
            logger.debug("Processing outfile as stdout");
            this.out = new BufferedWriter(new OutputStreamWriter(System.out));
        } else {
            logger.debug("Processing outfile " + this.getOutputPath());
            File outfile = new File(this.getOutputPath());
            try {
                this.out = new BufferedWriter(new FileWriter(outfile));
            } catch (IOException e) {
                this.setExitCode(APPLICATION_ERROR);
                String msg = "Unable to open output file";
                throw new ApplicationRuntimeException(msg, e);
            }
        }

        // compute dynamic SQL string:
        boolean hasGatewayUser = this.connection.hasGatewayUserColumn();
        String sql =
            "SELECT job_grid_id, creation_time, queued_time" +
                ((hasGatewayUser) ? ", gateway_user " : " ") +
                "FROM gram_audit_table " +
                "WHERE local_job_id = ?";

        try {
            this.statement =
                this.connection.getPreparedStatement(sql);
        } catch (GRAMAuditSQLException e) {
            this.setExitCode(e.getErrorCode());
            String msg = "Unable to get prepared statement";
            throw new ApplicationRuntimeException(msg, e);
        }

        String line;
        Matcher matcher;
        try {
            while((line = ((BufferedReader)this.in).readLine()) != null) {

                logger.debug("Input line: " + line);

                matcher = INPUT_LINE_PATTERN.matcher(line);
                if (!matcher.find()) {
                    this.setExitCode(APPLICATION_ERROR);
                    String msg = "Unable to parse input: " + line;
                    throw new ApplicationRuntimeException(msg);
                }

                // match and process three input fields:
                this.processInputLine(matcher.group(1),
                                      matcher.group(2),
                                      matcher.group(3));
            }
        } catch (IOException e) {
                this.setExitCode(APPLICATION_ERROR);
                String msg = "Unable to read from input stream";
                throw new ApplicationRuntimeException(msg, e);
        }

        try {
            this.statement.close();
        } catch (SQLException e) {
            logger.warn("Unable to close prepared statement: " +
                        e.getMessage());
        }

        try {
            this.in.close();
        } catch (IOException e) {
            logger.warn("Unable to close input stream: " +
                        e.getMessage());
        }

        try {
            this.out.close();
        } catch (IOException e) {
            logger.warn("Unable to close output stream: " +
                        e.getMessage());
        }
    }

    private void processInputLine(String id,
                                  String localJobId,
                                  String dateTime)
                           throws SQLException,
                                  ApplicationRuntimeException {

        logger.debug("Processing input line: " + id + " " +
                     localJobId + " " + dateTime);

        this.statement.clearParameters();
        this.statement.setString(1, localJobId);
        ResultSet result = this.statement.executeQuery();

        boolean moreResults = result.next();
        if (!moreResults) {
            logger.warn("No results for local_job_id " + localJobId);
            return;
        }
        logger.info("Result(s) found for local_job_id " + localJobId);

        Date date;
        try {
            date = this.parse(dateTime);
        } catch (ParseException e) {
            this.setExitCode(APPLICATION_ERROR);
            String msg = "Unable to parse dateTime string " + dateTime;
            throw new ApplicationRuntimeException(msg, e);
        }
        logger.debug("Converted dateTime: " + date.toString());

        int i = 0;
        long diff;
        long deltaMax = this.getMaxDeltaMillis();
        long delta = deltaMax;
        String jobGridId = null;
        String gatewayUser = null;
        while (moreResults) {

            logger.debug("Begin processing result " + (++i));

            Timestamp timestamp = this.connection.getQueuedTime(result);
            if (timestamp == null) {
                timestamp = this.connection.getCreationTime(result);
                assert (timestamp != null);
                logger.debug("Using creation_time: " + this.format(timestamp));
            } else {
                logger.debug("Using queued_time: " + this.format(timestamp));
            }
            diff = Math.abs(date.getTime() - timestamp.getTime());

            if (diff > delta) {
                logger.warn("Discarding out-of-range result: " +
                            this.format(timestamp));
            } else {
                logger.debug("Result is within range: " +
                             this.format(timestamp));
                delta = diff;
                jobGridId = GRAMAuditV1.getJobGridId(result);
                gatewayUser = this.connection.getGatewayUser(result);
            }

            logger.debug("End processing result " + i);
            moreResults = result.next();
        }

        if (jobGridId == null) {
            logger.warn("No results within range for local_job_id " +
                        localJobId);
            return;
        }
        logger.info("Result(s) within range found for local_job_id " +
                    localJobId);

        try {
            String lineOut =
                id + " " +
                GRAMAuditV1.getAttributeName("job_grid_id") + " " +
                jobGridId;
            logger.debug("Writing output line 1: " + lineOut);
            ((BufferedWriter)this.out).write(lineOut);
            ((BufferedWriter)this.out).newLine();

            if (gatewayUser != null) {
                logger.info("Writing 2 output lines for local_job_id " +
                            localJobId);
                lineOut =
                    id + " " +
                    GRAMAuditV1.getAttributeName("gateway_user") + " " +
                    gatewayUser;
                logger.debug("Writing output line 2: " + lineOut);
                ((BufferedWriter)this.out).write(lineOut);
                ((BufferedWriter)this.out).newLine();
            } else {
                logger.info("Writing 1 output line for local_job_id " +
                            localJobId);
            }
            ((BufferedWriter)this.out).flush();
        } catch (IOException e) {
            logger.error("Unable to write output for local_job_id: " +
                         localJobId, e);
        }

        try {
            result.close();
        } catch (SQLException e) {
            logger.warn("Unable to close result set: " + e.getMessage());
        }
    }

    private Date parse(String dateTime) throws ParseException {

        try {
            return this.getFirstDateFormat().parse(dateTime);
        } catch (ParseException e) {
            Date date = this.getSecondDateFormat().parse(dateTime);
            this.reverseDateFormats();  // an optimization
            return date;
        }
    }
}
