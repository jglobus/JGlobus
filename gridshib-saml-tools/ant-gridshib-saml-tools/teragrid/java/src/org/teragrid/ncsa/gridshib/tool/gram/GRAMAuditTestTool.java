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

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Writer;
import java.sql.Statement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.cli.ApplicationRuntimeException;

import org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException;
import org.teragrid.ncsa.gridshib.gram.GRAMAuditV1;
import org.teragrid.ncsa.gridshib.gram.GRAMAuditV1Connection;

/**
 * Tests a connection to the GRAM audit database.  This
 * should be the first application you run after configuring
 * the GRAM Audit Tools for connectivity with a GRAM audit
 * database.
 * <p>
 * For convenience, the output of this test application is
 * precisely the input of <code>GRAMAuditRetrievalTool</code>.
 * The two applications may be fitted together into a pipe.
 *
 * @since 0.5.5
 *
 * @see org.teragrid.ncsa.gridshib.tool.gram.TestToolCLI
 *
 */
public class GRAMAuditTestTool extends TestToolCLI {

    private static Log logger =
        LogFactory.getLog(GRAMAuditTestTool.class.getName());

    private Writer out;
    private GRAMAuditV1Connection connection;

    public GRAMAuditTestTool(String[] args) {

        super(args);

        this.out = null;
        this.connection = null;
    }

    public static void main(String[] args) {

        GRAMAuditTestTool cli = new GRAMAuditTestTool(args);

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

        logger.info("Begin execution of GRAMAuditTestTool");

        try {
            this.connection = new GRAMAuditV1Connection(this.getConfigFile());
        } catch (GRAMAuditSQLException e) {
            this.setExitCode(e.getErrorCode());
            String msg = "Unable to get database connection";
            throw new ApplicationRuntimeException(msg, e);
        }

        try {
            this.runTest();
        } catch (SQLException e) {
            this.setExitCode(e.getErrorCode());
            String msg = "Test run failed";
            throw new ApplicationRuntimeException(msg, e);
        }

        try {
            this.connection.close();
        } catch (GRAMAuditSQLException e) {
            logger.warn("Unable to close database connection: " +
                        e.getMessage());
        }

        this.setExitCode(SUCCESS_CODE);

        logger.info("End execution of GRAMAuditTestTool");
    }

    private void runTest() throws SQLException,
                                  ApplicationRuntimeException {

        this.out = new PrintWriter(System.out);

        Statement statement;
        try {
            statement = this.connection.getStatement();
        } catch (GRAMAuditSQLException e) {
            this.setExitCode(e.getErrorCode());
            String msg = "Unable to get statement";
            throw new ApplicationRuntimeException(msg, e);
        }

        ResultSet result = statement.executeQuery(this.getDynamicSQL());

        this.printTestResults(result);

        try {
            result.close();
        } catch (SQLException e) {
            logger.warn("Unable to close result set: " + e.getMessage());
        }

        try {
            statement.close();
        } catch (SQLException e) {
            logger.warn("Unable to close prepared statement: " +
                        e.getMessage());
        }

        try {
            this.out.close();
        } catch (IOException e) {
            logger.warn("Unable to close output stream: " +
                        e.getMessage());
        }
    }

    private String getDynamicSQL() {

        String sql =
            "SELECT local_job_id, creation_time, queued_time " +
                "FROM gram_audit_table ";

        // constrain the result set:
        long t = (new Date()).getTime();  // NOW
        long d = this.getMaxDeltaMillis();
        String tsMin = (new Timestamp(t - d)).toString();
        if (this.connection.isPostgreSQL()) {
            sql += "WHERE creation_time " +
                   "> TIMESTAMP '" + tsMin + "' ";
        } else {
            sql += "WHERE CAST(creation_time AS TIMESTAMP) " +
                   "> '" + tsMin + "'";
        }
        logger.info("Computed dynamic SQL: " + sql);

        return sql;
    }

    private void printTestResults(ResultSet result)
                           throws SQLException,
                                  ApplicationRuntimeException {

        String lineOut;
        PrintWriter out = (PrintWriter)this.out;

        boolean moreResults = result.next();
        if (!moreResults) {
            logger.debug("No test results found");
            if (!this.wantQuiet()) {
                lineOut = "Found no test results within range";
                out.println(lineOut);
            }
            return;
        }
        logger.debug("Test result(s) found");

        int i = 0;
        int j = 0;
        String localJobId;
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

            localJobId = GRAMAuditV1.getLocalJobId(result);
            if (localJobId != null) {
                logger.debug("Column local_job_id is not NULL");
                lineOut = (++j) + " " + localJobId + " " + this.format(timestamp);
                out.println(lineOut);
            } else {
                logger.debug("Column local_job_id is NULL");
            }

            logger.debug("End processing result " + i);
            moreResults = result.next();
        }

        if (!this.wantQuiet()) {
            lineOut = "Found " + j + " of " + i + " results within range";
            out.println(lineOut);
        }
    }
}
