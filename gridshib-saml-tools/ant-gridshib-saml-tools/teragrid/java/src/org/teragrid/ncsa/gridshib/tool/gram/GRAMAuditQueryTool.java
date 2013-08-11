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
import java.sql.ResultSetMetaData;
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
 * The <code>GRAMAuditQueryTool</code> is basically two tools
 * rolled into one:
 * <ol>
 *   <li>Given a <code>job_grid_id</code>, query the GRAM
 *   audit table for all column values in that particular
 *   row and print the result to stdout</li>
 *   <li>Given a time interval (in hours), query the GRAM
 *   audit table for all rows within that interval and
 *   print the result to stdout</li>
 * </ol>
 * The command-line interface for the
 * <code>GRAMAuditQueryTool</code> is similar to the
 * <code>GRAMAuditTestTool</code> with the addition of
 * the <code>--GJID</code> option.
 *
 * @since 0.5.5
 *
 * @see org.teragrid.ncsa.gridshib.tool.gram.QueryToolCLI
 *
 */
public class GRAMAuditQueryTool extends QueryToolCLI {

    private static Log logger =
        LogFactory.getLog(GRAMAuditQueryTool.class.getName());

    private Writer out;
    private GRAMAuditV1Connection connection;
    private boolean hasGatewayUser;

    public GRAMAuditQueryTool(String[] args) {

        super(args);

        this.out = null;
        this.connection = null;
    }

    public static void main(String[] args) {

        GRAMAuditQueryTool cli = new GRAMAuditQueryTool(args);

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

        logger.info("Begin execution of GRAMAuditQueryTool");

        try {
            this.connection = new GRAMAuditV1Connection(this.getConfigFile());
            this.hasGatewayUser = this.connection.hasGatewayUserColumn();
        } catch (GRAMAuditSQLException e) {
            this.setExitCode(e.getErrorCode());
            String msg = "Unable to get database connection";
            throw new ApplicationRuntimeException(msg, e);
        }

        try {
            this.runQuery();
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

        logger.info("End execution of GRAMAuditQueryTool");
    }

    private void runQuery() throws SQLException,
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

        if (this.getEPR() != null) {
            this.printQueryResult(result);
        } else {
            this.printQueryResults(result);
        }

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

    private String getDynamicSQL() throws ApplicationRuntimeException {

        String sql =
            "SELECT" +
            " job_grid_id," +
            " local_job_id," +
            " subject_name," +
            " username," +
            " idempotence_id," +
            " creation_time," +
            " queued_time," +
            " stage_in_grid_id," +
            " stage_out_grid_id," +
            " clean_up_grid_id," +
            " globus_toolkit_version," +
            " resource_manager_type," +
            " job_description," +
            " success_flag," +
            " finished_flag" +
            ((this.hasGatewayUser) ? ", gateway_user " : " ") +
            "FROM gram_audit_table ";

        if (this.getEPR() != null) {
            sql += "WHERE job_grid_id='" + this.getEPR() + "'";
        } else {
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
        }
        logger.info("Computed dynamic SQL: " + sql);

        return sql;
    }

    private void printQueryResult(ResultSet result)
                           throws SQLException,
                                  ApplicationRuntimeException {

        String lineOut;
        PrintWriter out = (PrintWriter)this.out;

        boolean moreResults = result.next();
        if (!moreResults) {
            logger.debug("No query result found for EPR " + this.getEPR());
            if (!this.wantQuiet()) {
                lineOut = "Found no record with GJID " + this.getEPR();
                out.println(lineOut);
            }
            return;
        }
        logger.debug("Query result(s) found");

        lineOut = GRAMAuditV1.getAttributeName("job_grid_id") +
                  " " +
                  GRAMAuditV1.getJobGridId(result);
        logger.debug("Output line: " + lineOut);
        out.println(lineOut);

        String localJobId = GRAMAuditV1.getLocalJobId(result);
        lineOut = GRAMAuditV1.getAttributeName("local_job_id") +
                  ((localJobId == null) ? "" : " " + localJobId);
        logger.debug("Output line: " + lineOut);
        out.println(lineOut);

        lineOut = GRAMAuditV1.getAttributeName("subject_name") +
                  " " +
                  GRAMAuditV1.getSubjectName(result);
        logger.debug("Output line: " + lineOut);
        out.println(lineOut);

        lineOut = GRAMAuditV1.getAttributeName("username") +
                  " " +
                  GRAMAuditV1.getUsername(result);
        logger.debug("Output line: " + lineOut);
        out.println(lineOut);

        String idempotenceId = GRAMAuditV1.getIdempotenceId(result);
        lineOut = GRAMAuditV1.getAttributeName("idempotence_id") +
                  ((idempotenceId == null) ? "" : " " + idempotenceId);
        logger.debug("Output line: " + lineOut);
        out.println(lineOut);

        lineOut = GRAMAuditV1.getAttributeName("creation_time") +
                  " " +
                  this.format(this.connection.getCreationTime(result));
        logger.debug("Output line: " + lineOut);
        out.println(lineOut);

        Timestamp timestamp = this.connection.getQueuedTime(result);
        lineOut = GRAMAuditV1.getAttributeName("queued_time") +
                  ((timestamp == null) ? "" : " " + this.format(timestamp));
        logger.debug("Output line: " + lineOut);
        out.println(lineOut);

        String stageInGridId = GRAMAuditV1.getStageInGridId(result);
        lineOut = GRAMAuditV1.getAttributeName("stage_in_grid_id") +
                  ((stageInGridId == null) ? "" : " " + stageInGridId);
        logger.debug("Output line: " + lineOut);
        out.println(lineOut);

        String stageOutGridId = GRAMAuditV1.getStageOutGridId(result);
        lineOut = GRAMAuditV1.getAttributeName("stage_out_grid_id") +
                  ((stageOutGridId == null) ? "" : " " + stageOutGridId);
        logger.debug("Output line: " + lineOut);
        out.println(lineOut);

        String cleanUpGridId = GRAMAuditV1.getCleanUpGridId(result);
        lineOut = GRAMAuditV1.getAttributeName("clean_up_grid_id") +
                  ((cleanUpGridId == null) ? "" : " " + cleanUpGridId);
        logger.debug("Output line: " + lineOut);
        out.println(lineOut);

        lineOut = GRAMAuditV1.getAttributeName("globus_toolkit_version") +
                  " " +
                  GRAMAuditV1.getGlobusToolkitVersion(result);
        logger.debug("Output line: " + lineOut);
        out.println(lineOut);

        lineOut = GRAMAuditV1.getAttributeName("resource_manager_type") +
                  " " +
                  GRAMAuditV1.getResourceManagerType(result);
        logger.debug("Output line: " + lineOut);
        out.println(lineOut);

        String jobDescription = GRAMAuditV1.getJobDescription(result);
        lineOut = GRAMAuditV1.getAttributeName("job_description") +
                  " " +
                  jobDescription.replaceAll("[\n\r\f]", " ");  // a hack
        logger.debug("Output line: " + lineOut);
        out.println(lineOut);

        lineOut = GRAMAuditV1.getAttributeName("success_flag") +
                  " " +
                  GRAMAuditV1.getSuccessFlag(result);
        logger.debug("Output line: " + lineOut);
        out.println(lineOut);

        lineOut = GRAMAuditV1.getAttributeName("finished_flag") +
                  " " +
                  GRAMAuditV1.getFinishedFlag(result);
        logger.debug("Output line: " + lineOut);
        out.println(lineOut);

        if (this.hasGatewayUser) {
            String gatewayUser = GRAMAuditV1.getGatewayUser(result);
            lineOut = GRAMAuditV1.getAttributeName("gateway_user") +
                      ((gatewayUser == null) ? "" : " " + gatewayUser);
            logger.debug("Output line: " + lineOut);
            out.println(lineOut);
        }
    }

    private void printQueryResults(ResultSet result)
                            throws SQLException,
                                   ApplicationRuntimeException {

        String lineOut;
        PrintWriter out = (PrintWriter)this.out;

        boolean moreResults = result.next();
        if (!moreResults) {
            logger.debug("No query results found for maxDelta " +
                         this.getMaxDeltaHours());
            if (!this.wantQuiet()) {
                lineOut = "Found no query results found for maxDelta " +
                          this.getMaxDeltaHours();
                out.println(lineOut);
            }
            return;
        }
        logger.debug("Query result(s) found");

        String colName;
        StringBuffer buf = new StringBuffer();
        ResultSetMetaData metaData = result.getMetaData();

        // compute column headings:
        int i = 1;
        int n = metaData.getColumnCount();
        while (true) {
            colName = metaData.getColumnName(i++);
            buf.append(colName);
            if (i > n) { break; }
            buf.append(", ");
        }

        // print column headings:
        lineOut = buf.toString();
        logger.debug("Output line: " + lineOut);
        out.println(lineOut);

        String colValue;
        Timestamp timestamp;

        // compute and print table rows:
        i = 0;
        while (moreResults) {

            logger.debug("Begin processing result " + (++i));

            buf = new StringBuffer();
            buf.append(GRAMAuditV1.getJobGridId(result));

            buf.append(", ");
            colValue = GRAMAuditV1.getLocalJobId(result);
            buf.append((colValue == null) ? "" : colValue);

            buf.append(", ");
            buf.append(GRAMAuditV1.getSubjectName(result));

            buf.append(", ");
            buf.append(GRAMAuditV1.getUsername(result));

            buf.append(", ");
            colValue = GRAMAuditV1.getIdempotenceId(result);
            buf.append((colValue == null) ? "" : colValue);

            buf.append(", ");
            buf.append(this.format(this.connection.getCreationTime(result)));

            buf.append(", ");
            timestamp = this.connection.getQueuedTime(result);
            buf.append((timestamp == null) ? "" : this.format(timestamp));

            buf.append(", ");
            colValue = GRAMAuditV1.getStageInGridId(result);
            buf.append((colValue == null) ? "" : colValue);

            buf.append(", ");
            colValue = GRAMAuditV1.getStageOutGridId(result);
            buf.append((colValue == null) ? "" : colValue);

            buf.append(", ");
            colValue = GRAMAuditV1.getCleanUpGridId(result);
            buf.append((colValue == null) ? "" : colValue);

            buf.append(", ");
            buf.append(GRAMAuditV1.getGlobusToolkitVersion(result));

            buf.append(", ");
            buf.append(GRAMAuditV1.getResourceManagerType(result));

            buf.append(", ");
            colValue = GRAMAuditV1.getJobDescription(result);
            buf.append(colValue.replaceAll("[\n\r\f]", " "));  // a hack

            buf.append(", ");
            buf.append(GRAMAuditV1.getSuccessFlag(result));

            buf.append(", ");
            buf.append(GRAMAuditV1.getFinishedFlag(result));

            if (this.hasGatewayUser) {
                buf.append(", ");
                colValue = GRAMAuditV1.getGatewayUser(result);
                buf.append((colValue == null) ? "" : colValue);
            }

            lineOut = buf.toString();
            logger.debug("Output line: " + lineOut);
            out.println(lineOut);

            logger.debug("End processing result " + i);
            moreResults = result.next();
        }

        // optionally print summary line:
        if (!this.wantQuiet()) {
            lineOut = "Found " + i + " results within range";
            out.println(lineOut);
        }
    }
}
