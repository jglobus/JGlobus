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
import java.io.FileReader;
import java.io.FileWriter;
import java.sql.Statement;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.saml.SAMLToolsTestCase;

import org.teragrid.ncsa.gridshib.gram.GRAMAuditV1;
import org.teragrid.ncsa.gridshib.gram.GRAMAuditV1Connection;

/**
 * Tests the functionality of class
 * <code>GRAMAuditRetrievalTool</code>.
 * <p>
 * The basic test strategy is to perform the following
 * sequence of steps:
 * <ol>
 *   <li>Write <code>infile.txt</code></li>
 *   <li>Run <code>GRAMAuditRetrievalTool</code> on
 *   <code>infile.txt</code> and write its output to
 *   <code>outfile.txt</code></li>
 *   <li>Read <code>outfile.txt</code> and check the
 *   results</li>
 * </ol>
 * Repeat this sequence of steps for various initial
 * conditions.
 *
 * @since 0.5.5
 */
public class GRAMAuditRetrievalToolTest extends SAMLToolsTestCase {

    private static final Class CLASS = GRAMAuditRetrievalToolTest.class;
    private static final String CLASSNAME = CLASS.getName();

    private static Log logger = LogFactory.getLog(CLASSNAME);

    private static String[] args = new String[]{};

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CLASS);
        GRAMAuditRetrievalToolTest.args = args;
    }

    private GRAMAuditV1Connection connection;
    private Statement statement;

    private String jobGridId;
    private String subjectName;
    private String username;
    private Timestamp creationTime;
    private String globusToolkitVersion;
    private String resourceManagerType;
    private String jobDescription;
    private String successFlag;
    private String finishedFlag;

    private File inFile;
    private File outFile;

    public GRAMAuditRetrievalToolTest(String name) {
        super(name);
    }

    /**
     * @see TestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();

        Timestamp now = new Timestamp(new Date().getTime());
        // format timestamp as a date-time string to the nearest second:
        String creationTimeStr = GRAMAuditV1.format(now);

        this.jobGridId =
            "https://localhost:8443/wsrf/services/ManagedExecutableJobService?001";
        this.subjectName =
            "C=US/O=National Center for Supercomputing Applications/CN=Gisolve Community User";
        this.username = "gisolve";
        this.creationTime = GRAMAuditV1.parse(creationTimeStr);
        this.globusToolkitVersion = "4.0.9";
        this.resourceManagerType = "Fork";
        this.jobDescription = "an XML job description goes here";
        this.successFlag = "1";
        this.finishedFlag = "1";

        this.connection = new GRAMAuditV1Connection();
        this.statement = this.connection.getStatement();

        String sql =
            "INSERT INTO gram_audit_table (" +
                "job_grid_id, " +
                "subject_name, " +
                "username, " +
                "creation_time, " +
                "globus_toolkit_version, " +
                "resource_manager_type, " +
                "job_description, " +
                "success_flag, " +
                "finished_flag" +
            ") VALUES (" +
                "'" + this.jobGridId + "', " +
                "'" + this.subjectName + "', " +
                "'" + this.username + "', " +
                "'" + creationTimeStr + "', " +
                "'" + this.globusToolkitVersion + "', " +
                "'" + this.resourceManagerType + "', " +
                "'" + this.jobDescription + "', " +
                "'" + this.successFlag + "', " +
                "'" + this.finishedFlag + "'" +
            ")";

        // insert a row into the GRAM audit table:
        logger.debug("Issuing SQL statement: " + sql);
        int n = this.statement.executeUpdate(sql);
        assertTrue("Inserted one row, but database reports " + n, n == 1);

        this.inFile = null;
        this.outFile = null;
    }

    /**
     * @see TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        super.tearDown();

        String sql =
            "DELETE FROM gram_audit_table " +
                "WHERE job_grid_id='" + this.jobGridId + "'";

        // delete the row from the GRAM audit table:
        logger.debug("Issuing SQL statement: " + sql);
        int n = this.statement.executeUpdate(sql);
        assertTrue("Deleted one row, but database reports " + n, n == 1);

        this.statement.close();
        this.connection.close();
    }

    /**
     * Test a standard GRAM Audit V1 deployment.
     * Assume the GRAM audit table has no
     * <code>gateway_user</code> column (if there
     * is one, ignore it entirely).
     * <p>
     * There are four subcases, with and without a
     * null <code>queued_time</code> column and with
     * and without UTC input date format.
     */
    public void testNullGatewayUser() throws Exception {

        testGatewayUser(null);
    }

    /**
     * Test an extended GRAM Audit V1 deployment,
     * that is, a GRAM audit table with a
     * <code>gateway_user</code> column.
     * <p>
     * There are four subcases, with and without a
     * null <code>queued_time</code> column and with
     * and without UTC input date format.
     */
    public void testNonNullGatewayUser() throws Exception {

        int n;
        String sql;

        boolean hasGatewayUserColumn = this.connection.hasGatewayUserColumn();

        // alter the GRAM audit table, if necessary:
        if (!hasGatewayUserColumn) {
            sql = "ALTER TABLE gram_audit_table " +
                    "ADD COLUMN gateway_user VARCHAR(256)";

            logger.debug("Issuing SQL statement: " + sql);
            n = this.statement.executeUpdate(sql);
            assertTrue("Affected zero rows, but database reports " + n,
                       n == 0);
        }

        String gatewayUser = "user@gisolve.teragrid.org";
        sql = "UPDATE gram_audit_table " +
                "SET gateway_user='" + gatewayUser + "' " +
                "WHERE job_grid_id='" + this.jobGridId + "'";

        // update the GRAM audit table with the gateway_user:
        logger.debug("Issuing SQL statement: " + sql);
        n = this.statement.executeUpdate(sql);
        assertTrue("Updated one row, but database reports " + n, n == 1);

        testGatewayUser(gatewayUser);

        // return the GRAM audit table to its original state:
        if (!hasGatewayUserColumn) {
            sql = "ALTER TABLE gram_audit_table " +
                    "DROP COLUMN gateway_user";

            logger.debug("Issuing SQL statement: " + sql);
            n = this.statement.executeUpdate(sql);
            assertTrue("Affected zero rows, but database reports " + n,
                       n == 0);
        }
    }

    private void testGatewayUser(String gatewayUser) throws Exception {

        int n;
        String sql;
        String lineout;
        BufferedWriter out;

        this.inFile = File.createTempFile("infile", null);
        this.outFile = File.createTempFile("outfile", null);

        // compute a local job id:
        String localJobId = "00000001";
        sql = "UPDATE gram_audit_table " +
                "SET local_job_id='" + localJobId + "' " +
                "WHERE job_grid_id='" + this.jobGridId + "'";

        // update the GRAM audit table:
        logger.debug("Issuing SQL statement: " + sql);
        n = this.statement.executeUpdate(sql);
        assertTrue("Updated one row, but database reports " + n, n == 1);

        // compute a line of output using local time:
        lineout = "1 " + localJobId + " " + formatLocalTime(this.creationTime);
        logger.debug("Expected input line: " + lineout);

        out = new BufferedWriter(new FileWriter(this.inFile));
        out.write(lineout);
        out.newLine();
        out.flush();
        out.close();

        this.runGRAMAuditRetrievalTool(gatewayUser);

        // compute a line of output using UTC:
        lineout = "1 " + localJobId + " " + formatUTC(this.creationTime);
        logger.debug("Expected input line: " + lineout);

        out = new BufferedWriter(new FileWriter(this.inFile));
        out.write(lineout);
        out.newLine();
        out.flush();
        out.close();

        this.runGRAMAuditRetrievalTool(gatewayUser);

        // compute a queued_time value:
        int hour = 60*60*1000;  // millis
        Timestamp later = new Timestamp(this.creationTime.getTime() + hour);
        // format timestamp as a date-time string to the nearest second:
        String queuedTimeStr = GRAMAuditV1.format(later);
        Timestamp queuedTime = GRAMAuditV1.parse(queuedTimeStr);

        sql = "UPDATE gram_audit_table " +
                "SET queued_time='" + queuedTimeStr + "' " +
                "WHERE job_grid_id='" + this.jobGridId + "'";

        // update the GRAM audit table:
        logger.debug("Issuing SQL statement: " + sql);
        n = this.statement.executeUpdate(sql);
        assertTrue("Updated one row, but database reports " + n, n == 1);

        // compute a new line of output using local time:
        lineout = "1 " + localJobId + " " + formatLocalTime(queuedTime);
        logger.debug("Expected input line: " + lineout);

        out = new BufferedWriter(new FileWriter(this.inFile));
        out.write(lineout);
        out.newLine();
        out.flush();
        out.close();

        this.runGRAMAuditRetrievalTool(gatewayUser);

        // compute a new line of output using UTC:
        lineout = "1 " + localJobId + " " + formatUTC(queuedTime);
        logger.debug("Expected input line: " + lineout);

        out = new BufferedWriter(new FileWriter(this.inFile));
        out.write(lineout);
        out.newLine();
        out.flush();
        out.close();

        this.runGRAMAuditRetrievalTool(gatewayUser);
    }

    private void runGRAMAuditRetrievalTool(String gatewayUser)
                                    throws Exception {

        String[] args =
            new String[]{"--debug",
                         "--maxDelta", "0",
                         "--infile", this.inFile.getPath(),
                         "--outfile", this.outFile.getPath()};
        GRAMAuditRetrievalTool cli = new GRAMAuditRetrievalTool(args);
        cli.run();

        String line = "1 " +
                      GRAMAuditV1.getAttributeName("job_grid_id") + " " +
                      this.jobGridId;
        logger.debug("Expected output line #1: " + line);

        BufferedReader in = new BufferedReader(new FileReader(this.outFile));
        String linein = in.readLine();
        assertTrue("Unexpected input: " + linein, line.equals(linein));
        if (gatewayUser == null) {
            linein = in.readLine();
            assertTrue("Expected null input, found: " + linein, linein == null);
        } else {
            line = "1 " +
                   GRAMAuditV1.getAttributeName("gateway_user") + " " +
                   gatewayUser;
            logger.debug("Expected output line #2: " + line);
            linein = in.readLine();
            assertTrue("Unexpected input: " + linein, line.equals(linein));
            linein = in.readLine();
            assertTrue("Expected null input, found: " + linein, linein == null);
        }
        in.close();
    }

    private static String formatLocalTime(Timestamp timestamp) {

        String pattern = "yyyy-MM-dd'T'HH:mm:ssZ";
        SimpleDateFormat formatter = new SimpleDateFormat(pattern);
        formatter.setTimeZone(TimeZone.getDefault());
        return formatter.format(new Date(timestamp.getTime()));
    }

    private static String formatUTC(Timestamp timestamp) {

        String pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'";
        SimpleDateFormat formatter = new SimpleDateFormat(pattern);
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
        return formatter.format(new Date(timestamp.getTime()));
    }
}
