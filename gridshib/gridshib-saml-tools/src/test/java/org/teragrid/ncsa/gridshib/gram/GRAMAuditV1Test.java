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

package org.teragrid.ncsa.gridshib.gram;

import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.saml.SAMLToolsTestCase;

import org.teragrid.ncsa.gridshib.gram.GRAMAuditV1;
import org.teragrid.ncsa.gridshib.gram.GRAMAuditV1Connection;

/**
 * Tests the various static methods of class
 * <code>GRAMAuditV1</code>.
 *
 * @since 0.5.5
 */
public class GRAMAuditV1Test extends SAMLToolsTestCase {

    private static final Class CLASS = GRAMAuditV1Test.class;
    private static final String CLASSNAME = CLASS.getName();

    private static Log logger = LogFactory.getLog(CLASSNAME);

    private static String[] args = new String[]{};

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CLASS);
        GRAMAuditV1Test.args = args;
    }

    private GRAMAuditV1Connection connection;
    private Statement statement;
    private boolean isPostgreSQL;

    private String jobGridId;
    private String subjectName;
    private String username;
    private Timestamp creationTime;
    private String globusToolkitVersion;
    private String resourceManagerType;
    private String jobDescription;
    private String successFlag;
    private String finishedFlag;

    public GRAMAuditV1Test(String name) {
        super(name);
    }

    /**
     * @see TestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();

        Timestamp now = new Timestamp(new Date().getTime());
        // format as a date-time string to the nearest second:
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
        this.isPostgreSQL = this.connection.isPostgreSQL();

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

    public void testGetJobGridIdMethod() throws Exception {

        String sql =
            "SELECT job_grid_id " +
                "FROM gram_audit_table " +
                "WHERE job_grid_id='" + this.jobGridId + "'";

        // issue the SQL query and check the result:
        logger.debug("Issuing SQL statement: " + sql);
        ResultSet result = this.statement.executeQuery(sql);
        if (!result.next()) {
            fail("No results found for query: " + sql);
        }

        // recover the original column value:
        String jobGridId = GRAMAuditV1.getJobGridId(result);
        result.close();

        logger.debug("Retrieved job grid id: " + jobGridId);
        assertTrue("Unable to retrieve original job grid id",
                   this.jobGridId.equals(jobGridId));
    }

    public void testGetLocalJobIdMethod() throws Exception {

        String sql =
            "SELECT local_job_id " +
                "FROM gram_audit_table " +
                "WHERE job_grid_id='" + this.jobGridId + "'";

        // issue the SQL query and check the result:
        logger.debug("Issuing SQL statement: " + sql);
        ResultSet result = this.statement.executeQuery(sql);
        if (!result.next()) {
            fail("No results found for query: " + sql);
        }

        // recover the original column value:
        String localJobId = GRAMAuditV1.getLocalJobId(result);
        result.close();

        assertTrue("Expected null local job id but found: " + localJobId,
                   localJobId == null);

        // compute a local job id:
        String localJobId1 = "00000001";
        String sql2 = "UPDATE gram_audit_table " +
                        "SET local_job_id='" + localJobId1 + "' " +
                        "WHERE job_grid_id='" + this.jobGridId + "'";

        // update the GRAM audit table:
        logger.debug("Issuing SQL statement: " + sql2);
        int n = this.statement.executeUpdate(sql2);
        assertTrue("Updated one row, but database reports " + n, n == 1);

        // re-issue the original SQL query and check the result:
        logger.debug("Issuing SQL statement: " + sql);
        result = this.statement.executeQuery(sql);
        if (!result.next()) {
            fail("No results found for query: " + sql);
        }

        // recover the original column value:
        String localJobId2 = GRAMAuditV1.getLocalJobId(result);
        result.close();

        logger.debug("Retrieved local job id: " + localJobId2);
        assertTrue("Unable to retrieve original local job id",
                   localJobId1.equals(localJobId2));
    }

    public void testGetSubjectNameMethod() throws Exception {

        String sql =
            "SELECT subject_name " +
                "FROM gram_audit_table " +
                "WHERE job_grid_id='" + this.jobGridId + "'";

        // issue the SQL query and check the result:
        logger.debug("Issuing SQL statement: " + sql);
        ResultSet result = this.statement.executeQuery(sql);
        if (!result.next()) {
            fail("No results found for query: " + sql);
        }

        // recover the original column value:
        String subjectName = GRAMAuditV1.getSubjectName(result);
        result.close();

        logger.debug("Retrieved subject name: " + subjectName);
        assertTrue("Unable to retrieve original subject name",
                   this.subjectName.equals(subjectName));
    }

    public void testGetUsernameMethod() throws Exception {

        String sql =
            "SELECT username " +
                "FROM gram_audit_table " +
                "WHERE job_grid_id='" + this.jobGridId + "'";

        // issue the SQL query and check the result:
        logger.debug("Issuing SQL statement: " + sql);
        ResultSet result = this.statement.executeQuery(sql);
        if (!result.next()) {
            fail("No results found for query: " + sql);
        }

        // recover the original column value:
        String username = GRAMAuditV1.getUsername(result);
        result.close();

        logger.debug("Retrieved username: " + username);
        assertTrue("Unable to retrieve original username",
                   this.username.equals(username));
    }

    //public void testGetIdempotenceIdMethod() throws Exception;

    public void testGetCreationTimeMethod() throws Exception {

        String sql =
            "SELECT creation_time " +
                "FROM gram_audit_table " +
                "WHERE job_grid_id='" + this.jobGridId + "'";

        // issue the SQL query and check the result:
        logger.debug("Issuing SQL statement: " + sql);
        ResultSet result = this.statement.executeQuery(sql);
        if (!result.next()) {
            fail("No results found for query: " + sql);
        }

        // recover the original column value:
        Timestamp creationTime =
            GRAMAuditV1.getCreationTime(result, this.isPostgreSQL);
        result.close();

        logger.debug("Retrieved creation time: " + creationTime);
        assertTrue("Unable to retrieve original creation time",
                   this.creationTime.equals(creationTime));
    }

    public void testGetQueuedTimeMethod() throws Exception {

        String sql =
            "SELECT queued_time " +
                "FROM gram_audit_table " +
                "WHERE job_grid_id='" + this.jobGridId + "'";

        // issue the SQL query and check the result:
        logger.debug("Issuing SQL statement: " + sql);
        ResultSet result = this.statement.executeQuery(sql);
        if (!result.next()) {
            fail("No results found for query: " + sql);
        }

        // recover the original column value:
        Timestamp queuedTime =
            GRAMAuditV1.getQueuedTime(result, this.isPostgreSQL);
        result.close();

        assertTrue("Expected null queued time but found: " + queuedTime,
                   queuedTime == null);

        // compute a queued_time value:
        int hour = 60*60*1000;  // millis
        Timestamp later = new Timestamp(this.creationTime.getTime() + hour);
        // format timestamp as a date-time string to the nearest second:
        String queuedTimeStr = GRAMAuditV1.format(later);
        Timestamp queuedTime1 = GRAMAuditV1.parse(queuedTimeStr);

        String sql2 = "UPDATE gram_audit_table " +
                        "SET queued_time='" + queuedTimeStr + "' " +
                        "WHERE job_grid_id='" + this.jobGridId + "'";

        // update the GRAM audit table:
        logger.debug("Issuing SQL statement: " + sql2);
        int n = this.statement.executeUpdate(sql2);
        assertTrue("Updated one row, but database reports " + n, n == 1);

        // re-issue the original SQL query and check the result:
        logger.debug("Issuing SQL statement: " + sql);
        result = this.statement.executeQuery(sql);
        if (!result.next()) {
            fail("No results found for query: " + sql);
        }

        // recover the original column value:
        Timestamp queuedTime2 =
            GRAMAuditV1.getQueuedTime(result, this.isPostgreSQL);
        result.close();

        logger.debug("Retrieved queued time: " + queuedTime2);
        assertTrue("Unable to retrieve original queued time",
                   queuedTime1.equals(queuedTime2));
    }

    //public void testGetStageInGridIdMethod() throws Exception;

    //public void testGetStageOutGridIdMethod() throws Exception;

    //public void testGetCleanUpGridIdMethod() throws Exception;

    public void testGetGlobusToolkitVersionMethod() throws Exception {

        String sql =
            "SELECT globus_toolkit_version " +
                "FROM gram_audit_table " +
                "WHERE job_grid_id='" + this.jobGridId + "'";

        // issue the SQL query and check the result:
        logger.debug("Issuing SQL statement: " + sql);
        ResultSet result = this.statement.executeQuery(sql);
        if (!result.next()) {
            fail("No results found for query: " + sql);
        }

        // recover the original column value:
        String globusToolkitVersion =
            GRAMAuditV1.getGlobusToolkitVersion(result);
        result.close();

        logger.debug("Retrieved globus toolkit version: " +
                     globusToolkitVersion);
        assertTrue("Unable to retrieve original globus toolkit version",
                   this.globusToolkitVersion.equals(globusToolkitVersion));
    }

    public void testGetResourceManagerTypeMethod() throws Exception {

        String sql =
            "SELECT resource_manager_type " +
                "FROM gram_audit_table " +
                "WHERE job_grid_id='" + this.jobGridId + "'";

        // issue the SQL query and check the result:
        logger.debug("Issuing SQL statement: " + sql);
        ResultSet result = this.statement.executeQuery(sql);
        if (!result.next()) {
            fail("No results found for query: " + sql);
        }

        // recover the original column value:
        String resourceManagerType =
            GRAMAuditV1.getResourceManagerType(result);
        result.close();

        logger.debug("Retrieved resource manager type: " +
                     resourceManagerType);
        assertTrue("Unable to retrieve original resource manager type",
                   this.resourceManagerType.equals(resourceManagerType));
    }

    public void testGetJobDescriptionMethod() throws Exception {

        String sql =
            "SELECT job_description " +
                "FROM gram_audit_table " +
                "WHERE job_grid_id='" + this.jobGridId + "'";

        // issue the SQL query and check the result:
        logger.debug("Issuing SQL statement: " + sql);
        ResultSet result = this.statement.executeQuery(sql);
        if (!result.next()) {
            fail("No results found for query: " + sql);
        }

        // recover the original column value:
        String jobDescription = GRAMAuditV1.getJobDescription(result);
        result.close();

        logger.debug("Retrieved job description: " + jobDescription);
        assertTrue("Unable to retrieve original job description",
                   this.jobDescription.equals(jobDescription));
    }

    public void testGetSuccessFlagMethod() throws Exception {

        String sql =
            "SELECT success_flag " +
                "FROM gram_audit_table " +
                "WHERE job_grid_id='" + this.jobGridId + "'";

        // issue the SQL query and check the result:
        logger.debug("Issuing SQL statement: " + sql);
        ResultSet result = this.statement.executeQuery(sql);
        if (!result.next()) {
            fail("No results found for query: " + sql);
        }

        // recover the original column value:
        String successFlag = GRAMAuditV1.getSuccessFlag(result);
        result.close();

        logger.debug("Retrieved success flag: " + successFlag);
        assertTrue("Unable to retrieve original success flag",
                   this.successFlag.equals(successFlag));
    }

    public void testGetFinishedFlagMethod() throws Exception {

        String sql =
            "SELECT finished_flag " +
                "FROM gram_audit_table " +
                "WHERE job_grid_id='" + this.jobGridId + "'";

        // issue the SQL query and check the result:
        logger.debug("Issuing SQL statement: " + sql);
        ResultSet result = this.statement.executeQuery(sql);
        if (!result.next()) {
            fail("No results found for query: " + sql);
        }

        // recover the original column value:
        String finishedFlag = GRAMAuditV1.getFinishedFlag(result);
        result.close();

        logger.debug("Retrieved finished flag: " + finishedFlag);
        assertTrue("Unable to retrieve original finished flag",
                   this.finishedFlag.equals(finishedFlag));
    }

    public void testGetGatewayUserMethod() throws Exception {

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

        sql = "SELECT gateway_user " +
                "FROM gram_audit_table " +
                "WHERE job_grid_id='" + this.jobGridId + "'";

        // issue the SQL query and check the result:
        logger.debug("Issuing SQL statement: " + sql);
        ResultSet result = this.statement.executeQuery(sql);
        if (!result.next()) {
            fail("No results found for query: " + sql);
        }

        // recover the original column value:
        String gatewayUser = GRAMAuditV1.getGatewayUser(result);
        result.close();

        assertTrue("Expected null gateway user but found: " + gatewayUser,
                   gatewayUser == null);

        String gatewayUser1 = "user@gisolve.teragrid.org";
        String sql2 =
            "UPDATE gram_audit_table " +
                "SET gateway_user='" + gatewayUser1 + "' " +
                "WHERE job_grid_id='" + this.jobGridId + "'";

        // update the GRAM audit table with the gateway_user:
        logger.debug("Issuing SQL statement: " + sql2);
        n = this.statement.executeUpdate(sql2);
        assertTrue("Updated one row, but database reports " + n, n == 1);

        // re-issue the original SQL query and check the result:
        logger.debug("Issuing SQL statement: " + sql);
        result = this.statement.executeQuery(sql);
        if (!result.next()) {
            fail("No results found for query: " + sql);
        }

        // recover the original column value:
        String gatewayUser2 = GRAMAuditV1.getGatewayUser(result);
        result.close();

        logger.debug("Retrieved gateway user identifier: " + gatewayUser2);
        assertTrue("Unable to retrieve original gateway user identifier",
                   gatewayUser2.equals(gatewayUser1));

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
}
