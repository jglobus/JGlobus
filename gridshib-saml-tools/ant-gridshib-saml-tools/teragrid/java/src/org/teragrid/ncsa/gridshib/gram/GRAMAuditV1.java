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
import java.sql.SQLException;
import java.sql.Timestamp;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * This class is a container for various static methods
 * that are useful when querying a
 * <a href="http://dev.globus.org/wiki/GRAM_Audit_V1">GRAM Audit&nbsp;V1</code>
 * database.
 *
 * @since 0.5.5
 *
 * @see org.teragrid.ncsa.gridshib.gram.GRAMAuditV1Connection
 */
public class GRAMAuditV1 {

    private static Log logger =
        LogFactory.getLog(GRAMAuditV1.class.getName());

    private GRAMAuditV1() {}

    final private static java.util.Map GRAMAttributeNames;

    static {
        String stem = "http://globus.org/names/attribute/gram/audit_v1/";
        java.util.Map names = new java.util.HashMap();
        names.put("job_grid_id", stem + "job_grid_id");
        names.put("local_job_id", stem + "local_job_id");
        names.put("subject_name", stem + "subject_name");
        names.put("username", stem + "username");
        names.put("idempotence_id", stem + "idempotence_id");
        names.put("creation_time", stem + "creation_time");
        names.put("queued_time", stem + "queued_time");
        names.put("stage_in_grid_id", stem + "stage_in_grid_id");
        names.put("stage_out_grid_id", stem + "stage_out_grid_id");
        names.put("clean_up_grid_id", stem + "clean_up_grid_id");
        names.put("globus_toolkit_version", stem + "globus_toolkit_version");
        names.put("resource_manager_type", stem + "resource_manager_type");
        names.put("job_description", stem + "job_description");
        names.put("success_flag", stem + "success_flag");
        names.put("finished_flag", stem + "finished_flag");
        names.put("gateway_user", stem + "gateway_user");
        GRAMAttributeNames = new java.util.HashMap(names);
    }

    /**
     * Given the name of a column in the GRAM audit table,
     * get the formal name of the corresponding GRAM
     * attribute, which is a URI.
     * <p>
     * By definition, an <em>attribute</em> is a name-value
     * pair.  The name of a <em>GRAM attribute</em> is a
     * URI (obtained by this method) while the value is
     * presumably a column value from the GRAM audit table.
     *
     * @param colName the name of a column in the
     *                GRAM audit table
     *
     * @return a GRAM attribute name
     */
    public static String getAttributeName(String colName) {

        return (String)GRAMAttributeNames.get(colName);
    }

    /**
     * Get the value of the <code>job_grid_id</code> column
     * from the given SQL result.
     * The <code>job_grid_id</code> is the primary key of
     * the GRAM audit table.
     *
     * @param result the result of a SQL query
     *
     * @return the value of the <code>job_grid_id</code>
     *         column, which is never null
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to get the <code>job_grid_id</code>
     *            from the SQL result set
     */
    public static String getJobGridId(ResultSet result)
                               throws GRAMAuditSQLException {

        String value;
        try {
            value = result.getString("job_grid_id");
        } catch (SQLException e) {
            String msg = "Unable to get job_grid_id column";
            throw new GRAMAuditSQLException(msg, e);
        }
        assert (value != null);
        logger.debug("Obtained job_grid_id: " + value);

        return value;
    }

    /**
     * Get the value of the <code>local_job_id</code> column
     * from the given SQL result.
     *
     * @param result the result of a SQL query
     *
     * @return the value of the <code>local_job_id</code>
     *         column, which may be null
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to get the <code>local_job_id</code>
     *            from the SQL result set
     */
    public static String getLocalJobId(ResultSet result)
                                throws GRAMAuditSQLException {

        String value;
        try {
            value = result.getString("local_job_id");
            if (result.wasNull()) {
                logger.debug("Column local_job_id is null");
                return null;
            }
        } catch (SQLException e) {
            String msg = "Unable to get local_job_id column";
            throw new GRAMAuditSQLException(msg, e);
        }
        assert (value != null);
        logger.debug("Obtained local_job_id: " + value);

        return value;
    }

    /**
     * Get the value of the <code>subject_name</code> column
     * from the given SQL result.
     *
     * @param result the result of a SQL query
     *
     * @return the value of the <code>subject_name</code>
     *         column, which is never null
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to get the <code>subject_name</code>
     *            from the SQL result set
     */
    public static String getSubjectName(ResultSet result)
                                 throws GRAMAuditSQLException {

        String value;
        try {
            value = result.getString("subject_name");
        } catch (SQLException e) {
            String msg = "Unable to get subject_name column";
            throw new GRAMAuditSQLException(msg, e);
        }
        assert (value != null);
        logger.debug("Obtained subject_name: " + value);

        return value;
    }

    /**
     * Get the value of the <code>username</code> column
     * from the given SQL result.
     *
     * @param result the result of a SQL query
     *
     * @return the value of the <code>username</code>
     *         column, which is never null
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to get the <code>username</code>
     *            from the SQL result set
     */
    public static String getUsername(ResultSet result)
                              throws GRAMAuditSQLException {

        String value;
        try {
            value = result.getString("username");
        } catch (SQLException e) {
            String msg = "Unable to get username column";
            throw new GRAMAuditSQLException(msg, e);
        }
        assert (value != null);
        logger.debug("Obtained username: " + value);

        return value;
    }

    /**
     * Get the value of the <code>idempotence_id</code> column
     * from the given SQL result.
     *
     * @param result the result of a SQL query
     *
     * @return the value of the <code>idempotence_id</code>
     *         column, which may be null
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to get the <code>idempotence_id</code>
     *            from the SQL result set
     */
    public static String getIdempotenceId(ResultSet result)
                                   throws GRAMAuditSQLException {

        String value;
        try {
            value = result.getString("idempotence_id");
            if (result.wasNull()) {
                logger.debug("Column idempotence_id is null");
                return null;
            }
        } catch (SQLException e) {
            String msg = "Unable to get idempotence_id column";
            throw new GRAMAuditSQLException(msg, e);
        }
        assert (value != null);
        logger.debug("Obtained idempotence_id: " + value);

        return value;
    }

    /**
     * Get the value of the <code>creation_time</code> column
     * from the given SQL result.  Since the SQL type of this
     * column in a GRAM Audit&nbsp;V1 database is one of two
     * types, the caller indicates the SQL type by passing a
     * boolean flag to this method.
     * <p>
     * If the value of <code>useTimestamp</code> is true,
     * then this method uses
     * {@link java.sql.ResultSet#getTimestamp(String)}
     * to obtain the column value; otherwise it uses
     * {@link java.sql.ResultSet#getString(String)}.
     * In the latter case, the format of the date-time string
     * is assumed to be
     * <pre>yyyy-MM-dd HH:mm:ss</pre>
     * The above date-time string is parsed as a UTC value.
     *
     * @param result        the result of a SQL query
     * @param useTimestamp  indicates whether the <code>creation_time</code>
     *                      column is of SQL type <code>TIMESTAMP</code>
     *                      or <code>VARCHAR</code>
     *
     * @return the value of the <code>creation_time</code>
     *         column, which is never null
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to get the <code>creation_time</code>
     *            from the SQL result set
     */
    public static Timestamp getCreationTime(ResultSet result,
                                            boolean useTimestamp)
                                     throws GRAMAuditSQLException {

        Timestamp timestamp;
        if (useTimestamp) {
            try {
                timestamp = result.getTimestamp("creation_time");
            } catch (SQLException e) {
                String msg = "Unable to get creation_time column";
                throw new GRAMAuditSQLException(msg, e);
            }
        } else {
            String dateTime;
            try {
                dateTime = result.getString("creation_time");
            } catch (SQLException e) {
                String msg = "Unable to get creation_time column";
                throw new GRAMAuditSQLException(msg, e);
            }
            assert (dateTime != null);
            try {
                timestamp = parse(dateTime);
            } catch (ParseException e) {
                String msg = "Unable to parse dateTime string " + dateTime;
                throw new GRAMAuditSQLException(msg, e);
            }
        }
        assert (timestamp != null);
        logger.debug("Obtained creation_time (in local time): " +
                     timestamp.toString());

        return timestamp;
    }

    /**
     * Get the value of the <code>queued_time</code> column
     * from the given SQL result.  Since the SQL type of this
     * column in a GRAM Audit&nbsp;V1 database is one of two
     * types, the caller indicates the SQL type by passing a
     * boolean flag to this method.
     * <p>
     * If the value of <code>useTimestamp</code> is true,
     * then this method uses
     * {@link java.sql.ResultSet#getTimestamp(String)}
     * to obtain the column value; otherwise it uses
     * {@link java.sql.ResultSet#getString(String)}.
     * In the latter case, the format of the date-time string
     * is assumed to be
     * <pre>yyyy-MM-dd HH:mm:ss</pre>
     * The above date-time string is parsed as a UTC value.
     *
     * @param result the result of a SQL query
     * @param useTimestamp  indicates whether the <code>queued_time</code>
     *                      column is of SQL type <code>TIMESTAMP</code>
     *                      or <code>VARCHAR</code>
     *
     * @return the value of the <code>queued_time</code>
     *         column, which may be null
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to get the <code>queued_time</code>
     *            from the SQL result set
     */
    public static Timestamp getQueuedTime(ResultSet result,
                                          boolean useTimestamp)
                                   throws GRAMAuditSQLException {

        Timestamp timestamp;
        if (useTimestamp) {
            try {
                timestamp = result.getTimestamp("queued_time");
                if (result.wasNull()) {
                    logger.debug("Column queued_time is null");
                    return null;
                }
            } catch (SQLException e) {
                String msg = "Unable to get queued_time column";
                throw new GRAMAuditSQLException(msg, e);
            }
        } else {
            String dateTime;
            try {
                dateTime = result.getString("queued_time");
                if (result.wasNull()) {
                    logger.debug("Column queued_time is null");
                    return null;
                }
            } catch (SQLException e) {
                String msg = "Unable to get creation_time column";
                throw new GRAMAuditSQLException(msg, e);
            }
            assert (dateTime != null);
            try {
                timestamp = parse(dateTime);
            } catch (ParseException e) {
                String msg = "Unable to parse dateTime string " + dateTime;
                throw new GRAMAuditSQLException(msg, e);
            }

        }
        assert (timestamp != null);
        logger.debug("Obtained queued_time (in local time): " +
                     timestamp.toString());

        return timestamp;
    }

    /**
     * Get the value of the <code>stage_in_grid_id</code> column
     * from the given SQL result.
     *
     * @param result the result of a SQL query
     *
     * @return the value of the <code>stage_in_grid_id</code>
     *         column, which may be null
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to get the <code>stage_in_grid_id</code>
     *            from the SQL result set
     */
    public static String getStageInGridId(ResultSet result)
                                   throws GRAMAuditSQLException {

        String value;
        try {
            value = result.getString("stage_in_grid_id");
            if (result.wasNull()) {
                logger.debug("Column stage_in_grid_id is null");
                return null;
            }
        } catch (SQLException e) {
            String msg = "Unable to get stage_in_grid_id column";
            throw new GRAMAuditSQLException(msg, e);
        }
        assert (value != null);
        logger.debug("Obtained stage_in_grid_id: " + value);

        return value;
    }

    /**
     * Get the value of the <code>stage_out_grid_id</code> column
     * from the given SQL result.
     *
     * @param result the result of a SQL query
     *
     * @return the value of the <code>stage_out_grid_id</code>
     *         column, which may be null
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to get the <code>stage_out_grid_id</code>
     *            from the SQL result set
     */
    public static String getStageOutGridId(ResultSet result)
                                    throws GRAMAuditSQLException {

        String value;
        try {
            value = result.getString("stage_out_grid_id");
            if (result.wasNull()) {
                logger.debug("Column stage_out_grid_id is null");
                return null;
            }
        } catch (SQLException e) {
            String msg = "Unable to get stage_out_grid_id column";
            throw new GRAMAuditSQLException(msg, e);
        }
        assert (value != null);
        logger.debug("Obtained stage_out_grid_id: " + value);

        return value;
    }

    /**
     * Get the value of the <code>clean_up_grid_id</code> column
     * from the given SQL result.
     *
     * @param result the result of a SQL query
     *
     * @return the value of the <code>clean_up_grid_id</code>
     *         column, which may be null
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to get the <code>clean_up_grid_id</code>
     *            from the SQL result set
     */
    public static String getCleanUpGridId(ResultSet result)
                                   throws GRAMAuditSQLException {

        String value;
        try {
            value = result.getString("clean_up_grid_id");
            if (result.wasNull()) {
                logger.debug("Column clean_up_grid_id is null");
                return null;
            }
        } catch (SQLException e) {
            String msg = "Unable to get clean_up_grid_id column";
            throw new GRAMAuditSQLException(msg, e);
        }
        assert (value != null);
        logger.debug("Obtained clean_up_grid_id: " + value);

        return value;
    }

    /**
     * Get the value of the <code>globus_toolkit_version</code> column
     * from the given SQL result.
     *
     * @param result the result of a SQL query
     *
     * @return the value of the <code>globus_toolkit_version</code>
     *         column, which is never null
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to get the <code>globus_toolkit_version</code>
     *            from the SQL result set
     */
    public static String getGlobusToolkitVersion(ResultSet result)
                                          throws GRAMAuditSQLException {

        String value;
        try {
            value = result.getString("globus_toolkit_version");
        } catch (SQLException e) {
            String msg = "Unable to get globus_toolkit_version column";
            throw new GRAMAuditSQLException(msg, e);
        }
        assert (value != null);
        logger.debug("Obtained globus_toolkit_version: " + value);

        return value;
    }

    /**
     * Get the value of the <code>resource_manager_type</code> column
     * from the given SQL result.
     *
     * @param result the result of a SQL query
     *
     * @return the value of the <code>resource_manager_type</code>
     *         column, which is never null
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to get the <code>resource_manager_type</code>
     *            from the SQL result set
     */
    public static String getResourceManagerType(ResultSet result)
                                         throws GRAMAuditSQLException {

        String value;
        try {
            value = result.getString("resource_manager_type");
        } catch (SQLException e) {
            String msg = "Unable to get resource_manager_type column";
            throw new GRAMAuditSQLException(msg, e);
        }
        assert (value != null);
        logger.debug("Obtained resource_manager_type: " + value);

        return value;
    }

    /**
     * Get the value of the <code>job_description</code> column
     * from the given SQL result.
     *
     * @param result the result of a SQL query
     *
     * @return the value of the <code>job_description</code>
     *         column, which is never null
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to get the <code>job_description</code>
     *            from the SQL result set
     */
    public static String getJobDescription(ResultSet result)
                                    throws GRAMAuditSQLException {

        String value;
        try {
            value = result.getString("job_description");
        } catch (SQLException e) {
            String msg = "Unable to get job_description column";
            throw new GRAMAuditSQLException(msg, e);
        }
        assert (value != null);
        logger.debug("Obtained job_description: " + value);

        return value;
    }

    /**
     * Get the value of the <code>success_flag</code> column
     * from the given SQL result.
     *
     * @param result the result of a SQL query
     *
     * @return the value of the <code>success_flag</code>
     *         column, which is never null
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to get the <code>success_flag</code>
     *            from the SQL result set
     */
    public static String getSuccessFlag(ResultSet result)
                                 throws GRAMAuditSQLException {

        String value;
        try {
            value = result.getString("success_flag");
        } catch (SQLException e) {
            String msg = "Unable to get success_flag column";
            throw new GRAMAuditSQLException(msg, e);
        }
        assert (value != null);
        logger.debug("Obtained success_flag: " + value);

        return value;
    }

    /**
     * Get the value of the <code>finished_flag</code> column
     * from the given SQL result.
     *
     * @param result the result of a SQL query
     *
     * @return the value of the <code>finished_flag</code>
     *         column, which is never null
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to get the <code>finished_flag</code>
     *            from the SQL result set
     */
    public static String getFinishedFlag(ResultSet result)
                               throws GRAMAuditSQLException {

        String value;
        try {
            value = result.getString("finished_flag");
        } catch (SQLException e) {
            String msg = "Unable to get finished_flag column";
            throw new GRAMAuditSQLException(msg, e);
        }
        assert (value != null);
        logger.debug("Obtained finished_flag: " + value);

        return value;
    }

    /**
     * Get the value of the <code>gateway_user</code> column
     * from the given SQL result.
     * <p>
     * Not all GRAM audit database deployments have a
     * <code>gateway_user</code> column, so it is up to
     * caller to check to make sure such a column exists.
     * <strong>If the GRAM audit database that produced
     * the given result does not have a
     * <code>gateway_user</code> column, this method will
     * throw a <code>GRAMAuditSQLException</code>.</strong>
     *
     * @param result the result of a SQL query
     *
     * @return the value of the <code>gateway_user</code>
     *         column, which may be null
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to get the <code>gateway_user</code>
     *            from the SQL result set
     *
     * @see org.teragrid.ncsa.gridshib.gram.GRAMAuditV1Connection#hasGatewayUserColumn()
     */
    public static String getGatewayUser(ResultSet result)
                                 throws GRAMAuditSQLException {

        String value;
        try {
            value = result.getString("gateway_user");
            if (result.wasNull()) {
                logger.debug("Column gateway_user is null");
                return null;
            }
        } catch (SQLException e) {
            String msg = "Unable to get gateway_user column";
            throw new GRAMAuditSQLException(msg, e);
        }
        assert (value != null);
        logger.debug("Obtained gateway_user: " + value);

        return value;
    }

    /**
     * The format of date-time strings in a non-PostgreSQL
     * GRAM audit table.  (In PostgreSQL, date-times are
     * represented as SQL <code>TIMESTAMP</code> values.)
     */
    final private static String DATE_TIME_PATTERN =
        "yyyy-MM-dd HH:mm:ss";

    /**
     * Parse the given date-time string into an equivalent
     * <code>Timestamp</code> object.  The format of the
     * date-time string is assumed to be a UTC date-time
     * value of the form
     * <pre>yyyy-MM-dd HH:mm:ss</pre>
     * which is precisely the format of a date-time string
     * in a MySQL-backed GRAM audit table.
     *
     * @param dateTime a date-time string of the form
     *                 <code>yyyy-MM-dd HH:mm:ss</code>
     *
     * @return the equivalent SQL <code>TIMESTAMP</code> value
     *
     * @exception java.text.ParseException
     *            if unable to parse the give date-time string
     */
    public static Timestamp parse(String dateTime)
                           throws ParseException {

        if (dateTime == null) {
            logger.debug("The given dateTime string is null");
            return null;
        }
        logger.debug("Converting a UTC dateTime string: " + dateTime);

        // Assume that the given dateTime string is UTC.
        // This may or may not be true in practice so this
        // method may be BUGGED!  See
        //
        // https://bugzilla.mcs.anl.gov/globus/show_bug.cgi?id=6744
        //
        // for a detailed discussion of this issue.

        SimpleDateFormat formatter =
            new SimpleDateFormat(DATE_TIME_PATTERN);
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));

        Date date = formatter.parse(dateTime);

        return new Timestamp(date.getTime());
    }

    /**
     * Convert an arbitrary <code>Timestamp</code> to
     * a date-time string.  The format of the resulting
     * date-time string is
     * <pre>yyyy-MM-dd HH:mm:ss</pre>
     * which is an implicit UTC date-time value.
     * <p>
     * Note that some precision is lost as a result of this
     * conversion.  This is intentional since this is
     * precisely what GRAM does when it inserts a
     * date-time into a MySQL audit table.
     *
     * @param timestamp an arbitrary SQL <code>TIMESTAMP</code>
     *
     * @return a date-time string of the form
     *         <code>yyyy-MM-dd HH:mm:ss</code>
     */
    public static String format(Timestamp timestamp) {

        if (timestamp == null) {
            logger.debug("The given timestamp is null");
            return null;
        }

        SimpleDateFormat formatter =
            new SimpleDateFormat(DATE_TIME_PATTERN);
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));

        String dateTime = formatter.format(new Date(timestamp.getTime()));
        logger.debug("Converted a timestamp into the following UTC " +
                     "dateTime string: " + dateTime);

        return dateTime;
    }
}
