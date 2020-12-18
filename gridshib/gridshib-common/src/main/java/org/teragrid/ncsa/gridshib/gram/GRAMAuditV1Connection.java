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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.Properties;

import javax.sql.DataSource;

import org.apache.commons.dbcp.BasicDataSource;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.util.PropertiesUtil;
import org.globus.gridshib.config.BootstrapConfigLoader;

/**
 * A class that creates and manages a connection to a
 * <a href="http://dev.globus.org/wiki/GRAM_Audit_V1">GRAM Audit&nbsp;V1</code>
 * database.
 *
 * @since 0.5.5
 *
 * @see org.teragrid.ncsa.gridshib.gram.GRAMAuditV1
 */
public class GRAMAuditV1Connection {

    private static Log logger =
        LogFactory.getLog(GRAMAuditV1Connection.class.getName());

    final private static String DB_DRIVER_CLASS_KEY =
        "db.driver.class";
    final private static String DB_URL_KEY =
        "audit.db.url";
    final private static String DB_USERNAME_KEY =
        "audit.db.username";
    final private static String DB_PASSWORD_KEY =
        "audit.db.password";

    private static String driverClass;
    private static String url;
    private static String username;
    private static String password;

    private static DataSource getDataSource(File dbConfigFile)
                                     throws GRAMAuditSQLException {

        loadConnectionProperties(dbConfigFile);

        BasicDataSource dataSource = new BasicDataSource();
        dataSource.setDriverClassName(driverClass);
        dataSource.setUsername(username);
        dataSource.setPassword(password);
        dataSource.setUrl(url);

        return dataSource;
    }

    private static void loadConnectionProperties(File dbConfigFile)
                                          throws GRAMAuditSQLException {

        File file = null;
        if (dbConfigFile == null) {
            file = BootstrapConfigLoader.getDBConfigFileDefault();
        } else {
            file = dbConfigFile;
            if (!file.isAbsolute()) {
                String msg = "Path to database connection properties file " +
                             "must be absolute: " + dbConfigFile.getPath();
                throw new GRAMAuditSQLException(msg);
            }
        }
        if (file == null) {
            String msg = "Database connection properties file not specified";
            throw new GRAMAuditSQLException(msg);
        }

        Properties props = new Properties();
        try {
            props.load(new FileInputStream(file));
        } catch (FileNotFoundException e) {
            String msg = "Unable to open database connection properties " +
                         "file for reading: " + file.getPath();
            throw new GRAMAuditSQLException(msg, e);
        } catch (IOException e) {
            String msg = "Unable to load database connection properties " +
                         "file: " + file.getPath();
            throw new GRAMAuditSQLException(msg, e);
        }
        logger.info("Loading database connection properties file: " +
                    file.getPath());

        String propName;  // a property name

        propName = DB_DRIVER_CLASS_KEY;
        driverClass = PropertiesUtil.getProperty(props, propName, null);
        if (driverClass == null || driverClass.equals("")) {
            String msg =
                "Property (" + DB_DRIVER_CLASS_KEY + ") is null or empty";
            throw new GRAMAuditSQLException(msg);
        }

        propName = DB_URL_KEY;
        url = PropertiesUtil.getProperty(props, propName, null);
        if (url == null || url.equals("")) {
            String msg =
                "Property (" + DB_URL_KEY + ") is null or empty";
            throw new GRAMAuditSQLException(msg);
        }

        propName = DB_USERNAME_KEY;
        username = PropertiesUtil.getProperty(props, propName, null);
        if (username == null || username.equals("")) {
            String msg =
                "Property (" + DB_USERNAME_KEY + ") is null or empty";
            throw new GRAMAuditSQLException(msg);
        }

        propName = DB_PASSWORD_KEY;
        password = PropertiesUtil.getProperty(props, propName, null);
        if (password == null || password.equals("")) {
            String msg =
                "Property (" + DB_PASSWORD_KEY + ") is null or empty";
            throw new GRAMAuditSQLException(msg);
        }
    }

    private Connection connection;
    private String dbName;

    /**
     * Creates a connection to a data source.
     * <p>
     * Invokes the
     * {@link org.globus.gridshib.config.BootstrapConfigLoader#getDBConfigFileDefault()}
     * method to determine a database connection properties file.
     * Loads this properties file to obtain values for each
     * of the database connection properties.  Creates a
     * data source for the database using these connection
     * properties.  Finally, makes a connection to the data
     * source.
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to create a connection to the data source
     *            or initialize the members of this class
     */
    public GRAMAuditV1Connection() throws GRAMAuditSQLException {

        this(null);
    }

    /**
     * Creates a connection to a data source.
     * <p>
     * Loads the given database connection properties file
     * to obtain values for each of the database connection
     * properties.  Creates a data source for the database
     * using these connection properties.  Finally, makes a
     * connection to the data source.
     * <p>
     * The <code>dbConfigFile</code> parameter may be null.
     * If it is, this constructor invokes the
     * {@link org.globus.gridshib.config.BootstrapConfigLoader#getDBConfigFileDefault()}
     * method to determine a database connection properties file.
     *
     * @param dbConfigFile the (possibly null) configuration file
     *                     corresponding to a database connection
     *                     properties file
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to create a connection to the data source
     *            or initialize the members of this class
     */
    public GRAMAuditV1Connection(File dbConfigFile)
                          throws GRAMAuditSQLException {

        DataSource dataSource = getDataSource(dbConfigFile);

        try {
            this.connection = dataSource.getConnection();
            this.connection.setAutoCommit(true);
        } catch (SQLException e) {
            this.connection = null;
            String msg = "Unable to get database connection";
            throw new GRAMAuditSQLException(msg, e);
        }
        assert (this.connection != null);

        // determine the name of this database product:
        this.dbName = null;
        try {
            this.dbName =
                this.connection.getMetaData().getDatabaseProductName();
            logger.info("Connected to database product: " + this.dbName);
        } catch (SQLException e) {
            String msg = "Unable to get database product name";
            throw new GRAMAuditSQLException(msg, e);
        }
        if (this.dbName == null) {
            String msg = "Database product name is null";
            throw new GRAMAuditSQLException(msg);
        }
        assert (this.dbName != null);
    }

    /**
     * Get the name of this database product.
     *
     * @return the name of the database
     */
    public String getDatabaseName() {

        return this.dbName;
    }

    /**
     * Determine if a connection was made to a
     * PostgreSQL database.
     *
     * @return true if and only if this is a PostgreSQL database
     */
    public boolean isPostgreSQL() {

        return this.dbName.equalsIgnoreCase("postgresql");
    }

    /**
     * Determine if a connection was made to a GRAM audit
     * database with a GRAM audit table having a
     * <code>gateway_user</code> column.  The GRAM audit
     * table is queried every time this method is called,
     * so if the <code>gateway_user</code> column is added
     * or dropped during the interim, this method will still
     * return the correct result.
     *
     * @return true if and only if there is a
     *         <code>gateway_user</code> column
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to determine if the GRAM audit table at
     *            this connection has a <code>gateway_user</code> column
     */
    public boolean hasGatewayUserColumn() throws GRAMAuditSQLException {

        boolean foundGatewayUserColumn;
        try {
            Statement statement = this.getStatement();
            String sql =
                "SELECT * FROM gram_audit_table WHERE job_grid_id='dummy'";
            ResultSetMetaData metaData =
                statement.executeQuery(sql).getMetaData();

            int n = metaData.getColumnCount();
            if (n == 15 || n == 16) {
                String msg =
                    "Found " + n + " columns in the gram_audit_table";
                logger.info(msg);
            } else {
                String msg =
                    "Found " + n + " columns in the gram_audit_table " +
                    "but expected to find 15 or 16";
                throw new GRAMAuditSQLException(msg);
            }

            foundGatewayUserColumn = false;
            for (int i = 1; i <= n; i++) {
                String name = metaData.getColumnName(i);
                logger.debug("Found column name: " + name);
                if (name.equalsIgnoreCase("gateway_user")) {
                    foundGatewayUserColumn = true;
                    break;
                }
            }

            statement.close();

            if (foundGatewayUserColumn) {
                String msg = "Found the gateway_user column and so the " +
                             "Science Gateways Capability kit is installed";
                logger.info(msg);
                if (n == 15) {
                    msg = "Found 15 columns in the gram_audit_table " +
                          "but expected to find 16";
                    throw new GRAMAuditSQLException(msg);
                }
            } else {
                String msg = "The gateway_user column was not found and " +
                             "so the Science Gateways Capability kit is " +
                             "not installed";
                logger.info(msg);
                if (n == 16) {
                    msg = "Found 16 columns in the gram_audit_table " +
                          "but expected to find 15";
                    throw new GRAMAuditSQLException(msg);
                }
            }
        } catch (SQLException e) {
            String msg = "Unable to determine if the Science Gateways " +
                         "Capability kit is installed";
            throw new GRAMAuditSQLException(msg, e);
        }

        return foundGatewayUserColumn;
    }

    /**
     * Get a SQL statement.
     *
     * @return a SQL statement
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to create a statement
     */
    public Statement getStatement() throws GRAMAuditSQLException {

        Statement statement;
        try {
            statement = this.connection.createStatement();
        } catch (SQLException e) {
            String msg = "Unable to get SQL statement";
            throw new GRAMAuditSQLException(msg, e);
        }
        logger.info("SQL statement created");

        return statement;
    }

    /**
     * Get a SQL prepared statement.
     *
     * @param sql a SQL string used to create this prepared statement
     *
     * @return a SQL prepared statement
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to create a prepared statement
     */
    public PreparedStatement getPreparedStatement(String sql)
                                           throws GRAMAuditSQLException {

        PreparedStatement statement;
        try {
            statement = this.connection.prepareStatement(sql);
        } catch (SQLException e) {
            String msg = "Unable to get prepared statement for SQL string " +
                         "\"" + sql + "\"";
            throw new GRAMAuditSQLException(msg, e);
        }
        logger.info("Prepared SQL statement created: " + sql);

        return statement;
    }

    /**
     * Close the connection to the data source.
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to close the connection
     */
    public void close() throws GRAMAuditSQLException {

        try {
            this.connection.close();
        } catch (SQLException e) {
            String msg = "Unable to close database connection";
            throw new GRAMAuditSQLException(msg, e);
        }
    }

    /**
     * A convenience method that invokes
     * {@link org.teragrid.ncsa.gridshib.gram.GRAMAuditV1#getCreationTime(ResultSet, boolean)}
     * with the appropriate value of the <code>useTimestamp</code>
     * parameter for this connection.
     *
     * @return the value of the <code>creation_time</code>
     *         column, which is never null
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to get the <code>creation_time</code>
     *            from the SQL result set
     */
    public Timestamp getCreationTime(ResultSet result)
                              throws GRAMAuditSQLException {

        return GRAMAuditV1.getCreationTime(result, this.isPostgreSQL());
    }

    /**
     * A convenience method that invokes
     * {@link org.teragrid.ncsa.gridshib.gram.GRAMAuditV1#getQueuedTime(ResultSet, boolean)}
     * with the appropriate value of the <code>useTimestamp</code>
     * parameter for this connection.
     *
     * @return the value of the <code>queued_time</code>
     *         column, which is never null
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to get the <code>queued_time</code>
     *            from the SQL result set
     */
    public Timestamp getQueuedTime(ResultSet result)
                            throws GRAMAuditSQLException {

        return GRAMAuditV1.getQueuedTime(result, this.isPostgreSQL());
    }

    /**
     * A convenience method that invokes
     * {@link org.teragrid.ncsa.gridshib.gram.GRAMAuditV1#getGatewayUser(ResultSet)}
     * if the connection is to a GRAM audit database and
     * the GRAM audit table has a <code>gateway_user</code>
     * column.  If the GRAM audit table does not have a
     * <code>gateway_user</code> column, this method
     * immediately returns null.
     *
     * @return the value of the <code>gateway_user</code>
     *         column, which may be null, either because
     *         the <code>gateway_user</code> column does
     *         not exist or because the <code>gateway_user</code>
     *         column is in fact null
     *
     * @exception org.teragrid.ncsa.gridshib.gram.GRAMAuditSQLException
     *            if unable to get the <code>gateway_user</code>
     *            from the SQL result set
     */
    public String getGatewayUser(ResultSet result)
                          throws GRAMAuditSQLException {

        String gatewayUser = null;
        if (this.hasGatewayUserColumn()) {
            gatewayUser = GRAMAuditV1.getGatewayUser(result);
        }

        return gatewayUser;
    }
}
