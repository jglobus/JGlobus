/*
 * Copyright 1999-2009 University of Chicago
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

import java.io.InputStream;
import java.io.IOException;
import java.util.Properties;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.FileAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.xml.DOMConfigurator;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.common.ShibResource;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.idp.IdPConfig;
import edu.internet2.middleware.shibboleth.log.RollingFileAppender;

/**
 * TBA
 *
 * @author Tom Scavo
 */
public class GridShibTool {

    private static String gridshibPropFilePath =
        "/conf/gridshib-idp-sysinfo.properties";

    //private static String shibPropFilePath =
    //    "/conf/shib-idp-sysinfo.properties";

    private static Properties gridshibProps = null;
    //private static Properties shibProps = null;

    static {
        loadProperties();
    }

    /**
     * Get GridShib properties
     */
    protected static Properties getProperties() {
        return gridshibProps;
    }

    /**
     * Load properties
     */
    private static void loadProperties() {

        InputStream in;
        Properties props;

        // load GridShib properties file:
        in = GridShibTool.class.getResourceAsStream(gridshibPropFilePath);
        props = new Properties();
        try {
            props.load(in);
        } catch (IOException e) {
            String msg = "Unable to load properties file: " + gridshibPropFilePath;
            System.err.println(msg);
            System.exit(1);
        }
        try {
            in.close();
        } catch (IOException e) {
            String msg = "Unable to close input stream";
            System.err.println(msg);
            System.exit(1);
        }
        gridshibProps = props;

        /*
        // load Shib properties file:
        in = GridShibSysInfo.class.getResourceAsStream(shibPropFilePath);
        props = new Properties();
        try {
            props.load(in);
        } catch (IOException e) {
            String msg = "Unable to load properties file: " + shibPropFilePath;
            System.err.println(msg);
            System.exit(1);
        }
        try {
            in.close();
        } catch (IOException e) {
            String msg = "Unable to close input stream";
            System.err.println(msg);
            System.exit(1);
        }
        shibProps = props;
        */

    }

    /**
     * The log file extension
     */
    //private static String logFileExtension = ".log";

    /**
     * Log message layout pattern for the transaction log
     */
    //private static String txLogLayoutPattern = "%d{ISO8601} %m%n";

    /**
     * Date pattern used at the end of the transaction log filename
     */
    //private static String txLogAppenderDatePattern = "'.'yyyy-MM-dd";

    /**
     * Log message layout pattern for the general system log
     */
    //private static String sysLogLayoutPattern = "%d{ISO8601} %-5p %-41X{serviceId} - %m%n";

    /**
     * Date pattern used at the end of the general system log filename
     */
    //private static String sysLogAppenderDatePattern = "'.'yyyy-MM-dd";

    /**
     * Initializes the Log4J logging framework.
     *
     * @param configuration
     *            logging configuration element from the IdP XML configuration file
     * @throws ShibbolethConfigurationException
     *             thrown if there is a problem configuring the logs
     */
    /*
    public static void initializeLogging(Element configuration) throws ShibbolethConfigurationException {

        NodeList txLogElems = configuration.getElementsByTagNameNS(IdPConfig.configNameSpace, "TransactionLog");
        if (txLogElems.getLength() > 0) {
            if (txLogElems.getLength() > 1) {
                System.err.println("WARNING: More than one TransactionLog element detected in IdP logging "
                        + "configuration, only the first one will be used.");
            }
            Element txLogConfig = (Element) txLogElems.item(0);
            configureTransactionLog(txLogConfig);
        } else {
            configureTransactionLog();
        }

        NodeList sysLogElems = configuration.getElementsByTagNameNS(IdPConfig.configNameSpace, "ErrorLog");
        if (sysLogElems.getLength() > 0) {
            if (sysLogElems.getLength() > 1) {
                System.err.println("WARNING: More than one ErrorLog element detected in IdP logging configuration, "
                        + "only the first one will be used.");
            }
            Element sysLogConfig = (Element) sysLogElems.item(0);
            configureSystemLog(sysLogConfig);
        } else {
            configureSystemLog();
        }

        NodeList log4jElems = configuration.getElementsByTagNameNS(IdPConfig.configNameSpace, "Log4JConfig");
        if (log4jElems.getLength() > 0) {
            if (log4jElems.getLength() > 1) {
                System.err.println("WARNING: More than one Log4JConfig element detected in IdP logging configuration, "
                        + "only the first one will be used.");
            }
            Element log4jConfig = (Element) log4jElems.item(0);
            configureLog4J(log4jConfig);
        }
    }
    */

    /**
     * Initialize the logs for the Shibboleth-TRANSACTION log, edu.internet2.middleware.shibboleth, and org.opensaml
     * logs. Output is directed to the standard out with the the transaction log at INFO level and the remainder at
     * warn.
     */
    /*
    public static void initializeLogging() {

        configureTransactionLog();
        configureSystemLog();
    }
    */

    /**
     * Configured the transaction log to log to the console at INFO level.
     */
    /*
    private static void configureTransactionLog() {

        ConsoleAppender appender = new ConsoleAppender(new PatternLayout(txLogLayoutPattern),
                ConsoleAppender.SYSTEM_OUT);
        Logger log = Logger.getLogger("Shibboleth-TRANSACTION");
        log.setAdditivity(false); // do not want parent's messages
        log.setLevel(Level.INFO);
        log.addAppender(appender);
    }
    */

    /**
     * Configures the transaction log.
     *
     * @param configuration
     *            the TransactionLog element from the IdP XML logging configuration
     * @throws ShibbolethConfigurationException
     *             thrown if there is a problem configuring the logs
     */
    /*
    private static void configureTransactionLog(Element configuration) throws ShibbolethConfigurationException {

        NamedNodeMap attributes = configuration.getAttributes();

        String location = attributes.getNamedItem("location").getNodeValue();
        if (location == null) { throw new ShibbolethConfigurationException(
                "No log file location attribute specified in TransactionLog element"); }

        FileAppender appender = null;
        try {
            String logPath = new ShibResource(location, GridShibTool.class).getFile().getCanonicalPath();
            appender = createRollingFileAppender(txLogLayoutPattern, logPath, txLogAppenderDatePattern);
            appender.setName("shibboleth-transaction");
        } catch (Exception e) {
            throw new ShibbolethConfigurationException("<TransactionLog location=\"" + location
                    + "\">: error creating DailyRollingFileAppender: " + e);
        }

        Level level = Level.INFO;
        if (attributes.getNamedItem("level") != null) {
            level = Level.toLevel(attributes.getNamedItem("level").getNodeValue());
        }

        Logger log = Logger.getLogger("Shibboleth-TRANSACTION");
        log.setAdditivity(false); // do not want parent's messages
        log.setLevel(level);
        log.addAppender(appender);
    }
    */

    /**
     * Configures the standard system log to log messages from edu.internet2.middleware.shibboleth and org.opensaml to
     * the console at WARN level.
     */
    /*
    private static void configureSystemLog() {

        ConsoleAppender appender = new ConsoleAppender(new PatternLayout(sysLogLayoutPattern),
                ConsoleAppender.SYSTEM_OUT);
        Logger shibLog = Logger.getLogger("edu.internet2.middleware.shibboleth");
        shibLog.setLevel(Level.WARN);
        shibLog.addAppender(appender);

        Logger openSAMLLog = Logger.getLogger("org.opensaml");
        openSAMLLog.setLevel(Level.WARN);
        openSAMLLog.addAppender(appender);
    }
    */

    /**
     * Configures the system-wide IdP log.
     *
     * @param configuration
     *            the ErrorLog element from the IdP XML logging configuration
     * @throws ShibbolethConfigurationException
     *             thrown if there is a problem configuring the logs
     */
    /*
    private static void configureSystemLog(Element configuration) throws ShibbolethConfigurationException {

        NamedNodeMap attributes = configuration.getAttributes();

        String location = attributes.getNamedItem("location").getNodeValue();
        if (location == null) { throw new ShibbolethConfigurationException(
                "No log file location attribute specified in ErrorLog element"); }

        FileAppender appender = null;
        try {
            String logPath = new ShibResource(location, GridShibTool.class).getFile().getCanonicalPath();
            appender = createRollingFileAppender(sysLogLayoutPattern, logPath, sysLogAppenderDatePattern);
            appender.setName("shibboleth-error");
        } catch (Exception e) { // catch any exception
            throw new ShibbolethConfigurationException("<ErrorLog location=\"" + location
                    + "\">: error creating DailyRollingFileAppender: " + e);
        }

        Level level = Level.WARN;
        if (attributes.getNamedItem("level") != null) {
            level = Level.toLevel(attributes.getNamedItem("level").getNodeValue());
        }

        Logger shibLog = Logger.getLogger("edu.internet2.middleware.shibboleth");
        shibLog.setLevel(level);
        shibLog.addAppender(appender);

        Logger openSAMLLog = Logger.getLogger("org.opensaml");
        openSAMLLog.setLevel(level);
        openSAMLLog.addAppender(appender);
    }
    */

    /**
     * Configures the tool log to log to a file.
     *
     * @throws ShibbolethConfigurationException
     *             thrown if there is a problem configuring the logs
     */
    /*
    protected static void configureToolLog() throws ShibbolethConfigurationException {

        String location = logLocation;
        if (location == null) {}

        FileAppender appender = null;
        try {
            String logPath = new ShibResource(location, GridShibTool.class).getFile().getCanonicalPath();
            appender = createRollingFileAppender(toolLogLayoutPattern,
                                                 logPath,
                                                 logAppenderDatePattern);
            appender.setName("gridshib-tool");
        } catch (Exception e) { // catch any exception
            throw new ShibbolethConfigurationException("location " + location
                    + ": error creating DailyRollingFileAppender: " + e);
        }

        Level level = Level.WARN;
        if (logLevel != null) {
            level = Level.toLevel(logLevel);
        }

        Logger log = Logger.getLogger("gridshib-tool");
        log.setAdditivity(false);
        log.setLevel(level);
        log.addAppender(appender);

    }
    */

    protected static Logger log = null;

    //private static String logLevel = "DEBUG";

    protected static String logLocation =
        "file:/C:/shibboleth-idp-1.3/logs/gridshib-tool.log";

    private static String toolLogLayoutPattern =
        "%-5p %d{ISO8601} (%c:%L) - %m%n";
    private static String logAppenderDatePattern = "'.'yyyy-MM-dd";

    protected static void configureLogging(boolean debugEnabled) throws ShibbolethConfigurationException {

        String location = logLocation;
        if (location == null) {}

        FileAppender rootAppender = null;
        try {
            String logPath = new ShibResource(location, GridShibTool.class).getFile().getCanonicalPath();
            rootAppender = createRollingFileAppender(toolLogLayoutPattern,
                                                     logPath,
                                                     logAppenderDatePattern);
            rootAppender.setName("gridshib-tool");
        } catch (Exception e) {
            throw new ShibbolethConfigurationException("location " + location
                    + ": error creating DailyRollingFileAppender: " + e);
        }

        log = Logger.getLogger(GridShibTool.class);
        log.addAppender(rootAppender);

        Logger.getRootLogger().removeAllAppenders();
        Logger.getRootLogger().addAppender(rootAppender);

        if (debugEnabled) {
            log.setLevel(Level.DEBUG);
            Logger.getRootLogger().setLevel(Level.DEBUG);
            //rootAppender.setLayout(new PatternLayout("%-5p %d{ISO8601} (%c:%L) - %m%n"));
        } else {
            log.setLevel(Level.INFO);
            Logger.getRootLogger().setLevel(Level.INFO);
            Logger.getLogger("edu.internet2.middleware.shibboleth.aa.attrresolv").setLevel(Level.WARN);
            //rootAppender.setLayout(new PatternLayout(PatternLayout.TTCC_CONVERSION_PATTERN));
        }
        Logger.getLogger("org.apache.xml.security").setLevel(Level.OFF);
    }

    /**
     * Creates a rolling file appender.  If the given log file ends with .* the characters after the .
     * will be treated as the logs extension.  If there is no . in the log file path a default extension
     * of "log" will be used.  When the log file is rolled the resulting file name is "logfile"."date"."extension".
     *
     * @param messagePattern patterns for the log messages
     * @param logFile the log file
     * @param datePattern the date pattern to roll the file one
     *
     * @return a rolling file appender
     *
     * @throws IOException thrown if the appender can not create the initial log file
     */
    protected static FileAppender createRollingFileAppender(String messagePattern, String logFile, String datePattern) throws IOException {
        PatternLayout messageLayout = new PatternLayout(messagePattern);

        int fileExtDelimIndex = logFile.lastIndexOf(".");
        if(fileExtDelimIndex <= 0) {
            return new RollingFileAppender(messageLayout, logFile, datePattern, ".log");
        } else {
            String filePath = logFile.substring(0, fileExtDelimIndex);
            String fileExtension = logFile.substring(fileExtDelimIndex);

            return new RollingFileAppender(messageLayout, filePath, datePattern, fileExtension);
        }
    }

    /**
     * Configures Log4J by way of a Log4J specific configuration file.
     *
     * @param configuration
     *            the Log4JConfig element from the IdP XML logging configuration
     * @throws ShibbolethConfigurationException
     *             thrown if there is a problem configuring the logs
     */
    /*
    private static void configureLog4J(Element configuration) throws ShibbolethConfigurationException {

        NamedNodeMap attributes = configuration.getAttributes();

        String location = attributes.getNamedItem("location").getNodeValue();
        if (location == null) { throw new ShibbolethConfigurationException(
                "No configuration file location attribute specified in Log4JConfig element"); }

        String type = null;
        Node typeNode = attributes.getNamedItem("type");
        if (typeNode != null) {
            type = typeNode.getNodeValue();
        }

        ShibResource log4jConfig;
        try {
            log4jConfig = new ShibResource(location);
            if (type == null || "properties".equals(type)) {
                PropertyConfigurator.configure(log4jConfig.getURL());
            } else if ("xml".equals(type)) {
                DOMConfigurator.configure(log4jConfig.getURL());
            } else {
                throw new ShibbolethConfigurationException(
                        "<Log4JConfig (type) attribute must be one of \"xml\" or \"properties\".");
            }
        } catch (IOException e) {
            throw new ShibbolethConfigurationException("<Log4JConfig location=\"" + location + "\">: not a valid URL: "
                    + e);
        }

    }
    */
}
