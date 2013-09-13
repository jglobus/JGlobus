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

package org.globus.gridshib.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.IOException;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.log4j.PropertyConfigurator;

import org.globus.gridshib.common.GridShibConfigException;
import org.globus.gridshib.common.LoadException;
import org.globus.gridshib.common.StringSetFile;
import org.globus.gridshib.common.util.PropertiesUtil;
import org.globus.gridshib.security.util.GSIUtil;

import org.globus.gsi.X509Credential;
import org.globus.gsi.CredentialException;
import org.globus.util.ConfigUtil;

/**
 * A <em>bootstrap properties file</em> provides bootstrap
 * configuration options to GridShib SAML Tools at startup.
 * The following <em>bootstrap properties</em> are defined:
 * <ol>
 *   <li><code>gridshib.logConfigPath</code></li>
 *   <li><code>gridshib.SAMLToolsConfigPath</code></li>
 *   <li><code>gridshib.certPath</code></li>
 *   <li><code>gridshib.keyPath</code></li>
 *   <li><code>gridshib.identityAttributesPath</code></li>
 *   <li><code>gridshib.cogConfigPath</code></li>
 *   <li><code>gridshib.SecurityContextImpl</code></li>
 * </ol>
 * See the GridShib SAML Tools
 * <a href="http://gridshib.globus.org/docs/gridshib-saml-tools/install.html#configuration">Installation Notes</a>
 * for definitions of each bootstrap property and background
 * reading regarding the bootstrap properties file.
 * <p>
 * This <code>BootstrapConfigLoader</code> attempts to
 * load a bootstrap properties file automatically. The
 * file is obtained in one of three ways (checked in order):
 * <ol>
 *   <li>Check the system property
 *   <code>org.globus.gridshib.config</code> for a
 *   (system dependent) absolute path to a bootstrap
 *   properties file</li>
 *   <li>Check for file
 *   <code>$HOME/.globus/gridshib-bootstrap.properties</code>
 *   on UNIX systems (or
 *   <code>%USERPROFILE%\.globus\gridshib-bootstrap.properties</code>
 *   on Windows systems)</li>
 *   <li>Check for resource
 *   <code>/org/globus/gridshib/resource/gridshib-bootstrap.properties</code>
 *   on the classpath</li>
 * </ol>
 * A default bootstrap properties file is created at
 * install time and bundled with the gridshib-saml-tools
 * JAR file.  Thus step&nbsp;3 is guaranteed to succeed
 * in a source deployment of GridShib SAML Tools.
 * In the case of a binary deployment, one approach is to use
 * {@link java.lang.System#setProperty(String,String)} to set
 * the system property <code>org.globus.gridshib.config</code>
 * <strong>before</strong> this class is initialized.  See the
 * GridShib SAML Tools
 * <a href="http://gridshib.globus.org/docs/gridshib-saml-tools-0.4.2/dev-guide.html#configuring-gridshib-common">Developer Guide</a>
 * for additional information.
 * <p>
 * Once loaded, the <code>BootstrapConfigLoader</code> class
 * provides an API to override selected bootstrap properties.
 *
 * @since 0.4.0
 */
public class BootstrapConfigLoader {

    private static final Class CLASS = BootstrapConfigLoader.class;
    private static final String CLASSNAME = CLASS.getName();
    private static Log logger = LogFactory.getLog(CLASSNAME);

    private static final String LOG_CONFIG_PATH_KEY =
        "gridshib.logConfigPath";
    private static final String TOOL_CONFIG_PATH_KEY =
        "gridshib.SAMLToolsConfigPath";
    private static final String DB_CONFIG_PATH_KEY =
        "gridshib.dbConfigPath";
    private static final String CERT_PATH_KEY =
        "gridshib.certPath";
    private static final String KEY_PATH_KEY =
        "gridshib.keyPath";
    private static final String ID_ATTRIBUTES_PATH_KEY =
        "gridshib.identityAttributesPath";
    private static final String COG_CONFIG_PATH_KEY =
        "gridshib.cogConfigPath";
    private static final String KEY_STORE_PATH_KEY =
        "gridshib.keyStorePath";
    private static final String KEY_STORE_PASSWORD_KEY =
        "gridshib.keyStorePassword";
    private static final String KEY_STORE_KEY_ALIAS_KEY =
        "gridshib.keyStoreKeyAlias";
    private static final String KEY_STORE_KEY_PASSWORD_KEY =
        "gridshib.keyStoreKeyPassword";
    private static final String SECURITY_CONTEXT_IMPL_KEY =
        "gridshib.SecurityContextImpl";

    private static final String GRIDSHIB_HOME;

    // a well-known system property:
    private static final String CONFIG_PATH_KEY =
        "org.globus.gridshib.config";

    private static final String BASE_FILENAME =
        "gridshib-bootstrap.properties";

    // a well-known path in the file system:
    private static final String PATH =
        ConfigUtil.globus_dir + BASE_FILENAME;

    // a well-known resource on the classpath:
    private static final String RESOURCE =
        "/org/globus/gridshib/resource/" + BASE_FILENAME;

    private static boolean isLoaded;

    // exposed bootstrap properties:
    private static String logConfigPathDefault;
    private static File samlToolsConfigFileDefault;
    private static File dbConfigFileDefault;
    private static X509Credential credentialDefault;
    private static StringSetFile identityAttributes;
    private static String cogConfigPathDefault;
    private static String keyStorePathDefault;
    private static String keyStorePasswordDefault;
    private static String keyStoreKeyAliasDefault;
    private static String keyStoreKeyPasswordDefault;
    private static String securityContextImpl;

    static {

        GRIDSHIB_HOME = System.getProperty("gridshib.home");

        init();

        // check well-known system property:
        String path = System.getProperty(CONFIG_PATH_KEY);
        if (path == null || path.equals("")) {
            // well-known system property is not set
        } else {
            // try the configured path:
            File f = new File(path);
            try {
                loadBootstrapProps(new FileInputStream(f));
                String msg = "Bootstrap properties loaded: " + path;
                logger.info(msg);
                isLoaded = true;
            } catch (FileNotFoundException e) {
                String msg = "Unable to process file at path: " + path;
                System.err.println(msg);
                System.err.println(e.getMessage());
            } catch (GridShibConfigException e) {
                String msg = "Unable to load bootstrap properties " +
                             "at path: " + path;
                System.err.println(msg);
                System.err.println(e.getMessage());
                msg = "Reinitializing " + CLASSNAME;
                System.err.println(msg);
                init();
            }
        }

        if (!isLoaded) {
            // try well-known path in the file system:
            File f = new File(PATH);
            try {
                loadBootstrapProps(new FileInputStream(f));
                String msg = "Bootstrap properties loaded: " + PATH;
                logger.info(msg);
                isLoaded = true;
            } catch (FileNotFoundException e) {
                // No bootstrap properties file found at well-known path
            } catch (GridShibConfigException e) {
                String msg = "Unable to load bootstrap properties " +
                             "at well-known path: " + PATH;
                System.err.println(msg);
                System.err.println(e.getMessage());
                msg = "Reinitializing " + CLASSNAME;
                System.err.println(msg);
                init();
            }
        }

        if (!isLoaded) {
            // try well-known resource on the classpath
            InputStream in = CLASS.getResourceAsStream(RESOURCE);
            if (in == null) {
                // No bootstrap properties file found at well-known resource
            } else {
                try {
                    loadBootstrapProps(in);
                    String msg = "Bootstrap properties loaded: " + RESOURCE;
                    logger.info(msg);
                    isLoaded = true;
                } catch (GridShibConfigException e) {
                    String msg = "Unable to load bootstrap properties " +
                                 "at well-known resource: " + RESOURCE;
                    System.err.println(msg);
                    System.err.println(e.getMessage());
                    msg = "Reinitializing " + CLASSNAME;
                    System.err.println(msg);
                    init();
                } finally {
                    try { in.close(); } catch (IOException e) {}
                }
            }
        }
    }

    private BootstrapConfigLoader() {}

    private static void init() {
        isLoaded = false;
        logConfigPathDefault = null;
        samlToolsConfigFileDefault = null;
        dbConfigFileDefault = null;
        credentialDefault = null;
        identityAttributes = null;
        cogConfigPathDefault = null;
        securityContextImpl = null;
    }

    /**
     * Converts a path to an absolute <code>File</code>
     * object. If the given path is relative and the
     * <code>gridshib.home</code> property is not null,  the
     * path is resolved relative to <code>gridshib.home</code>.
     * <p>
     * Checks the system property <code>gridshib.home</code>
     * first.  If the system property is null, checks the
     * given properties for the <code>gridshib.home</code>
     * property.
     *
     * @param path  a path to be resolved, either relative
     *              or absolute
     * @param props a set of properties that may contain a
     *              <code>gridshib.home</code> property
     * @return      an absolute, abstract file (or null, if the
     *              given path is null
     *
     * @exception org.globus.gridshib.common.GridShibConfigException
     *            if the given path is relative but the
     *            <code>gridshib.home</code> property is null
     */
    private static File toAbsoluteFile(String path, Properties props)
                                throws GridShibConfigException {

        if (path == null) { return null; }

        File f = new File(path);
        if (f.isAbsolute()) { return f; }

        if (GRIDSHIB_HOME != null) {
            f = new File(GRIDSHIB_HOME, path);
            assert (f.isAbsolute());
            return f;
        }

        String gridshib_home =
            PropertiesUtil.getProperty(props, "gridshib.home", null, false);
        if (gridshib_home != null) {
            f = new File(gridshib_home, path);
            assert (f.isAbsolute());
            return f;
        }

        String msg = "Path (" + path + ") is a relative path " +
                     "but property gridshib.home is not set";
        throw new GridShibConfigException(msg);
    }

    /**
     * Set the path to the default log4j properties file
     * and configure the logger.
     *
     * @param logConfigPath the absolute path to a log4j properties file
     */
    public static void setLogConfigPathDefault(String logConfigPath) {

        if (!isNonNullAndNonEmpty(logConfigPath)) {
            String msg =
                "Property (" + LOG_CONFIG_PATH_KEY + ") is null or empty";
            logger.warn(msg);
            return;
        }

        if (!new File(logConfigPath).isAbsolute()) {
            String msg = "Path (" + logConfigPath + ") is not absolute";
            throw new IllegalArgumentException(msg);
        }

        PropertyConfigurator.configure(logConfigPath);  // yuk
        logConfigPathDefault = logConfigPath;
        logger.info("Property " + LOG_CONFIG_PATH_KEY + ": " + logConfigPath);
    }

    /**
     * Set the default database config file.
     *
     * @param configPath the absolute path to a database
     *                   configuration properties file
     *
     * @since 0.5.5
     */
    private static void setDBConfigFileDefault(String configPath) {

        if (!isNonNullAndNonEmpty(configPath)) {
            String msg =
                "Property (" + DB_CONFIG_PATH_KEY + ") is null or empty";
            logger.warn(msg);
            return;
        }

        dbConfigFileDefault = new File(configPath);
        assert (dbConfigFileDefault.isAbsolute());
        logger.info("Property " + DB_CONFIG_PATH_KEY + ": " + configPath);
    }

    /**
     * Set the identity attributes, that is, those attributes
     * that may be treated as principal names.
     *
     * @param idAttributes the identity attributes
     */
    private static void setIdentityAttributes(StringSetFile idAttributes) {

        if (idAttributes == null) {
            String msg = "Arg (idAttributes) is null";
            logger.warn(msg);
            return;
        }

        identityAttributes = idAttributes;
        logger.info("Identity attributes set: " +
                    idAttributes.getResource().toString());
    }

    /**
     * Store the given path in the "org.globus.config.file"
     * system property.
     *
     * @param cogConfigPath the absolute path to a CoG properties file
     */
    public static void setCoGConfigPathDefault(String cogConfigPath) {

        if (!isNonNullAndNonEmpty(cogConfigPath)) {
            String msg =
                "Property (" + COG_CONFIG_PATH_KEY + ") is null or empty";
            logger.warn(msg);
            return;
        }

        if (!new File(cogConfigPath).isAbsolute()) {
            String msg = "Path (" + cogConfigPath + ") is not absolute";
            throw new IllegalArgumentException(msg);
        }

        System.setProperty("org.globus.config.file", cogConfigPath);
        cogConfigPathDefault = cogConfigPath;
        logger.info("Property " + COG_CONFIG_PATH_KEY + ": " + cogConfigPath);
    }

    /**
     * Set the path to a Java KeyStore.  The KeyStore is used
     * solely for testing purposes.
     *
     * @param keyStorePath the absolute path to a Java KeyStore
     */
    private static void setKeyStorePathDefault(String keyStorePath) {

        if (!isNonNullAndNonEmpty(keyStorePath)) {
            String msg =
                "Property (" + KEY_STORE_PATH_KEY + ") is null or empty";
            logger.warn(msg);
            return;
        }

        if (!new File(keyStorePath).isAbsolute()) {
            String msg = "Path (" + keyStorePath + ") is not absolute";
            throw new IllegalArgumentException(msg);
        }

        keyStorePathDefault = keyStorePath;
        logger.info("Property " + KEY_STORE_PATH_KEY + ": " + keyStorePath);
    }

    /**
     * Set the password to a Java KeyStore.  The KeyStore is used
     * solely for testing purposes.
     *
     * @param keyStorePassword the password to a Java KeyStore
     */
    private static void setKeyStorePasswordDefault(String keyStorePassword) {

        if (!isNonNullAndNonEmpty(keyStorePassword)) {
            String msg =
                "Property (" + KEY_STORE_PASSWORD_KEY + ") is null or empty";
            logger.warn(msg);
            return;
        }

        keyStorePasswordDefault = keyStorePassword;
        logger.info("Property " + KEY_STORE_PASSWORD_KEY + ": " +
                    keyStorePassword);
    }

    /**
     * Set the alias to a Java KeyStore key.  The KeyStore is used
     * solely for testing purposes.
     *
     * @param keyStoreKeyAlias the alias to a Java KeyStore key
     */
    private static void setKeyStoreKeyAliasDefault(String keyStoreKeyAlias) {

        if (!isNonNullAndNonEmpty(keyStoreKeyAlias)) {
            String msg =
                "Property (" + KEY_STORE_KEY_ALIAS_KEY + ") is null or empty";
            logger.warn(msg);
            return;
        }

        keyStoreKeyAliasDefault = keyStoreKeyAlias;
        logger.info("Property " + KEY_STORE_KEY_ALIAS_KEY + ": " +
                    keyStoreKeyAlias);
    }

    /**
     * Set the password to a Java KeyStore key.  The KeyStore is used
     * solely for testing purposes.
     *
     * @param keyStoreKeyPassword the password to a Java KeyStore key
     */
    private static void setKeyStoreKeyPasswordDefault(String keyStoreKeyPassword) {

        if (!isNonNullAndNonEmpty(keyStoreKeyPassword)) {
            String msg =
                "Property (" + KEY_STORE_KEY_PASSWORD_KEY + ") is null or empty";
            logger.warn(msg);
            return;
        }

        keyStoreKeyPasswordDefault = keyStoreKeyPassword;
        logger.info("Property " + KEY_STORE_KEY_PASSWORD_KEY + ": " +
                    keyStoreKeyPassword);
    }

    /**
     * Set the <code>SecurityContext</code> implementation.
     *
     * @param impl an implementation of the <code>SecurityContext</code>
     *        interface
     *
     * @see org.globus.gridshib.security.SecurityContext
     */
    private static void setSecurityContextImpl(String impl) {

        if (!isNonNullAndNonEmpty(impl)) {
            String msg =
                "Property (" + SECURITY_CONTEXT_IMPL_KEY + ") is null or empty";
            logger.warn(msg);
            return;
        }

        securityContextImpl = impl;
        logger.info("SecurityContext implementation set: " + impl);
    }

    /**
     * Get the current value of the
     * <code>gridshib.logConfigPath</code> bootstrap property.
     */
    public static String getLogConfigPathDefault() {

        return logConfigPathDefault;
    }

    /**
     * Get the current value of the
     * <code>gridshib.SAMLToolsConfigPath</code> bootstrap property.
     */
    public static File getConfigFileDefault() {

        return samlToolsConfigFileDefault;
    }

    /**
     * Get the current value of the
     * <code>gridshib.dbConfigPath</code> bootstrap property.
     *
     * @since 0.5.5
     */
    public static File getDBConfigFileDefault() {

        return dbConfigFileDefault;
    }

    /**
     * Get the current default issuing credential.
     */
    public static X509Credential getCredentialDefault() {

        return credentialDefault;
    }

    /**
     * Get the identity attributes.
     *
     * @since 0.4.3
     */
    public static StringSetFile getIdentityAttributes() {

        return identityAttributes;
    }

    /**
     * Get the value of the
     * <code>gridshib.keyStorePath</code> bootstrap property.
     * The Java KeyStore is used solely for testing purposes.
     *
     * @since 0.5.0
     */
    public static String getKeyStorePathDefault() {

        return keyStorePathDefault;
    }

    /**
     * Get the value of the
     * <code>gridshib.keyStorePassword</code> bootstrap property.
     * The Java KeyStore is used solely for testing purposes.
     *
     * @since 0.5.0
     */
    public static char[] getKeyStorePasswordDefault() {

        return keyStorePasswordDefault.toCharArray();
    }

    /**
     * Get the value of the
     * <code>gridshib.keyStoreKeyAlias</code> bootstrap property.
     * The Java KeyStore is used solely for testing purposes.
     *
     * @since 0.5.0
     */
    public static String getKeyStoreKeyAliasDefault() {

        return keyStoreKeyAliasDefault;
    }

    /**
     * Get the value of the
     * <code>gridshib.keyStoreKeyPassword</code> bootstrap property.
     * The Java KeyStore is used solely for testing purposes.
     *
     * @since 0.5.0
     */
    public static char[] getKeyStoreKeyPasswordDefault() {

        return keyStoreKeyPasswordDefault.toCharArray();
    }

    /**
     * Get the value of the
     * <code>gridshib.SecurityContextImpl</code> bootstrap property.
     * This becomes the default <code>SecurityContext</code>
     * implementation in <code>SecurityContextFactory</code>.
     *
     * @since 0.5.0
     *
     * @see org.globus.gridshib.security.SecurityContextFactory
     */
    public static String getSecurityContextImpl() {

        return securityContextImpl;
    }

    private static boolean isNonNullAndNonEmpty(String s) {
        return (s != null && !(s.equals("")));
    }

    private static boolean isNonNullAndNonEmpty(File f) {
        return (f != null && !(f.getName().equals("")));
    }

    /**
     * Load the bootstrap configuration properties at the
     * given input stream.
     *
     * @param in a (non-null) input stream
     *
     * @exception org.globus.gridshib.common.GridShibConfigException
     *            if the bootstrap properties file can not be
     *            loaded or if the configured certificate and key
     *            do not resolve into a valid credential
     */
    private static void loadBootstrapProps(InputStream in)
                                    throws GridShibConfigException {

        if (in == null) {
            String msg = "Null inputstream";
            throw new IllegalArgumentException(msg);
        }

        // load the properties file:
        Properties props = new Properties();
        try {
            props.load(in);
        } catch (IOException e) {
            String msg = "Unable to load bootstrap properties file: ";
            msg += e.getMessage();
            throw new GridShibConfigException(msg);
        }

        File file;
        String propName;  // a property name

        // get LOG_CONFIG_PATH_KEY bootstrap property:
        propName = LOG_CONFIG_PATH_KEY;
        String logConfigPath =
            PropertiesUtil.getProperty(props, propName, null, false);
        file = toAbsoluteFile(logConfigPath, props);
        assert (file == null || file.isAbsolute());
        if (file != null) {
            setLogConfigPathDefault(file.getPath());
        }

        // get TOOL_CONFIG_PATH_KEY bootstrap property:
        propName = TOOL_CONFIG_PATH_KEY;
        String configPath =
            PropertiesUtil.getProperty(props, propName, null);
        file = toAbsoluteFile(configPath, props);
        assert (file == null || file.isAbsolute());
        if (file != null) {
            if (!isNonNullAndNonEmpty(file)) {
                String msg =
                    "Property (" + TOOL_CONFIG_PATH_KEY + ") is null or empty";
                logger.warn(msg);
            } else {
                samlToolsConfigFileDefault = new File(file.getPath());
                assert (samlToolsConfigFileDefault.isAbsolute());
                logger.info("Property " + TOOL_CONFIG_PATH_KEY + ": " +
                            file);
            }
        }

        // get DB_CONFIG_PATH_KEY bootstrap property:
        propName = DB_CONFIG_PATH_KEY;
        String dbConfigPath =
            PropertiesUtil.getProperty(props, propName, null);
        file = toAbsoluteFile(dbConfigPath, props);
        assert (file == null || file.isAbsolute());
        if (file != null) {
            setDBConfigFileDefault(file.getPath());
        }

        // get CERT_PATH_KEY bootstrap property:
        propName = CERT_PATH_KEY;
        String certPath = PropertiesUtil.getProperty(props, propName, null);

        // get KEY_PATH_KEY bootstrap property:
        propName = KEY_PATH_KEY;
        String keyPath = PropertiesUtil.getProperty(props, propName, null);

        if (!isNonNullAndNonEmpty(certPath)) {
            String msg =
                "Property (" + CERT_PATH_KEY + ") is null or empty";
            logger.info(msg);
        } else if (!isNonNullAndNonEmpty(keyPath)) {
            String msg =
                "Property (" + KEY_PATH_KEY + ") is null or empty";
            logger.info(msg);
        } else {
            certPath = toAbsoluteFile(certPath, props).getPath();
            keyPath = toAbsoluteFile(keyPath, props).getPath();
            try {
                X509Credential cred =
                    GSIUtil.getCredential(certPath, keyPath);
                if (cred == null) {
                    String msg = "Argument (cred) is null";
                    logger.warn(msg);
                } else {
                    credentialDefault = cred;
                    logger.info("Default issuing credential set: " +
                                cred.toString());
                }
            } catch (CredentialException e) {
                String msg = "Unable to obtain valid issuing credential";
                logger.error(msg, e);
                throw new GridShibConfigException(msg);
            }
        }

        // get ID_ATTRIBUTES_PATH_KEY bootstrap property:
        propName = ID_ATTRIBUTES_PATH_KEY;
        String identityAttributesPath =
            PropertiesUtil.getProperty(props, propName, null);

        if (!isNonNullAndNonEmpty(identityAttributesPath)) {
            String msg =
                "Property (" + ID_ATTRIBUTES_PATH_KEY + ") is null or empty";
            logger.info(msg);
        } else {
            File f = toAbsoluteFile(identityAttributesPath, props);
            assert (f.isAbsolute());
            try {
                StringSetFile idAttributes = StringSetFile.getInstance(f);
                setIdentityAttributes(idAttributes);
            } catch (LoadException e) {
                String msg =
                    "Unable to load identity attributes: " + f.getPath();
                logger.error(msg, e);
                throw new GridShibConfigException(msg, e);
            }
        }

        // JGlobus CoG requires a cog.properties file.
        // Without it, nonfatal errors appear in the logs.
        // As a workaround, we provide an empty cog.properties,
        // which forces CoG to rely on its default properties.

        // get COG_CONFIG_PATH_KEY bootstrap property:
        propName = COG_CONFIG_PATH_KEY;
        String cogConfigPath =
            PropertiesUtil.getProperty(props, propName, null, false);
        file = toAbsoluteFile(cogConfigPath, props);
        assert (file == null || file.isAbsolute());
        if (file != null) {
            setCoGConfigPathDefault(file.getPath());
        }

        // get KEY_STORE_PATH_KEY bootstrap property:
        propName = KEY_STORE_PATH_KEY;
        String keyStorePath =
            PropertiesUtil.getProperty(props, propName, null, false);
        file = toAbsoluteFile(keyStorePath, props);
        assert (file == null || file.isAbsolute());
        if (file != null) {
            setKeyStorePathDefault(file.getPath());
        }

        // get KEY_STORE_PASSWORD_KEY bootstrap property:
        propName = KEY_STORE_PASSWORD_KEY;
        setKeyStorePasswordDefault(
            PropertiesUtil.getProperty(props, propName, null));

        // get KEY_STORE_KEY_ALIAS_KEY bootstrap property:
        propName = KEY_STORE_KEY_ALIAS_KEY;
        setKeyStoreKeyAliasDefault(
            PropertiesUtil.getProperty(props, propName, null));

        // get KEY_STORE_KEY_PASSWORD_KEY bootstrap property:
        propName = KEY_STORE_KEY_PASSWORD_KEY;
        setKeyStoreKeyPasswordDefault(
            PropertiesUtil.getProperty(props, propName, null));

        // get SECURITY_CONTEXT_IMPL_KEY bootstrap property:
        propName = SECURITY_CONTEXT_IMPL_KEY;
        String classname = PropertiesUtil.getProperty(props, propName, null);

        if (classname != null) {
            try {
                Class.forName(classname);
                setSecurityContextImpl(classname);
            } catch (ClassNotFoundException e) {
                String msg = "Class not found: " + classname;
                throw new GridShibConfigException(msg, e);
            }
        }
    }

    /**
     * Gets the value of a GridShib Tool config property.
     * This value is guaranteed to be non-null and nonempty.
     *
     * @param props the complete set of config properties
     * @param propName the config property of interest
     *
     * @return the requested property value
     *
     * @exception org.globus.gridshib.common.GridShibConfigException
     *            if the property value is missing or empty
     *
     * @deprecated As of 0.5.3, use
     * {@link org.globus.gridshib.common.util.PropertiesUtil#getProperty(Properties, String, String)}
     * instead.  This method will be removed in a future
     * version of GridShib SAML Tools.
     */
    public static String getProperty(Properties props, String propName)
                              throws GridShibConfigException {

        String propValue = props.getProperty(propName);
        if (propValue == null) {
            String msg = "Property " + propName + " not found";
            logger.error(msg);
            throw new GridShibConfigException(msg);
        } else if (propValue.equals("")) {
            String msg = "Property " + propName + " empty, ";
            logger.error(msg);
            throw new GridShibConfigException(msg);
        } else {
            logger.info("Property " + propName + " loaded: " + propValue);
            return propValue;
        }
    }

    /**
     * Gets the value of a GridShib Tool config property.
     *
     * @param props the complete set of config properties
     * @param propName the config property of interest
     * @param propValueDefault the default config property value,
     *                         which may be null
     *
     * @return the requested config property value or the default
     *         config property value if the requested property is
     *         not found
     *
     * @deprecated As of 0.5.3, use
     * {@link org.globus.gridshib.common.util.PropertiesUtil#getProperty(Properties, String, String)}
     * instead.  This method will be removed in a future
     * version of GridShib SAML Tools.
     */
    public static String getProperty(Properties props,
                                     String propName,
                                     String propValueDefault) {

        String propValue = props.getProperty(propName);
        if (propValue == null) {
            String msg = "Property " + propName + " not found, ";
            msg += "using default value: " + propValueDefault;
            logger.info(msg);
            return propValueDefault;
        } else if (propValue.equals("")) {
            String msg = "Property " + propName + " empty, ";
            msg += "using default value: " + propValueDefault;
            logger.warn(msg);
            return propValueDefault;
        } else {
            logger.info("Property " + propName + ": " + propValue);
            return propValue;
        }
    }
}
