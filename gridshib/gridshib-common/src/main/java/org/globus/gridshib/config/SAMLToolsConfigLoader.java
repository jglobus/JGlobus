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
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.FileLocation;
import org.globus.gridshib.common.GridShibConfigException;
import org.globus.gridshib.security.saml.SimpleAttribute;
import org.globus.gridshib.security.util.GSIUtil;

import org.globus.gsi.X509Credential;
import org.globus.gsi.CredentialException;

import org.globus.opensaml11.md.common.Constants;
import org.globus.opensaml11.saml.SAMLException;

/**
 * Configuration property file loader for
 * the GridShib SAML Tools.  This loader maintains
 * a static SAML Tools configuration object that may be
 * retrieved at any time using {@link #getToolConfig()}.
 * Calling {@link #load(File)} or {@link #load(InputStream)}
 * initializes the configuration object with the loaded
 * configuration properties.  On the other hand, calling
 * {@link #overlay(InputStream)} overlays the current
 * configuration object with the configuration properties
 * on the input stream.
 * <p>
 * This loader performs the following optimizations.
 * A configuration file loaded with {@link #load(File)}
 * is cached such that the next request to load the same
 * file is short-circuited.  Subsequent calls to
 * {@link #load(InputStream)} or {@link #overlay(InputStream)}
 * clear the cache, that is, the next call to {@link #load(File)}
 * is guaranteed not to short-circuit.
 *
 * @since 0.4.0
 */
public class SAMLToolsConfigLoader {

    private static Log logger =
        LogFactory.getLog(SAMLToolsConfigLoader.class.getName());

    private static File cachedConfigFile = null;
    private static SAMLToolsConfig toolConfig = null;

    /**
     * A regular expression used to parse an
     * Attribute* property name in the config file.
     */
    // use Pattern.quote (requires JDK 1.5)
    private static final String ATTRIBUTE_REGEX =
        "^Attribute\\.([^.]+)\\.([^.]+)$";

    /**
     * The compiled regular expression used to parse
     * an Attribute* property.
     */
    private static final Pattern ATTRIBUTE_PATTERN;

    static {

        // pre-compile the regular expression:
        try {
            ATTRIBUTE_PATTERN = Pattern.compile(ATTRIBUTE_REGEX);
        } catch (PatternSyntaxException e) {
            throw e;
        }
    }

    private SAMLToolsConfigLoader() {}

    /**
     * Gets the SAML Tools configuration object.
     * If the config object is null (which it is, initially),
     * this method loads the default config file specified in
     * the bootstrap properties file and returns the resulting
     * config object.  Thus this method is guaranteed to return
     * a non-null config object.
     *
     * @return the (non-null) configuration object
     * @exception org.globus.gridshib.common.GridShibConfigException
     *            if there was an error loading the default config file
     *
     * @see org.globus.gridshib.config.BootstrapConfigLoader#getConfigFileDefault()
     */
    public static SAMLToolsConfig getToolConfig()
                                         throws GridShibConfigException {

        if (toolConfig == null) {
            load();
        }
        return toolConfig;
    }

    /**
     * Gets the SAML Tools configuration object.
     * If the config object is null (which it is, initially),
     * this method loads the given config file and returns
     * the resulting config object.  Thus this method is
     * guaranteed to return a non-null config object.
     *
     * @param defaultConfigFile a default config file to load
     *        if the configuration object is null
     * @return the (non-null) configuration object
     * @exception org.globus.gridshib.common.GridShibConfigException
     *            if there was an error loading the given config file
     *
     * @see org.globus.gridshib.config.BootstrapConfigLoader#getConfigFileDefault()
     */
    public static SAMLToolsConfig getToolConfig(File defaultConfigFile)
                                         throws GridShibConfigException {

        if (toolConfig == null) {
            load(defaultConfigFile);
        }
        return toolConfig;
    }

    /**
     * A convenience method that loads the default config file
     * specified in the bootstrap properties file.
     *
     * @exception org.globus.gridshib.common.GridShibConfigException
     *            if there was an error loading the default config file
     *
     * @see org.globus.gridshib.config.BootstrapConfigLoader#getConfigFileDefault()
     *
     * @since 0.4.3
     */
    public static void load()
                     throws GridShibConfigException {

        load((File)null);
    }

    /**
     * Load the properties from the given config file.
     * If the given config file is null, load the default
     * config file specified in the bootstrap properties
     * file.
     *
     * @param configFile the config file to be loaded
     *
     * @exception org.globus.gridshib.common.GridShibConfigException
     *            if there was an error loading the indicated config file
     *
     * @see org.globus.gridshib.config.BootstrapConfigLoader#getConfigFileDefault()
     */
    public static void load(File configFile)
                     throws GridShibConfigException {

        if (configFile == null) {
            File file = BootstrapConfigLoader.getConfigFileDefault();
            if (file == null) {
                String msg = "Configuration error: " +
                             "default config file is not specified";
                throw new GridShibConfigException(msg);
            }
            if (cachedConfigFile == null || !cachedConfigFile.equals(file)) {
                logger.info("Loading default config file: " +
                            file.toString());
                cachedConfigFile = file;
            } else {
                logger.info("Default config file already loaded: " +
                            cachedConfigFile.toString());
                return;
            }
        } else {
            if (cachedConfigFile == null ||
                !cachedConfigFile.equals(configFile)) {
                logger.info("Loading config file: " +
                            configFile.toString());
                cachedConfigFile = configFile;
            } else {
                logger.info("Config file already loaded: " +
                            cachedConfigFile.toString());
                logger.info("Skipping config file: " +
                            configFile.toString());
                return;
            }
        }

        // create new config object:
        toolConfig = new SAMLToolsConfig();

        InputStream in = null;
        try {
            in = new FileInputStream(cachedConfigFile);
            loadProperties(in);
        } catch (FileNotFoundException e) {
            String msg = "File not found: ";
            msg += e.getMessage();
            logger.error(msg);
            throw new GridShibConfigException(msg);
        //} catch (IOException e) {
        //    String msg = "Unable to load config properties file: ";
        //    msg += e.getMessage();
        //    logger.error(msg);
        //    throw new GridShibConfigException(msg);
        } finally {
            if (in != null) {
                try { in.close(); } catch (IOException e) {}
            }
        }
    }

    /**
     * Load the properties from the given input stream.
     * In effect this method initializes the current
     * config object with the loaded config properties.
     * <p>
     * This method clears the cache, that is, the next
     * call to {@link #load(File)} is guaranteed not to
     * short-circuit.
     *
     * @param in an input stream of config properties
     * @exception org.globus.gridshib.common.GridShibConfigException
     *            if there was an error loading the config properties
     *            on the input stream
     */
    public static void load(InputStream in)
                     throws GridShibConfigException {

        // create new config object:
        toolConfig = new SAMLToolsConfig();
        overlay(in);
    }

    /**
     * Overlays the config properties on the given input
     * stream on top of the existing configuration object.
     * Each property value defaults to the current property
     * value, which in effect loads properties on top of
     * existing properties.
     * <p>
     * If this method is called without previously loading
     * any config properties, the effect is the same as
     * calling {@link #load(InputStream)}.
     * <p>
     * This method clears the cache, that is, the next
     * call to {@link #load(File)} is guaranteed not to
     * short-circuit.
     *
     * @param in an input stream of config properties
     * @exception org.globus.gridshib.common.GridShibConfigException
     *            if there was an error loading the config properties
     *            on the input stream
     *
     * @since 0.4.3
     */
    public static void overlay(InputStream in)
                        throws GridShibConfigException {

        if (toolConfig == null) { load(in); }
        cachedConfigFile = null;  // clear the cache
        loadProperties(in);
    }

    private static void loadProperties(InputStream in)
                                throws GridShibConfigException {

        Properties props = new Properties();
        try {
            props.load(in);
        } catch (IOException e) {
            String msg = "Unable to load properties: ";
            msg += e.getMessage();
            logger.error(msg);
            throw new GridShibConfigException(msg);
        }

        // get IdP.entityID property:
        String propName = "IdP.entityID";
        String propValue =
            props.getProperty(propName, toolConfig.getEntityID());
        toolConfig.setEntityID(propValue);
        logger.debug("Using " + propName + ": " + propValue);

        // get NameID.Format property:
        String propName1 = "NameID.Format";
        String propValue1 =
            props.getProperty(propName1, toolConfig.getFormat());

        // get NameID.Format.template property:
        String propName2 = "NameID.Format.template";
        String propValue2 =
            props.getProperty(propName2, toolConfig.getTemplate());

        // set the format and its template:
        if (propValue1 != null && propValue2 != null) {
            toolConfig.setFormat(propValue1);
            logger.debug("Using " + propName1 + ": " + propValue1);
            toolConfig.setTemplate(propValue2);
            logger.debug("Using " + propName2 + ": " + propValue2);
        } else {
            logger.debug("Ignoring " + propName1);
            logger.debug("Ignoring " + propName2);
        }

        // get NameID.NameQualifier property:
        propName = "NameID.NameQualifier";
        propValue =
            props.getProperty(propName, toolConfig.getNameQualifier());
        toolConfig.setNameQualifier(propValue);
        logger.debug("Using " + propName + ": " + propValue);

        // get dateTime.pattern property:
        propName = "dateTime.pattern";
        propValue =
            props.getProperty(propName, toolConfig.getDateTimePattern());
        toolConfig.setDateTimePattern(propValue);
        logger.debug("Using " + propName + ": " + propValue);

        // get certLocation property:
        propName1 = "certLocation";
        propValue1 = props.getProperty(propName1);

        // get keyLocation property:
        propName2 = "keyLocation";
        propValue2 = props.getProperty(propName2);

        // get certPath property:
        String propName3 = "certPath";
        String propValue3 = props.getProperty(propName3);

        // get keyPath property:
        String propName4 = "keyPath";
        String propValue4 = props.getProperty(propName4);

        File certFile = null;
        File keyFile = null;
        // either both (or none) locations is accepted:
        if (propValue1 != null && propValue2 != null) {

            if (propValue3 != null || propValue4 != null) {
                String msg = "Both locations and paths for certs and keys " +
                             "are not allowed";
                logger.error(msg);
                throw new GridShibConfigException(msg);
            }

            logger.debug("Using " + propName1 + ": " + propValue1);
            logger.debug("Using " + propName2 + ": " + propValue2);

            try {
                certFile = new FileLocation(propValue1).toFile();
                keyFile = new FileLocation(propValue2).toFile();
            } catch (IOException e) {
                String msg = "IO error: " + e.getMessage();
                logger.error(msg, e);
                throw new GridShibConfigException(msg, e);
            }
        } else if (propValue1 == null && propValue2 == null) {

            // either both (or none) paths is accepted:
            if (propValue3 != null && propValue4 != null) {

                logger.debug("Using " + propName3 + ": " + propValue3);
                logger.debug("Using " + propName4 + ": " + propValue4);

                certFile = new File(propValue3);
                keyFile = new File(propValue4);
            } else if (propValue3 == null && propValue4 == null) {

                if (toolConfig.getCredential() == null) {
                    X509Credential credentialDefault =
                        BootstrapConfigLoader.getCredentialDefault();
                    // set default credential property:
                    toolConfig.setCredential(credentialDefault);
                }
                cachedConfigFile = null;  // clear the cache
            } else {

                String msg = "Both (or none) of certPath and keyPath " +
                             "are required";
                logger.error(msg);
                throw new GridShibConfigException(msg);
            }
        } else {

            String msg = "Both (or none) of certLocation and keyLocation " +
                         "are required";
            logger.error(msg);
            throw new GridShibConfigException(msg);
        }

        if (certFile != null && keyFile != null) {

            // set the issuing credential:
            X509Credential credential = null;
            try {
                credential = GSIUtil.getCredential(certFile, keyFile);
            } catch (CredentialException e) {
                String msg = "Unable to obtain configured issuing " +
                             "credential";
                logger.error(msg, e);
                throw new GridShibConfigException(msg, e);
            }
            toolConfig.setCredential(credential);
        }

        if (toolConfig.getCredential() == null) {
            String msg = "Issuing credential not configured";
            logger.warn(msg);
        } else {
            String msg = "Using issuing credential: " +
                  toolConfig.getCredential().toString();
            logger.debug(msg);
        }

        loadAttributes(props);
    }

    /**
     * Load a static list of attributes.
     */
    private static void loadAttributes(Properties props)
                                throws GridShibConfigException {

        String propName;  // a property name

        /* Let  S  be the set of all strings.
         * For  s  in  S , let  g(s) = f_s  where
         *
         *   f("Namespace") := Attribute/@Namespace
         *   f("Name")      := Attribute/@Name
         *   f("Value")     := Attribute/AttributeValue
         *
         * For example, if  s = "NVO" ,
         *
         *   g(s)("Namespace")
         *     = f_s("Namespace")
         *     = "urn:mace:shibboleth:1.0:attributeNamespace:uri"
         *
         *   g(s)("Name")
         *     = f_s("Name")
         *     = "urn:mace:dir:attribute-def:isMemberOf"
         *
         *   g(s)("Value")
         *     = f_s("Value")
         *     = "http://www.us-vo.org/"
         */
        Matcher matcher;
        Map g = new HashMap();
        Enumeration propNames = props.propertyNames();
        while (propNames.hasMoreElements()) {
            propName = (String)propNames.nextElement();
            if (propName.startsWith("Attribute.")) {
                matcher = ATTRIBUTE_PATTERN.matcher(propName);
                if (!matcher.find()) {
                    String msg = "Property syntax error: " + propName;
                    logger.warn(msg);
                    continue;
                }
                logger.debug("Matched property name: " + propName);
                String s = matcher.group(1);  // label
                String x = matcher.group(2);  // (namespace|name|value)
                String y = props.getProperty(propName);
                logger.debug("Matched property value: " + y);
                if (g.get(s) == null) {
                    g.put(s, new F());
                }
                g.put(s, ((F)g.get(s)).set(x, y));
            }
        }
        for (Iterator i = g.values().iterator(); i.hasNext();) {
            F f = (F)i.next();
            String name = f.getName();
            String value = f.getValue();
            if (name == null || value == null) {
                String msg = "Null attribute name or value";
                logger.warn(msg);
                continue;
            }
            String namespace = f.getNamespace();
            if (namespace == null) {
                namespace = Constants.SHIB_ATTRIBUTE_NAMESPACE_URI;
            }
            try {
                SimpleAttribute attribute =
                    new SimpleAttribute(namespace,
                                        name,
                                        value.split("\\t"));
                toolConfig.addAttribute(attribute);
            } catch (SAMLException e) {
                String msg = "Unable to create attribute " + name;
                logger.error(msg);
                throw new GridShibConfigException(msg);
            }
        }
    }
}

/**
 * A convenience class that encapsulates an
 * attribute triple (Namespace, Name, Value).
 */
class F {

    private String name = null;
    private String value = null;
    private String namespace = null;

    String getName() { return name; }
    String getValue() { return value; }
    String getNamespace() { return namespace; }

    F set(String propName, String propValue) {
        if (propName.equals("Name")) {
            name = propValue;
        } else if (propName.equals("Value")) {
            value = propValue;
        } else if (propName.equals("Namespace")) {
            namespace = propValue;
        }
        return this;
    }
}
