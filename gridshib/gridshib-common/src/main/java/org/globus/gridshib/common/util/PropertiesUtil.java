/*
 * Copyright 2008-2009 University of Illinois
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

package org.globus.gridshib.common.util;

import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Utilities for getting and resolving property values.
 *
 * @since 0.5.3
 */
public class PropertiesUtil {

    private static final Class CLASS = PropertiesUtil.class;
    private static final String CLASSNAME = CLASS.getName();
    private static Log logger = LogFactory.getLog(CLASSNAME);

    /**
     * A property value token of the form <code>${key}</code>
     */
    final private static String PROPERTY_VALUE_TOKEN =
        "\\$\\{([^}]+)\\}";

    /**
     * A property value that contains a property value token
     * is an unresolved property value
     */
    final private static Pattern unresolvedPropValue;

    static {

        // compile the regular expression:
        try {
            unresolvedPropValue = Pattern.compile(PROPERTY_VALUE_TOKEN);
        } catch (PatternSyntaxException e) {
            logger.error("Invalid regex: " + PROPERTY_VALUE_TOKEN);
            throw e;
        }
    }

    /**
     * Resolves all property value tokens of the form
     * <code>${key}</code> in the given property value.
     * If a property value token can not be resolved,
     * resolution is aborted and the given property
     * value is returned with one or more unresolved
     * tokens.
     *
     * @param props     the complete set of config properties
     * @param propValue the property value to be resolved
     *
     * @return the fully resolved property value (if possible)
     */
    public static String resolvePropValue(Properties props,
                                          String propValue) {

        Matcher matcher = unresolvedPropValue.matcher(propValue);
        if (matcher.find()) {
            // get the matched key:
            String key = matcher.group(1);
            // check the system properties for the key:
            String replacement = getSystemProperty(key, null);
            // check given properties for the key:
            if (replacement == null && props != null) {
                replacement = props.getProperty(key);
            }
            // if no value found, abort resolution of tokens:
            if (replacement == null) {
                String msg = "Unable to resolve property value token: " +
                             matcher.group(0);
                logger.debug(msg);
                return propValue;
            }
            // recurse on the replacement value:
            replacement = resolvePropValue(props, replacement);
            // quote replacement string:
            replacement = quoteReplacement(replacement);
            // replace the first occurrence of the token:
            String newPropValue = matcher.replaceFirst(replacement);
            // recurse on the new (partially resolved) property value:
            return resolvePropValue(props, newPropValue);
        } else {
            return propValue;
        }
    }

    /**
     * Returns a quoted replacement <code>String</code> for
     * the given replacement <code>String</code>.
     *
     * This method was introduced in JDK&nbsp;1.5, so it is
     * provided here for backward compatibility with JDK&nbsp;1.4.
     *
     * @param replacement The replacement string to be quoted
     * @return            A quoted replacement string
     *
     * @see java.util.regex.Matcher#quoteReplacement(String)
     */
    private static String quoteReplacement(String replacement) {

        if ((replacement.indexOf('\\') == -1) &&
            (replacement.indexOf('$') == -1)) { return replacement; }

        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < replacement.length(); i++) {
            char c = replacement.charAt(i);
            if (c == '\\' || c == '$') {
                sb.append('\\');
            }
            sb.append(c);
        }
        return sb.toString();
    }

    /**
     * Gets the value of a system property.
     * <p>
     * This convenience method is a wrapper around
     * {@link java.lang.System#getProperty(String, String)}.
     * If the latter throws a runtime exception, this method
     * returns the default property value.
     *
     * @param propName         the system property of interest
     * @param propValueDefault the default property value,
     *                         which may be null
     *
     * @return the requested system property value or the
     *         default property value if the requested
     *         system property is not found
     */
    public static String getSystemProperty(String propName,
                                           String propValueDefault) {
        try {
            return System.getProperty(propName, propValueDefault);
        } catch (RuntimeException e) {
            String msg = "Unable to get system property " + propName;
            logger.error(msg, e);
            return propValueDefault;
        }
    }

    /**
     * Gets the value of a property from a properties file.
     * If the value contains property value tokens
     * of the form <code>${key}</code>, the tokens are
     * resolved, if possible.
     * <p>
     * Invoking this method is equivalent to calling
     * {@link #getProperty(Properties, String, String, boolean)}
     * with a boolean argument of <code>true</code>, that is,
     * logging is enabled by default.
     *
     * @param props            the complete set of config properties
     * @param propName         the config property of interest
     * @param propValueDefault the default config property value,
     *                         which may be null
     *
     * @return the requested property value or the default
     *         property value if the requested property is
     *         not found
     *
     * @see #resolvePropValue(Properties, String)
     */
    public static String getProperty(Properties props,
                                     String propName,
                                     String propValueDefault) {

        return getProperty(props, propName, propValueDefault, true);
    }

    /**
     * Gets the value of a property from a properties file.
     * If the value contains property value tokens
     * of the form <code>${key}</code>, the tokens are
     * resolved, if possible.
     *
     * @param props            the complete set of config properties
     * @param propName         the config property of interest
     * @param propValueDefault the default config property value,
     *                         which may be null
     * @param enable           if disabled, no logging will be done
     *
     * @return the requested property value or the default
     *         property value if the requested property is
     *         not found
     *
     * @see #resolvePropValue(Properties, String)
     */
    public static String getProperty(Properties props,
                                     String propName,
                                     String propValueDefault,
                                     boolean enable) {

        String propValue = props.getProperty(propName);
        if (propValue == null) {
            String msg = "Property " + propName + " not found, ";
            msg += "using default value: " + propValueDefault;
            if (enable) { logger.info(msg); }
            return propValueDefault;
        } else if (propValue.equals("")) {
            String msg = "Property " + propName + " empty, ";
            msg += "using default value: " + propValueDefault;
            if (enable) { logger.warn(msg); }
            return propValueDefault;
        } else {
            String msg = "Property " + propName + " found: " + propValue;
            if (enable) { logger.info(msg); }
            return resolvePropValue(props, propValue);
        }
    }
}
