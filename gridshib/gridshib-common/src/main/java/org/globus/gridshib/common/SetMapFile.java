/*
 * Copyright 2007-2009 University of Illinois
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

package org.globus.gridshib.common;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.LoadException;
import org.globus.gridshib.common.LoadableResource;

/**
 * An implementation of the <code>Loadable</code> interface
 * for maps of <code>String</code> into <code>Set</code>
 * (of <code>String</code>).
 *
 * @see org.globus.gridshib.common.Loadable
 * @see org.globus.gridshib.common.LoadableResource
 *
 * @since 0.5.1
 */
public class SetMapFile extends LoadableResource  {

    private static Log logger =
        LogFactory.getLog(SetMapFile.class.getName());

    /**
     * A list of <code>SetMapFile</code> instances
     * maintained by {@link #getInstance(File)}.
     */
    private static List instances;

    /**
     * Creates a <code>File</code> object from the given
     * <code>URI</code> instance and invokes
     * {@link #getInstance(File)}.
     *
     * @param uri the URI of the file that backs
     *            this instance of <code>SetMapFile</code>
     * @return    the one and only one <code>SetMapFile</code>
     *            instance that corresponds to the given URI
     * @exception org.globus.gridshib.common.LoadException
     *            if a new instance of <code>SetMapFile</code>
     *            is required but the file fails to load
     */
    public static SetMapFile getInstance(URI uri)
                                  throws LoadException {

        return getInstance(new File(uri));
    }

    /**
     * Creates a <code>File</code> object from the given
     * <code>pathname</code> and invokes
     * {@link #getInstance(File)}.
     *
     * @param pathname the pathname of the file that backs
     *                 this instance of <code>SetMapFile</code>
     * @return         the one and only one <code>SetMapFile</code>
     *                 instance that corresponds to the given pathname
     * @exception      org.globus.gridshib.common.LoadException
     *                 if a new instance of <code>SetMapFile</code>
     *                 is required but the file fails to load
     */
    public static SetMapFile getInstance(String pathname)
                                  throws LoadException {

        return getInstance(new File(pathname));
    }

    /**
     * Gets <em>the</em> instance of <code>SetMapFile</code>
     * that corresponds to the given file.  Such an instance
     * may have been created previously, in which case that
     * instance is returned directly.  Otherwise, a new instance
     * of <code>SetMapFile</code> is created and returned.
     * <p>
     * Use of this method (as opposed to the direct use of the
     * constructor) prevents needless reloading of a file that
     * may have already been loaded.
     *
     * @param file the file that backs this instance of
     *             <code>SetMapFile</code>
     * @return     the one and only one <code>SetMapFile</code>
     *             instance that corresponds to the given file
     * @exception  org.globus.gridshib.common.LoadException
     *             if a new instance of <code>SetMapFile</code>
     *             is required but the file fails to load
     *
     * @see #SetMapFile(File)
     */
    public static SetMapFile getInstance(File file)
                                  throws LoadException {

        SetMapFile setMap;
        for (int i = 0; i < instances.size(); i++) {
            setMap = (SetMapFile)(instances.get(i));
            if (setMap.resource.equals(file)) {
                logger.debug("Obtained existing instance");
                return setMap;
            }
        }
        setMap = new SetMapFile(file);
        logger.debug("Created new instance");
        if (instances.add(setMap)) {
            logger.debug("Storing new instance");
        } else {
            logger.debug("Instance previously created");
        }
        return setMap;
    }

    // TODO: use Pattern.quote (requires JDK 1.5)

    /**
     * An <code>UNQUOTED_FORM</code> is a field that has
     * no embedded whitespace, so it need not be quoted.
     */
    final private static String UNQUOTED_FORM =
        "([^ \\t]+)";

    /**
     * A <code>QUOTED_FORM</code> is a field that has
     * embedded whitespace, so it must be quoted.
     */
    final private static String QUOTED_FORM =
        "\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"";

    /**
     * A regular expression used to parse the first
     * field of each line of the map file.  The field
     * may be a <code>QUOTED_FORM</code> or an
     * <code>UNQUOTED_FORM</code>.
     */
    final private static String FIRST_DATA_FIELD_REGEX =
        "[ \\t]*" + QUOTED_FORM + "|" + UNQUOTED_FORM;

    /**
     * A regular expression used to parse the next
     * field (starting with the second field) of each
     * line of the map file.  This regular expression is
     * identical to <code>FIRST_DATA_FIELD_REGEX</code>
     * except that the next field must be preceded by
     * at least one whitespace character.
     */
    final private static String NEXT_DATA_FIELD_REGEX =
        "[ \\t]" + FIRST_DATA_FIELD_REGEX;

    /**
     * A regular expression for a comment or a blank
     * line, both of which are ignored by the parser.
     */
    final private static String IGNORED_LINE_REGEX =
        "^[ \\t]*(?:\\#.*)?$";

    /**
     * The compiled regular expression used to parse
     * <code>FIRST_DATA_FIELD_REGEX</code>.
     */
    final private static Pattern firstDataField;

    /**
     * The compiled regular expression used to parse
     * <code>NEXT_DATA_FIELD_REGEX</code>.
     */
    final private static Pattern nextDataField;

    /**
     * The compiled regular expression used to parse
     * <code>IGNORED_LINE_REGEX</code>.
     */
    final private static Pattern ignoredLine;

    static {

        instances = new ArrayList();

        // compile the regular expressions:
        try {
            firstDataField = Pattern.compile(FIRST_DATA_FIELD_REGEX);
        } catch (PatternSyntaxException e) {
            logger.error("Invalid regex: " + FIRST_DATA_FIELD_REGEX);
            throw e;
        }
        try {
            nextDataField = Pattern.compile(NEXT_DATA_FIELD_REGEX);
        } catch (PatternSyntaxException e) {
            logger.error("Invalid regex: " + NEXT_DATA_FIELD_REGEX);
            throw e;
        }
        try {
            ignoredLine = Pattern.compile(IGNORED_LINE_REGEX);
        } catch (PatternSyntaxException e) {
            logger.error("Invalid regex: " + IGNORED_LINE_REGEX);
            throw e;
        }
    }

    /**
     * This <code>SetMapFile</code> instance is backed by a
     * <code>Map</code>, specifically, a <code>Map</code> of
     * <code>String</code> objects into a <code>Set</code>
     * of <code>String</code> objects.  This is called a
     * <code>SetMapFile</code>.
     */
    private Map setMap;

    /**
     * Get the <code>Map</code> backing this
     * <code>SetMapFile</code> instance.
     */
    Map getSetMap() { return this.setMap; }

    /**
     * A convenience constructor that simply converts its
     * <code>URI</code> argument into a <code>File</code>
     * object, and then calls the corresponding constructor.
     *
     * @param uri the URI of the file that backs
     *            this instance of <code>SetMapFile</code>
     * @exception org.globus.gridshib.common.LoadException
     *            if the file that backs this instance of
     *            <code>SetMapFile</code> fails to load
     */
    public SetMapFile(URI uri) throws LoadException {
        this(new File(uri));
    }

    /**
     * A convenience constructor that simply converts its
     * <code>String</code> argument into a <code>File</code>
     * object, and then calls the corresponding constructor.
     *
     * @param pathname the pathname of the file that backs
     *                 this instance of <code>SetMapFile</code>
     * @exception      org.globus.gridshib.common.LoadException
     *                 if the file that backs this instance of
     *                 <code>SetMapFile</code> fails to load
     */
    public SetMapFile(String pathname) throws LoadException {
        this(new File(pathname));
    }

    /**
     * The primary constructor for obtaining an instance
     * of <code>SetMapFile</code>.  Captures the given
     * <code>File</code> object and loads the file.
     *
     * @param file the file that backs this instance of
     *             <code>SetMapFile</code>
     * @exception  org.globus.gridshib.common.LoadException
     *             if the file that backs this instance of
     *             <code>SetMapFile</code> fails to load
     *
     * @see #load()
     */
    public SetMapFile(File file) throws LoadException {

        if (file == null) {
            String msg = "Null argument";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }
        if (!file.exists()) {
            String msg = "File (" + file.toString() + ") does not exist";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }
        if (!file.isFile()) {
            String msg = "File (" + file.toString() + ") is not a file";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }
        logger.debug("Creating new instance");

        this.lastLoaded = 0;  // guarantees isStale() ==> true
        this.resource = file;
        this.load();
    }

    /**
     * Gets all the (<code>String</code>) keys
     * associated with this instance.
     * If this <code>Loadable</code> file is stale,
     * reload it first.
     *
     * @return    the (possibly empty) set of keys associated
     *            with this <code>SetMapFile</code> instance
     * @exception org.globus.gridshib.common.LoadException
     *            If unable to reload the (stale)
     *            <code>Loadable</code> object
     */
    public Set getKeySet() throws LoadException {

        // if necessary, reload the resource:
        if (isStale()) {
            logger.info("Reloading stale resource");
            load();
        }

        Set keys = this.setMap.keySet();

        logger.debug("This SetMapFile instance contains " +
                     "a total of " + keys.size() + " keys");

        return keys;
    }

    /**
     * Gets the set of string values that corresponds to the
     * given key.  If this <code>Loadable</code> file is stale,
     * reload it first.
     *
     * @param key a string key
     * @return    the (possibly empty) set of string values
     *            corresponding to the given key, or null if
     *            the map does not contain the given key
     * @exception org.globus.gridshib.common.LoadException
     *            If unable to reload the (stale)
     *            <code>Loadable</code> object
     */
    public Set getImageSet(String key) throws LoadException {

        // if necessary, reload the resource:
        if (isStale()) {
            logger.info("Reloading stale resource");
            load();
        }

        if (this.setMap.containsKey(key)) {
            Set values = (HashSet)this.setMap.get(key);
            String msg = "This SetMapFile instance contains ordered pair " +
                         "(" + key + ", " + values.toString() + ")";
            logger.debug(msg);
            return values;
        } else {
            String msg = "This SetMapFile instance does not " +
                         "contain key (" + key + ")";
            logger.debug(msg);
            return null;
        }
    }

    /**
     * Loads this file resource and calls {@link #resetLastLoaded()}.
     *
     * @exception  org.globus.gridshib.common.LoadException
     *             if the file that backs this instance of
     *             <code>SetMapFile</code> fails to load
     *
     * @see org.globus.gridshib.common.Loadable
     */
    public void load() throws LoadException {

        logger.debug("Reinitializing SetMapFile");
        this.setMap = new HashMap();

        logger.debug("Loading file: " + this.resource.toString());
        try {
            loadFile();
        } catch (IOException e) {
            String msg = "Unable to load file: " + this.resource.toString();
            logger.error(msg, e);
            throw new LoadException(msg, e);
        }
        logger.debug("File loaded: " + this.resource.toString());
        resetLastLoaded();
    }

    /**
     * Loads this file resource.  Does all the heavy
     * lifting, including opening, reading, parsing, and
     * closing the file.
     *
     * @exception  java.io.IOException
     *             if an I/O error occurs
     * @exception  org.globus.gridshib.common.LoadException
     *             if the file can not be parsed
     */
    private void loadFile() throws IOException, LoadException {

        File file = this.resource;
        assert (file.exists() && file.isFile());

        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;
        Matcher matcher;
        String key, value;
        HashSet values, oldValues;
        while ((line = reader.readLine()) != null) {
            line = line.trim();

            // ignore comment or blank line:
            if (ignoredLine.matcher(line).matches()) {
                logger.debug("line ignored: " + line);
                continue;
            }

            // initialize matcher to use firstDataField pattern:
            int i = 0;  // value counter
            matcher = firstDataField.matcher(line);
            logger.debug("matcher " + i + ": " + matcher.toString());
            logger.info("matching against line: [" + line + "]");

            // extract key from input line:
            key = find(matcher);
            if (key == null) {
                String msg = "Key is null";
                logger.error(msg);
                throw new LoadException(msg);
            }
            logger.debug("Map key: " + key);

            values = new HashSet();
            while (true) {

                // reset matcher to use nextDataField pattern
                //
                // Note: Matcher.usePattern(Pattern) requires J2SE 5.0.
                //
                //matcher = matcher.usePattern(nextDataField);
                //
                // A workaround is to reinitialize this matcher
                // based on a tail of the input string:
                line = line.substring(matcher.end());
                matcher = nextDataField.matcher(line);
                logger.debug("matcher " + (i + 1) + ": " + matcher.toString());
                logger.debug("matching against tail: [" + line + "]");

                // extract value from input line:
                value = find(matcher);
                if (value == null) {
                    String msg = "Found " + i + " value" +
                                 ((i == 1) ? "" : "s");
                    logger.debug(msg);
                    break;
                }

                if (values.add(value)) {
                    logger.debug("Value " + (++i) + " added to image set: " +
                                 value);
                } else {
                    logger.warn("Ignoring duplicate value: " + value);
                }
            }

            // add the ordered pair to the map:
            oldValues = (HashSet)this.setMap.put(key, values);
            String msg =
                "Map entry added: (" + key + ", " + values.toString() + ")";
            logger.info(msg);
            if (oldValues != null) {
                logger.warn("Replaced image set: " + oldValues.toString());
            }
        }
        reader.close();
    }

    /**
     * Given a particular matcher, find a match (if possible).
     * If the matcher finds a <code>QUOTED_FORM</code>, all
     * escaped characters are replaced with their literal selves.
     *
     * @param matcher the matcher used for matching
     * @return        the matched string value, or null if no
     *                match is found
     */
    private static String find(Matcher matcher) {
        if (!matcher.find()) { return null; }
        String quoted = matcher.group(1);
        String unquoted = matcher.group(2);
        if (quoted != null) {
            // unescape quoted characters:
            return quoted.replaceAll("\\\\(.)", "$1");
        }
        return unquoted;
    }
}
