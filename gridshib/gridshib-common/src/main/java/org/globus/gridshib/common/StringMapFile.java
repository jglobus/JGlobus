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
 * for string maps, that is maps of <code>String</code>
 * into <code>String</code>.
 *
 * @see org.globus.gridshib.common.Loadable
 * @see org.globus.gridshib.common.LoadableResource
 */
public class StringMapFile extends LoadableResource  {

    private static Log logger =
        LogFactory.getLog(StringMapFile.class.getName());

    /**
     * A list of <code>StringMapFile</code> instances
     * maintained by #getInstance(String) and #getInstance(URI).
     */
    private static List instances;

    /**
     * Creates a <code>File</code> object from the given
     * <code>URI</code> instance and invokes #getInstance(File).
     *
     * @param uri the URI of the file that backs
     *        this instance of <code>StringMapFile</code>
     * @return the one and only one <code>StringMapFile</code>
     *         instance that corresponds to the given URI
     * @exception org.globus.gridshib.common.LoadException
     *            if a new instance of <code>StringMapFile</code>
     *            is required but the file fails to load
     */
    public static StringMapFile getInstance(URI uri)
                                     throws LoadException {

        return getInstance(new File(uri));
    }

    /**
     * Creates a <code>File</code> object from the given
     * <code>pathname</code> and invokes #getInstance(File).
     *
     * @param pathname the pathname of the file that backs
     *        this instance of <code>StringMapFile</code>
     * @return the one and only one <code>StringMapFile</code>
     *         instance that corresponds to the given pathname
     * @exception org.globus.gridshib.common.LoadException
     *            if a new instance of <code>StringMapFile</code>
     *            is required but the file fails to load
     */
    public static StringMapFile getInstance(String pathname)
                                     throws LoadException {

        return getInstance(new File(pathname));
    }

    /**
     * Gets <em>the</em> instance of <code>StringMapFile</code>
     * that corresponds to the given file.  Such an instance
     * may have been created previously, in which case that
     * instance is returned directly.  Otherwise, a new instance
     * of <code>StringMapFile</code> is created and returned.
     * <p>
     * Use of this method (as opposed to the direct use of the
     * constructor) prevents needless reloading of a file that
     * may have already been loaded.
     *
     * @param file the file that backs this instance of
     *        <code>StringMapFile</code>
     * @return the one and only one <code>StringMapFile</code>
     *         instance that corresponds to the given file
     * @exception org.globus.gridshib.common.LoadException
     *            if a new instance of <code>StringMapFile</code>
     *            is required but the file fails to load
     *
     * @see #StringMapFile(File)
     */
    public static StringMapFile getInstance(File file)
                                     throws LoadException {

        StringMapFile stringMap;
        for (int i = 0; i < instances.size(); i++) {
            stringMap = (StringMapFile)(instances.get(i));
            if (stringMap.resource.equals(file)) {
                logger.debug("Obtained existing instance");
                return stringMap;
            }
        }
        stringMap = new StringMapFile(file);
        logger.debug("Created new instance");
        if (instances.add(stringMap)) {
            logger.debug("Storing new instance");
        } else {
            logger.debug("Instance previously created");
        }
        return stringMap;
    }

    /**
     * A regular expression used to parse the first
     * field of each line of the file.
     */
    // TODO: use Pattern.quote (requires JDK 1.5)
    private static final String UNQUOTED_FORM =
        "([^ \\t]+)";
    private static final String QUOTED_FORM =
        "\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"";
    private static final String FIRST_DATA_FIELD_REGEX =
        "[ \\t]*" + QUOTED_FORM + "|" + UNQUOTED_FORM;

    /**
     * A regular expression used to parse the second
     * field of each line of the grid-mapfile.  This
     * regular expression is identical to that used to
     * parse the first field except that the second
     * field must be preceded by at least one whitespace
     * character.
     */
    private static final String NEXT_DATA_FIELD_REGEX =
        "[ \\t]" + FIRST_DATA_FIELD_REGEX;

    /**
     * A comment or a blank line
     */
    private static final String IGNORED_LINE_REGEX =
        "^[ \\t]*(?:\\#.*)?$";

    /**
     * The compiled regular expression used to parse
     * the first field of a file.
     */
    private static Pattern firstDataField;

    /**
     * The compiled regular expression used to parse
     * the second field of a gridmap file.
     */
    private static Pattern nextDataField;

    /**
     * The compiled regular expression used to parse
     * a line to be ignored in each line of the file.
     */
    private static Pattern ignoredLine;

    /**
     * Static (one-time) initialization
     */
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
     * This implementation is backed by a <code>Map</code>,
     * specifically, a <code>Map</code> of <code>String</code>
     * objects into <code>String</code> objects.  This is
     * called a <code>StringMap</code>.
     */
    private Map stringMap;

    /**
     * Get the <code>StringMap</code> backing this
     * <code>StringMapFile</code> instance.
     */
    Map getStringMap() { return this.stringMap; }

    /**
     * A convenience constructor that simply converts its
     * <code>URI</code> argument into a <code>File</code> object,
     * and then calls the corresponding constructor.
     *
     * @param uri the URI of the file that backs
     *            this instance of <code>StringMapFile</code>
     * @exception org.globus.gridshib.common.LoadException
     *            if the file that backs this instance of
     *            <code>StringMapFile</code> fails to load
     */
    public StringMapFile(URI uri) throws LoadException {
        this(new File(uri));
    }

    /**
     * A convenience constructor that simply converts its
     * <code>String</code> argument into a <code>File</code> object,
     * and then calls the corresponding constructor.
     *
     * @param pathname the pathname of the file that backs
     *                 this instance of <code>StringMapFile</code>
     * @exception      org.globus.gridshib.common.LoadException
     *                 if the file that backs this instance of
     *                 <code>StringMapFile</code> fails to load
     */
    public StringMapFile(String pathname) throws LoadException {
        this(new File(pathname));
    }

    /**
     * The primary constructor for obtaining an instance of
     * <code>StringMapFile</code>.  Captures the given
     * <code>File</code> object and loads the file.
     *
     * @param file the file that backs this instance of
     *             <code>StringMapFile</code>
     * @exception  org.globus.gridshib.common.LoadException
     *             if the file that backs this instance of
     *             <code>StringMapFile</code> fails to load
     *
     * @see #load()
     */
    public StringMapFile(File file) throws LoadException {

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
        /*
        if (instances.add(this)) {
            logger.debug("Storing new instance");
        } else {
            logger.debug("Instance previously created");
        }
        */
    }

    /**
     * Gets all the (<code>String</code>) keys
     * associated with this instance.
     * If this <code>Loadable</code> object is stale,
     * reload it first.
     *
     * @return the keys associated with this
     *         <code>StringMapFile</code> instance
     * @exception org.globus.gridshib.common.LoadException
     *            If unable to reload the <code>Loadable</code>
     *            object (if stale)
     */
    public Set getKeySet() throws LoadException {

        // if necessary, reload the resource:
        if (isStale()) {
            logger.info("Reloading stale resource");
            load();
        }

        Set set = this.stringMap.keySet();

        logger.debug("This StringMapFile instance contains " +
                     "a total of " + set.size() + " keys");

        return set;
    }

    /**
     * Gets the string value that corresponds to the given
     * key.  If this <code>Loadable</code> object is stale,
     * reload it first.
     *
     * @param key a string key
     * @return the string value corresponding to the given key
     * @exception org.globus.gridshib.common.LoadException
     *            If unable to reload the <code>Loadable</code>
     *            object (if stale)
     */
    public String get(String key) throws LoadException {

        // if necessary, reload the resource:
        if (isStale()) {
            logger.info("Reloading stale resource");
            load();
        }

        String value = (String)this.stringMap.get(key);

        if (logger.isDebugEnabled()) {
            if (value == null) {
                String msg = "This StringMapFile instance does not " +
                             "contain key \"" + key + "\"";
                logger.debug(msg);
            } else {
                String msg = "This StringMapFile instance contains " +
                             "map entry " +
                             "(" + key + ", " + value + ")";
                logger.debug(msg);
            }
        }

        return value;
    }

    /**
     * Loads the file and calls #resetLastLoaded().
     *
     * @see org.globus.gridshib.common.Loadable
     */
    public void load() throws LoadException {

        logger.debug("Reinitializaing StringMap");
        this.stringMap = new HashMap();

        logger.debug("Loading file...");
        try {
            load(this.resource);
        } catch (IOException e) {
            String msg = "Unable to load file: ";
            logger.error(msg);
            throw new LoadException(msg + e.getMessage());
        }
        logger.debug("File loaded.");
        resetLastLoaded();
    }

    private void load(File file) throws IOException, LoadException {

        assert (file.exists() && file.isFile());

        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;
        Matcher matcher;
        String key, value, oldValue;
        while ((line = reader.readLine()) != null) {
          line = line.trim();

          // ignore if comment or blank line:
          if (ignoredLine.matcher(line).matches()) {
              logger.debug("line ignored: " + line);
              continue;
          }

          // initialize matcher to use firstDataField pattern:
          matcher = firstDataField.matcher(line);
          logger.debug("matcher1: " + matcher.toString());

          // extract key from input line:
          key = find(matcher);
          if (key == null) {
              String msg = "Key is null";
              logger.error(msg);
              throw new LoadException(msg);
          }
          logger.debug("Map key: " + key);

          /*
           * Matcher.usePattern(Pattern) requires J2SE 5.0.
           * A workaround is to reinitialize this matcher based
           * on a new pattern and a tail of the input string.
           */

          // reset matcher to use nextDataField pattern:
          //matcher = matcher.usePattern(nextDataField);
          matcher = nextDataField.matcher(line.substring(matcher.end()));
          logger.debug("matcher2: " + matcher.toString());

          // extract value from input line:
          value = find(matcher);
          if (value == null) {
              String msg = "Unable to parse file " + file.toString();
              logger.error(msg);
              throw new LoadException(msg);
          }
          logger.debug("Map value: " + value);

          // add the ordered pair to the map:
          oldValue = (String)this.stringMap.put(key, value);
          logger.info("Map entry added: (" + key + ", " + value + ")");
          if (oldValue != null) {
              logger.warn("Replaced old map value: " + oldValue);
          }
        }
        reader.close();
    }

    /**
     * Given a particular matcher, finds a match (if possible).
     * If the matcher finds a QUOTED_FORM, all escaped characters
     * are replaced with their literal selves.
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
