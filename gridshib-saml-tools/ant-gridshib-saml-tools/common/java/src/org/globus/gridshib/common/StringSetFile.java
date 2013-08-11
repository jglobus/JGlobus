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
import java.util.HashSet;
import java.util.List;
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
 * for sets of strings.
 *
 * @see org.globus.gridshib.common.Loadable
 * @see org.globus.gridshib.common.LoadableResource
 */
public class StringSetFile extends LoadableResource  {

    private static Log logger =
        LogFactory.getLog(StringSetFile.class.getName());

    /**
     * A list of <code>StringSetFile</code> instances
     * maintained by {@link #getInstance(String)} and
     * {@link #getInstance(URI)}.
     */
    private static List instances;

    /**
     * Creates a <code>File</code> object from the given
     * <code>URI</code> instance and invokes
     * {@link #getInstance(File)}.
     *
     * @param uri the URI of the file that backs
     *        this instance of <code>StringSetFile</code>
     * @return the one and only one <code>StringSetFile</code>
     *         instance that corresponds to the given URI
     * @exception org.globus.gridshib.common.LoadException
     *            if a new instance of <code>StringSetFile</code>
     *            is required but the file fails to load
     */
    public static StringSetFile getInstance(URI uri)
                                     throws LoadException {

        return getInstance(new File(uri));
    }

    /**
     * Creates a <code>File</code> object from the given
     * <code>pathname</code> and invokes
     * {@link #getInstance(File)}.
     *
     * @param pathname the pathname of the file that backs
     *        this instance of <code>StringSetFile</code>
     * @return the one and only one <code>StringSetFile</code>
     *         instance that corresponds to the given pathname
     * @exception org.globus.gridshib.common.LoadException
     *            if a new instance of <code>StringSetFile</code>
     *            is required but the file fails to load
     */
    public static StringSetFile getInstance(String pathname)
                                     throws LoadException {

        return getInstance(new File(pathname));
    }

    /**
     * Gets <em>the</em> instance of <code>StringSetFile</code>
     * that corresponds to the given file.  Such an instance
     * may have been created previously, in which case that
     * instance is returned directly.  Otherwise, a new instance
     * of <code>StringSetFile</code> is created and returned.
     * <p>
     * Use of this method (as opposed to direct use of the
     * constructor) prevents needless reloading of a file that
     * may have already been loaded.
     *
     * @param file the file that backs this instance of
     *        <code>StringSetFile</code>
     * @return the one and only one <code>StringSetFile</code>
     *         instance that corresponds to the given file
     * @exception org.globus.gridshib.common.LoadException
     *            if a new instance of <code>StringSetFile</code>
     *            is required but the file fails to load
     *
     * @see #StringSetFile(File)
     */
    public static StringSetFile getInstance(File file)
                                     throws LoadException {

        StringSetFile stringSet;
        for (int i = 0; i < instances.size(); i++) {
            stringSet = (StringSetFile)(instances.get(i));
            if (stringSet.resource.equals(file)) {
                logger.debug("Obtained existing instance");
                return stringSet;
            }
        }
        stringSet = new StringSetFile(file);
        logger.debug("Created new instance");
        if (instances.add(stringSet)) {
            logger.debug("Storing new instance");
        } else {
            logger.debug("Instance previously created");
        }
        return stringSet;
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
            ignoredLine = Pattern.compile(IGNORED_LINE_REGEX);
        } catch (PatternSyntaxException e) {
            logger.error("Invalid regex: " + IGNORED_LINE_REGEX);
            throw e;
        }
    }

    /**
     * This implementation is backed by a <code>Set</code>,
     * specifically, a <code>Set</code> of <code>String</code>
     * objects, otherwise called a <code>StringSet</code>.
     */
    private Set stringSet;

    /**
     * Get the <code>StringSet</code> backing this
     * <code>StringSetFile</code> instance.
     */
    Set getStringSet() { return this.stringSet; }

    /**
     * A convenience constructor that simply converts its
     * <code>URI</code> argument into a <code>File</code> object,
     * and then calls the corresponding constructor.
     */
    public StringSetFile(URI uri) throws LoadException {
        this(new File(uri));
    }

    /**
     * A convenience constructor that simply converts its
     * <code>String</code> argument into a <code>File</code> object,
     * and then calls the corresponding constructor.
     */
    public StringSetFile(String pathname) throws LoadException {
        this(new File(pathname));
    }

    /**
     * The primary constructor for obtaining an instance of
     * <code>StringSetFile</code>.  Captures the given
     * <code>File</code> object and loads the file into
     * the <code>StringSet</code>.
     */
    public StringSetFile(File file) throws LoadException {

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
     * Determine if this <code>StringSetFile</code>
     * contains the given string.  If this <code>Loadable</code>
     * object is stale, reload it first.
     *
     * @param s the string to be checked for containment
     * @return true if and only if the set contains
     *         the given string
     * @exception org.globus.gridshib.common.LoadException
     *            If unable to reload the <code>Loadable</code>
     *            object (if stale)
     */
    public boolean contains(String s) throws LoadException {

        // if necessary, reload the resource:
        if (isStale()) {
            logger.info("Reloading stale resource");
            load();
        }

        boolean b = this.stringSet.contains(s);

        if (logger.isDebugEnabled()) {
            String msg = "This StringSetFile " +
                         (b ? "contains " : "does not contain ") +
                         "string \"" + s + "\"";
            logger.debug(msg);
        }

        return b;
    }

    /**
     * Loads the file and calls {@link #resetLastLoaded()}.
     *
     * @see org.globus.gridshib.common.Loadable
     */
    public void load() throws LoadException {

        logger.debug("Reinitializing StringSet");
        this.stringSet = new HashSet();

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
        String matched;
        while ((line = reader.readLine()) != null) {
          line = line.trim();

          // ignore if comment or blank line:
          if (ignoredLine.matcher(line).matches()) {
              logger.debug("line ignored: " + line);
              continue;
          }

          // initialize matcher to use firstDataField pattern:
          matcher = firstDataField.matcher(line);
          logger.debug("matcher: " + matcher.toString());

          // extract matched string from input line:
          matched = find(matcher);
          if (matched == null) {
              String msg = "Matched string is null";
              logger.error(msg);
              throw new LoadException(msg);
          }

          // add the string to the set:
          if (!this.stringSet.add(matched)) {
              logger.warn("Duplicate string ignored: " + matched);
          } else {
              logger.info("String added to set: " + matched);
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
