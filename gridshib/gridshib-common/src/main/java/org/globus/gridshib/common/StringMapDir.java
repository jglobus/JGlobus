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

import java.io.File;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.LoadException;
import org.globus.gridshib.common.LoadableResource;

/**
 * An implementation of the <code>Loadable</code> interface
 * for directories of <code>StringMapFile</code> objects.
 *
 * @see org.globus.gridshib.common.Loadable
 * @see org.globus.gridshib.common.LoadableResource
 */
public class StringMapDir extends LoadableResource  {

    private static Log logger =
        LogFactory.getLog(StringMapDir.class.getName());

    /**
     * A list of <code>StringMapDir</code> instances
     * maintained by #getInstance(String) and #getInstance(URI).
     */
    private static List instances = new ArrayList();

    /**
     * Creates a <code>File</code> object from the given
     * <code>URI</code> instance and invokes #getInstance(File).
     *
     * @param uri the URI of the directory that backs
     *        this instance of <code>StringMapDir</code>
     * @return the one and only one <code>StringMapDir</code>
     *         instance that corresponds to the given URI
     * @exception org.globus.gridshib.common.LoadException
     *            if a new instance of <code>StringMapDir</code>
     *            is required but the directory fails to load
     */
    public static StringMapDir getInstance(URI uri)
                                    throws LoadException {

        return getInstance(new File(uri));
    }

    /**
     * Creates a <code>File</code> object from the given
     * <code>pathname</code> and invokes #getInstance(File).
     *
     * @param pathname the pathname of the directory that backs
     *        this instance of <code>StringMapDir</code>
     * @return the one and only one <code>StringMapDir</code>
     *         instance that corresponds to the given pathname
     * @exception org.globus.gridshib.common.LoadException
     *            if a new instance of <code>StringMapDir</code>
     *            is required but the directory fails to load
     */
    public static StringMapDir getInstance(String pathname)
                                    throws LoadException {

        return getInstance(new File(pathname));
    }

    /**
     * Gets <em>the</em> instance of <code>StringMapDir</code>
     * that corresponds to the given directory.  Such an
     * instance may have been created previously, in which
     * case that instance is returned directly.  Otherwise,
     * a new instance of <code>StringMapDir</code> is
     * created and returned.
     * <p>
     * Use of this method (as opposed to direct use of the
     * constructor) prevents needless reloading of a
     * directory that may have already been loaded.
     *
     * @param dir the directory that backs this instance of
     *        <code>StringMapDir</code>
     * @return the one and only one <code>StringMapDir</code>
     *         instance that corresponds to the given directory
     * @exception org.globus.gridshib.common.LoadException
     *            if a new instance of <code>StringMapDir</code>
     *            is required but the directory fails to load
     *
     * @see #StringMapDir(File)
     */
    public static StringMapDir getInstance(File dir)
                                    throws LoadException {

        StringMapDir smd;
        for (int i = 0; i < instances.size(); i++) {
            smd = (StringMapDir)instances.get(i);
            if (smd.resource.equals(dir)) {
                logger.debug("Obtained existing instance");
                return smd;
            }
        }
        smd = new StringMapDir(dir);
        logger.debug("Created new instance");
        if (instances.add(smd)) {
            logger.debug("Storing new instance");
        } else {
            logger.debug("Instance previously created");
        }
        return smd;
    }

    /**
     * A list of <code>StringMapFile</code> instances
     * in this directory.
     */
    private List stringMaps;

    /**
     * A convenience constructor that simply converts its
     * <code>URI</code> argument into a <code>File</code>
     * object, and then calls the corresponding constructor.
     */
    public StringMapDir(URI uri) throws LoadException {
        this(new File(uri));
    }

    /**
     * A convenience constructor that simply converts its
     * <code>String</code> argument into a <code>File</code>
     * object, and then calls the corresponding constructor.
     */
    public StringMapDir(String pathname) throws LoadException {
        this(new File(pathname));
    }

    /**
     * The primary constructor for creating an instance of
     * <code>StringMapDir</code>.  Captures the given
     * <code>File</code> object and loads the directory.
     */
    public StringMapDir(File dir) throws LoadException {

        if (dir == null) {
            String msg = "Null argument";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }
        if (!dir.exists()) {
            String msg = "Directory (" + dir.toString() +
                         ") does not exist";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }
        if (!dir.isDirectory()) {
            String msg = "Directory (" + dir.toString() +
                         ") is not a directory";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }
        logger.debug("Creating new instance");

        this.lastLoaded = 0;  // guarantees isStale() ==> true
        this.resource = dir;
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
     * @return the union of all the keys associated with
     *         each <code>StringMapFile</code> instance
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

        HashSet set = new HashSet();

        Map map;
        for (int i = 0; i < this.stringMaps.size(); i++) {
            // get the map backing this StringMapFile instance:
            map = ((StringMapFile)this.stringMaps.get(i)).getStringMap();
            logger.debug("StringMapFile[" + i + "] contains " +
                         map.keySet().size() + " keys");
            set.addAll(map.keySet());
        }

        logger.debug("This StringMapDir instance contains " +
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

        String value = null;

        for (int i = 0; i < this.stringMaps.size(); i++) {
            value = ((StringMapFile)this.stringMaps.get(i)).get(key);
            if (value != null) break;
        }

        if (logger.isDebugEnabled()) {
            if (value == null) {
                String msg = "This StringMapDir instance does not " +
                             "contain key \"" + key + "\"";
                logger.debug(msg);
            } else {
                String msg = "This StringMapDir instance contains " +
                             "map entry " +
                             "(" + key + ", " + value + ")";
                logger.debug(msg);
            }
        }

        return value;
    }

    /**
     * Loads the directory and calls #resetLastLoaded().
     *
     * @see org.globus.gridshib.common.Loadable
     */
    public void load() throws LoadException {

        logger.debug("Reinitializing list of StringMaps");
        this.stringMaps = new ArrayList();

        logger.info("Loading directory...");
        load(this.resource);
        logger.info("Directory loaded.");
        resetLastLoaded();
    }

    private void load(File dir) throws LoadException {

        assert (dir.exists() && dir.isDirectory());

        File[] files = dir.listFiles();
        if (files == null) {
            logger.warn("No files found");
            return;
        }

        /* Restrict the search to ordinary files.
         * In particular, ignore subdirectories.
         */

        int k = 0;
        for (int i = 0; i < files.length; i++) {
            if (files[i].isFile()) {
                try {
                    this.stringMaps.add(StringMapFile.getInstance(files[i]));
                    k++;
                } catch (LoadException e) {
                    String msg = "File failed to load: " +
                                 files[i].toString();
                    logger.error(msg);
                    logger.debug(e);
                    continue;
                }
            }
        }
        logger.info("Found " + files.length + " files; " +
                    "successfully loaded " + k + " files");
    }
}
