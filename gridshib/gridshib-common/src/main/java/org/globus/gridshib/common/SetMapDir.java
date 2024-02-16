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
 * for directories of <code>SetMapFile</code> objects.
 *
 * @see org.globus.gridshib.common.Loadable
 * @see org.globus.gridshib.common.LoadableResource
 *
 * @since 0.6.0
 */
public class SetMapDir extends LoadableResource  {

    private static Log logger =
        LogFactory.getLog(SetMapDir.class.getName());

    /**
     * A list of <code>SetMapDir</code> instances
     * maintained by {@link #getInstance(File)}.
     */
    private static List instances = new ArrayList();

    /**
     * Creates a <code>File</code> object from the given
     * <code>URI</code> instance and invokes
     * {@link #getInstance(File)}.
     *
     * @param uri the URI of the directory that backs
     *            this instance of <code>SetMapDir</code>
     * @return    the one and only one <code>SetMapDir</code>
     *            instance that corresponds to the given URI
     * @exception org.globus.gridshib.common.LoadException
     *            if a new instance of <code>SetMapDir</code>
     *            is required but the directory fails to load
     */
    public static SetMapDir getInstance(URI uri)
                                 throws LoadException {

        return getInstance(new File(uri));
    }

    /**
     * Creates a <code>File</code> object from the given
     * <code>pathname</code> and invokes
     * {@link #getInstance(File)}.
     *
     * @param pathname the pathname of the directory that backs
     *                 this instance of <code>SetMapDir</code>
     * @return         the one and only one <code>SetMapDir</code>
     *                 instance that corresponds to the given pathname
     * @exception      org.globus.gridshib.common.LoadException
     *                 if a new instance of <code>SetMapDir</code>
     *                 is required but the directory fails to load
     */
    public static SetMapDir getInstance(String pathname)
                                 throws LoadException {

        return getInstance(new File(pathname));
    }

    /**
     * Gets <em>the</em> instance of <code>SetMapDir</code>
     * that corresponds to the given directory.  Such an
     * instance may have been created previously, in which
     * case that instance is returned directly.  Otherwise,
     * a new instance of <code>SetMapDir</code> is
     * created and returned.
     * <p>
     * Use of this method (as opposed to direct use of the
     * constructor) prevents needless reloading of a
     * directory that may have already been loaded.
     *
     * @param dir the directory that backs this instance of
     *            <code>SetMapDir</code>
     * @return    the one and only one <code>SetMapDir</code>
     *            instance that corresponds to the given directory
     * @exception org.globus.gridshib.common.LoadException
     *            if a new instance of <code>SetMapDir</code>
     *            is required but the directory fails to load
     *
     * @see #SetMapDir(File)
     */
    public static SetMapDir getInstance(File dir)
                                 throws LoadException {

        SetMapDir setMapDir;
        for (int i = 0; i < instances.size(); i++) {
            setMapDir = (SetMapDir)instances.get(i);
            if (setMapDir.resource.equals(dir)) {
                logger.debug("Obtained existing instance");
                return setMapDir;
            }
        }
        setMapDir = new SetMapDir(dir);
        logger.debug("Created new instance");
        if (instances.add(setMapDir)) {
            logger.debug("Storing new instance");
        } else {
            logger.debug("Instance previously created");
        }
        return setMapDir;
    }

    /**
     * A list of <code>SetMapFile</code> instances
     * in this directory.
     */
    private List setMaps;

    /**
     * A convenience constructor that simply converts its
     * <code>URI</code> argument into a <code>File</code>
     * object, and then calls the corresponding constructor.
     *
     * @param uri the URI of the directory that backs
     *            this instance of <code>SetMapDir</code>
     * @exception org.globus.gridshib.common.LoadException
     *            if a new instance of <code>SetMapDir</code>
     *            is required but the directory fails to load
     */
    public SetMapDir(URI uri) throws LoadException {
        this(new File(uri));
    }

    /**
     * A convenience constructor that simply converts its
     * <code>String</code> argument into a <code>File</code>
     * object, and then calls the corresponding constructor.
     *
     * @param pathname the pathname of the directory that backs
     *                 this instance of <code>SetMapDir</code>
     * @exception      org.globus.gridshib.common.LoadException
     *                 if a new instance of <code>SetMapDir</code>
     *                 is required but the directory fails to load
     */
    public SetMapDir(String pathname) throws LoadException {
        this(new File(pathname));
    }

    /**
     * The primary constructor for creating an instance of
     * <code>SetMapDir</code>.  Captures the given
     * <code>File</code> object and loads the directory.
     *
     * @param dir the directory that backs this instance of
     *            <code>SetMapDir</code>
     * @exception org.globus.gridshib.common.LoadException
     *            if a new instance of <code>SetMapDir</code>
     *            is required but the directory fails to load
     */
    public SetMapDir(File dir) throws LoadException {

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
    }

    /**
     * Gets all the (<code>String</code>) keys
     * associated with this <code>SetMapDir</code> instance.
     * If this <code>Loadable</code> directory is stale,
     * reload it first.
     *
     * @return    the (possibly empty) union of all the keys
     *            associated with each <code>SetMapFile</code>
     *            instance
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

        HashSet keys = new HashSet();

        Map map;
        for (int i = 0; i < this.setMaps.size(); i++) {
            // get the map backing this SetMapFile instance:
            map = ((SetMapFile)this.setMaps.get(i)).getSetMap();
            logger.debug("SetMapFile[" + i + "] contains " +
                         map.keySet().size() + " keys");
            keys.addAll(map.keySet());
        }

        logger.debug("This SetMapDir instance contains " +
                     "a total of " + keys.size() + " keys");

        return keys;
    }

    /**
     * Gets the set of string values that corresponds to the
     * given key.  Iterates over all <code>SetMapFile</code>
     * objects in this directory.  If this <code>Loadable</code>
     * directory is stale, reload it first.
     *
     * @param key a string key
     * @return    the set of string values corresponding to the
     *            given key
     * @exception org.globus.gridshib.common.LoadException
     *            If unable to reload the <code>Loadable</code>
     *            object (if stale)
     */
    public Set getImageSet(String key) throws LoadException {

        // if necessary, reload the resource:
        if (isStale()) {
            logger.info("Reloading stale resource");
            load();
        }

        // iterate over all SetMaps in this directory:
        for (int i = 0; i < this.setMaps.size(); i++) {
            SetMapFile setMapFile = (SetMapFile)this.setMaps.get(i);
            if (setMapFile.getSetMap().containsKey(key)) {
                Set values = (HashSet)setMapFile.getImageSet(key);
                String msg = "SetMapFile[" + i + "] contains ordered pair " +
                             "(" + key + ", " + values.toString() + ")";
                logger.debug(msg);
                return values;
            } else {
                String msg = "SetMapFile[" + i + "] does not " +
                             "contain key (" + key + ")";
                logger.debug(msg);
            }
        }

        return null;
    }

    /**
     * Loads the directory and calls {@link #resetLastLoaded()}.
     *
     * @exception  org.globus.gridshib.common.LoadException
     *             if the directory that backs this instance
     *             of <code>SetMapDir</code> fails to load
     *
     * @see org.globus.gridshib.common.Loadable
     */
    public void load() throws LoadException {

        logger.debug("Reinitializing list of SetMaps");
        this.setMaps = new ArrayList();

        logger.info("Loading directory...");
        loadDir();
        logger.info("Directory loaded.");
        resetLastLoaded();
    }

    /**
     * Loads this directory resource.  Does all the heavy
     * lifting, including opening, reading, parsing, and
     * closing each file in the directory.
     *
     * @exception  org.globus.gridshib.common.LoadException
     *             if an I/O error occurs or the file can
     *             not be parsed
     */
    private void loadDir() throws LoadException {

        File dir = this.resource;
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
                    this.setMaps.add(SetMapFile.getInstance(files[i]));
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
