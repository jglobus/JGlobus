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
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.Loadable;

/**
 * An abstract implementation of the <code>Loadable</code>
 * interface.  This implementation is backed by a file-based
 * resource.
 * <p>
 * Note: Subclasses must implement the Loadable#load() method.
 *
 * @see org.globus.gridshib.common.Loadable
 */
public abstract class LoadableResource implements Loadable  {

    private static Log logger =
        LogFactory.getLog(LoadableResource.class.getName());

    /* For now, a resource is an instance of <code>File</code>.
     * A more appropriate implementation would be built
     * around <code>FileLocation</code>, but that class is
     * currently tied up in the GridShib SAML Tools distribution.
     * We need to devise a process whereby each CVS module
     * contributes to a shared package called
     * org.globus.gridshib.common (or something similar).
     */

    /**
     * The actual resource backing this
     * <code>LoadableResource</code> object.
     */
    protected File resource;

    /**
     * Is true if and only if this <code>LoadableResource</code>
     * object has been loaded.
     */
    protected boolean loaded = false;

    /**
     * The time (in milliseconds past the epoch) since
     * this <code>LoadableResource</code> instance was
     * last loaded.
     */
    protected long lastLoaded;

    /**
     * Get the file-based resource backing this instance
     * of <code>LoadableResource</code>.
     *
     * @since 0.4.3
     */
    public File getResource() {
        return this.resource;
    }

    /**
     * @see org.globus.gridshib.common.Loadable
     */
    public boolean isLoaded() {
        return this.loaded;
    }

    /**
     * @see org.globus.gridshib.common.Loadable
     */
    public long getLastLoaded() {
        return this.lastLoaded;
    }

    /**
     * @see org.globus.gridshib.common.Loadable
     */
    public void resetLastLoaded() {
        this.lastLoaded = System.currentTimeMillis();
        logger.debug("Resetting last loaded: " + this.lastLoaded);
    }

    /**
     * @see org.globus.gridshib.common.Loadable
     */
    public boolean isStale() {
        logger.debug("Resource last loaded: " + this.lastLoaded);
        logger.debug("Resource last modified: " +
                     this.resource.lastModified());
        return this.resource.lastModified() > this.lastLoaded;
    }

    /**
     * Convert the <code>File</code> object to a "file:" URL.
     * Returns null if the <code>File</code> is null or
     * can not be converted to a URL.
     */
    protected static URL toURL(File file) {
        if (file == null) { return null; }
        return toURL(file.toURI());
    }

    /**
     * Convert the <code>URI</code> object to a "file:" URL.
     * Returns null if the <code>URI</code> is null or
     * can not be converted to a URL.
     */
    protected static URL toURL(URI uri) {
        if (uri == null) { return null; }
        URL url = null;
        try {
            url = uri.toURL();
        } catch (MalformedURLException e) {
            logger.error("Unable to convert URI to URL: " + uri.toString());
        }
        return url;
    }
}
