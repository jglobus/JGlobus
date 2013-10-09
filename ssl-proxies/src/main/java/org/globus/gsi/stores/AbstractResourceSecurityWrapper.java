/*
 * Copyright 1999-2010 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS,WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

package org.globus.gsi.stores;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.globus.util.GlobusPathMatchingResourcePatternResolver;
import org.globus.util.GlobusResource;

import java.io.File;
import java.io.IOException;
import java.net.URL;

/**
 * // JGLOBUS-91 : add javadoc
 *
 * @param <T>
 *            Type of security object
 */
public abstract class AbstractResourceSecurityWrapper<T> implements
        SecurityObjectWrapper<T>, Storable {

    protected GlobusResource globusResource;

    private Log logger = LogFactory.getLog(getClass());

    private boolean changed;
    private T securityObject;
    private long lastModified = -1;
    private final String alias;
    private final boolean inMemory;
    private final SecurityObjectFactory<T> factory;

    protected static interface SecurityObjectFactory<T>
    {
        T create(GlobusResource resource)
            throws ResourceStoreException;
    }

    protected AbstractResourceSecurityWrapper(SecurityObjectFactory<T> factory, boolean inMemory, String locationPattern)
            throws ResourceStoreException {
        this(factory, inMemory, new GlobusPathMatchingResourcePatternResolver().getResource(locationPattern));
    }

    protected AbstractResourceSecurityWrapper(SecurityObjectFactory<T> factory, boolean inMemory, GlobusResource initialResource)
            throws ResourceStoreException {
        this(factory, inMemory, initialResource, factory.create(initialResource));
    }

    protected AbstractResourceSecurityWrapper(SecurityObjectFactory<T> factory, boolean inMemory, String locationPattern, T initialSecurityObject)
            throws ResourceStoreException {
        this(factory, inMemory, new GlobusPathMatchingResourcePatternResolver().getResource(locationPattern), initialSecurityObject);
    }

    protected AbstractResourceSecurityWrapper(SecurityObjectFactory<T> factory, boolean inMemory, GlobusResource initialResource, T initialSecurityObject)
            throws ResourceStoreException {
        this.factory = factory;
        this.inMemory = inMemory;
        if (initialSecurityObject == null) {
            // JGLOBUS-88 : better exception?
            throw new IllegalArgumentException("Object cannot be null");
        }
        this.securityObject = initialSecurityObject;
        this.globusResource = initialResource;
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("Loading initialResource: %s", this.globusResource.toString()));
        }
        try {
            this.alias = this.globusResource.getURL().toExternalForm();
            if(!this.inMemory){
                this.lastModified = this.globusResource.lastModified();
            }
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        }
    }

    public String getAlias() {
        return alias;
    }

    public GlobusResource getGlobusResource(){
        return globusResource;
    }

    public URL getResourceURL() {
        try {
            return globusResource.getURL();
        } catch (IOException e) {
            logger.warn("Unable to extract url", e);
            return null;
        }
    }


    public File getFile() {
        return globusResource.getFile();
    }

    public void refresh() throws ResourceStoreException {
        if(!inMemory){
            synchronized (this) {
                this.changed = false;
                long latestLastModified;
                try {
                    latestLastModified = this.globusResource.lastModified();
                } catch (IOException e) {
                    throw new ResourceStoreException(e);
                }
                if (this.lastModified < latestLastModified) {
                    this.securityObject = factory.create(this.globusResource);
                    this.lastModified = latestLastModified;
                    this.changed = true;
                }
            }
        }
    }

    protected final T create(GlobusResource targetResource)
            throws ResourceStoreException
    {
        return factory.create(targetResource);
    }

    public T getSecurityObject() throws ResourceStoreException {
        refresh();
        return this.securityObject;
    }

    public boolean hasChanged() {
        return this.changed;
    }
}
