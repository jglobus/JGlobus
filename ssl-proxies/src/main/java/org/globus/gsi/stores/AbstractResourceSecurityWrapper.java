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

import org.apache.commons.logging.LogFactory;

import org.apache.commons.logging.Log;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import org.globus.common.CoGProperties;

import org.globus.util.GlobusResource;
import org.globus.util.GlobusPathMatchingResourcePatternResolver;

/**
 * // JGLOBUS-91 : add javadoc
 *
 * @param <T>
 *            Type of security object
 */
public abstract class AbstractResourceSecurityWrapper<T> implements
		SecurityObjectWrapper<T>, Storable {

    protected GlobusPathMatchingResourcePatternResolver globusResolver = new GlobusPathMatchingResourcePatternResolver();
    protected GlobusResource globusResource;

	private Log logger = LogFactory.getLog(getClass().getCanonicalName());

	private boolean changed;
	private T securityObject;
	private long lastModified = -1;
        private long lastRefresh;
        private final long cacheLifetime;
	private String alias;
	private boolean inMemory = false;

	protected AbstractResourceSecurityWrapper(boolean inMemory) {
		this.inMemory = inMemory;
                cacheLifetime = CoGProperties.getDefault().getCertCacheLifetime();
	}

	protected void init(String locationPattern) throws ResourceStoreException {
		init(globusResolver.getResource(locationPattern));
	}

    protected void init(GlobusResource initialResource) throws ResourceStoreException {
        init(initialResource, create(initialResource));
    }

	public String getAlias() {
		return alias;
	}

	protected void init(String locationPattern, T initialSecurityObject)
			throws ResourceStoreException {
		init(globusResolver.getResource(locationPattern), initialSecurityObject);
	}

	protected void init(GlobusResource initialResource, T initialSecurityObject)
			throws ResourceStoreException {
		if (initialSecurityObject == null) {
			// JGLOBUS-88 : better exception?
			throw new IllegalArgumentException("Object cannot be null");
		}
		this.securityObject = initialSecurityObject;
		this.globusResource = initialResource;
                logger.debug(String.format("Loading initialResource: %s", this.globusResource.toString()));
		try {
			this.alias = this.globusResource.getURL().toExternalForm();
			if(!inMemory){
				this.lastModified = this.globusResource.lastModified();
                                this.lastRefresh = System.currentTimeMillis();
			}
		} catch (IOException e) {
			throw new ResourceStoreException(e);
		}
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
		try {
			return globusResource.getFile();
		} catch (IOException e) {
			logger.debug("Resource is not a file", e);
			return null;
		}
	}

	public void refresh() throws ResourceStoreException {
		if(!inMemory){
                    long now = System.currentTimeMillis();
                    if (this.lastRefresh + this.cacheLifetime < now) {
			this.changed = false;
			long latestLastModified;
			try {
				latestLastModified = this.globusResource.lastModified();
			} catch (IOException e) {
				throw new ResourceStoreException(e);
			}
			if (this.lastModified < latestLastModified) {
				this.securityObject = create(this.globusResource);
				this.lastModified = latestLastModified;
				this.changed = true;
			}
                        this.lastRefresh = now;
                    }
		}
	}

    protected abstract T create(GlobusResource targetResource)
            throws ResourceStoreException;

	public T getSecurityObject() throws ResourceStoreException {
		refresh();
		return this.securityObject;
	}

	public boolean hasChanged() {
		return this.changed;
	}
}
