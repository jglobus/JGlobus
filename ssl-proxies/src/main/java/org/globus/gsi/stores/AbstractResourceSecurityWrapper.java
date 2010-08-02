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



import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

/**
 * // FIXME: add javadoc
 * 
 * @param <T>
 *            Type of security object
 */
public abstract class AbstractResourceSecurityWrapper<T> implements
		SecurityObjectWrapper<T>, Storable {

	protected PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
	protected Resource resource;

	private Log logger = LogFactory.getLog(getClass().getCanonicalName());

	private boolean changed;
	private T securityObject;
	private long lastModified = -1;
	private String alias;

	protected void init(String locationPattern) throws ResourceStoreException {
		init(resolver.getResource(locationPattern));
	}

	protected void init(Resource initialResource) throws ResourceStoreException {
		this.resource = initialResource;
		this.securityObject = create(this.resource);
		logger.debug(String.format("Loading initialResource: %s", this.resource.toString()));
		try {
			this.alias = this.resource.getURL().toExternalForm();
			this.lastModified = this.resource.lastModified();
		} catch (IOException e) {
			throw new ResourceStoreException(e);
		}
	}

	public String getAlias() {
		return alias;
	}

	protected void init(String locationPattern, T initialSecurityObject)
			throws ResourceStoreException {
		init(resolver.getResource(locationPattern), initialSecurityObject);
	}

	protected void init(Resource initialResource, T initialSecurityObject)
			throws ResourceStoreException {
		if (initialSecurityObject == null) {
			// FIXME: better exception?
			throw new IllegalArgumentException("Object cannot be null");
		}
		this.securityObject = initialSecurityObject;
		this.resource = initialResource;
	}

	public Resource getResource() {
		return resource;
	}

	public URL getResourceURL() {
		try {
			return resource.getURL();
		} catch (IOException e) {
			logger.warn("Unable to extract url", e);
			return null;
		}
	}

	public File getFile() {
		try {
			return resource.getFile();
		} catch (IOException e) {
			logger.debug("Resource is not a file", e);
			return null;
		}
	}

	public void refresh() throws ResourceStoreException {
		this.changed = false;
		long latestLastModified;
		try {
			latestLastModified = this.resource.lastModified();
		} catch (IOException e) {
			throw new ResourceStoreException(e);
		}
		if (this.lastModified < latestLastModified) {
			this.securityObject = create(this.resource);
			this.lastModified = latestLastModified;
			this.changed = true;
		}
	}

	protected abstract T create(Resource targetResource)
			throws ResourceStoreException;

	public T getSecurityObject() throws ResourceStoreException {
		refresh();
		return this.securityObject;
	}

	public boolean hasChanged() {
		return this.changed;
	}
}
