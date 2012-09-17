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
import java.io.FilenameFilter;
import java.io.IOException;
import java.net.URI;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;



import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

/**
 * Created by IntelliJ IDEA. User: turtlebender Date: Dec 29, 2009 Time:
 * 12:29:45 PM To change this template use File | Settings | File Templates.
 * 
 * @param <T>
 * @param <V>
 */
public abstract class ResourceSecurityWrapperStore<T extends AbstractResourceSecurityWrapper<V>, V> {
	private Collection<V> rootObjects;
	private PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
	private Map<String, T> wrapperMap = new HashMap<String, T>();
	private Log logger = LogFactory.getLog(ResourceSecurityWrapperStore.class.getCanonicalName());

	public Map<String, T> getWrapperMap() {
		return this.wrapperMap;
	}

	public void loadWrappers(String[] locations) throws ResourceStoreException {
		for (String location : locations) {
			File file = new File(location);
			FileSystemResource resource = new FileSystemResource(file);
			try {
				loadWrappers(resource.getURL().toExternalForm());
			} catch (IOException ioe) {
				throw new ResourceStoreException(ioe);
			}
		}
	}

	public void loadWrappers(String locationPattern)
			throws ResourceStoreException {
		Set<V> updatedList = new HashSet<V>();
		boolean changed = false;
		Map<String, T> newWrapperMap = new HashMap<String, T>();
		if (locationPattern == null) {
			this.rootObjects = updatedList;
			this.wrapperMap = newWrapperMap;
			return;
		}
		if (locationPattern.indexOf(",") >= 0) {
			String[] locationPatterns = locationPattern.split(",");
			boolean tmpChanged = false;
			for (String lp : locationPatterns) {
				if (!tmpChanged) {
					tmpChanged = loadResources(lp, updatedList, newWrapperMap);
				}
				changed = tmpChanged;
			}
		} else {
			changed = loadResources(locationPattern, updatedList, newWrapperMap);
		}
		// in case certificates were removed
		if (!changed && this.rootObjects != null
				&& this.wrapperMap.size() != newWrapperMap.size()) {
			changed = true;
		}
		if (changed) {
			this.rootObjects = updatedList;
		}
		this.wrapperMap = newWrapperMap;
	}

	private boolean loadResources(String locationPattern, Set<V> updatedList,
			Map<String, T> newWrapperMap) throws ResourceStoreException {
		boolean changed = false;
		try {
			Resource[] resources = resolver.getResources(locationPattern);
			for (Resource resource : resources) {
				URI uri = resource.getURI();
				if (!resource.isReadable()) {
					getLog().warn("Cannot read: " + uri.toASCIIString());
					continue;
				}
				changed = load(resource, updatedList, newWrapperMap);
			}
		} catch (IOException e) {
			throw new ResourceStoreException(e);
		}
		return changed;
	}

	private boolean load(Resource resource, Set<V> currentRoots,
			Map<String, T> newWrapperMap) throws ResourceStoreException {
		if (!resource.isReadable()) {
			throw new ResourceStoreException("Cannot read file");
		}
		try {
			if (resource.getFile().isDirectory()) {
				File directory = resource.getFile();
				currentRoots.addAll(addCredentials(directory, newWrapperMap));
				return true;
			}
		} catch (IOException e) {
			// This is ok, it just means the resource is not a
			// filesystemresources
			logger.debug("Not a filesystem resource", e);
		}
		try {
			String resourceUri = resource.getURL().toExternalForm();
			T fbo = this.wrapperMap.get(resourceUri);
			if (fbo == null) {
				fbo = create(resource);
			}
			V target = fbo.create(resource);
			newWrapperMap.put(resourceUri, fbo);
			currentRoots.add(target);
			return true;
		} catch (IOException e) {
			throw new ResourceStoreException(e);
		}

	}

	private Set<V> addCredentials(File directory, Map<String, T> newWrapperMap) throws ResourceStoreException {
		FilenameFilter filter = getDefaultFilenameFilter();
		String[] children = directory.list(filter);
		Set<V> roots = new HashSet<V>();
        if (children == null) {
            return roots;
        }
		try {
			for (String child : children) {
				File childFile = new File(directory, child);
				if (childFile.isDirectory()) {
					roots.addAll(addCredentials(childFile, newWrapperMap));
				} else {
					Resource resource = new FileSystemResource(childFile);
					String resourceUri = resource.getURI().toASCIIString();
					T fbo = this.wrapperMap.get(resourceUri);
					if (fbo == null) {
						fbo = create(new FileSystemResource(childFile));
					}
					V target = fbo.create(resource);
					newWrapperMap.put(resourceUri, fbo);
					roots.add(target);
				}
			}
			return roots;
		} catch (IOException e) {
			throw new ResourceStoreException(e);
		}
	}

	public abstract T create(Resource resource) throws ResourceStoreException;

	public abstract FilenameFilter getDefaultFilenameFilter();

	public Collection<V> getCollection() {
		return this.rootObjects;
	}

	protected abstract Log getLog();
}
