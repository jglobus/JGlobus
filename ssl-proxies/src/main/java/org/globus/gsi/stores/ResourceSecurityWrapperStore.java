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
import org.globus.util.GlobusPathMatchingResourcePatternResolver;
import org.globus.util.GlobusResource;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.net.URI;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public abstract class ResourceSecurityWrapperStore<T extends AbstractResourceSecurityWrapper<V>, V> {
    private volatile Collection<V> roots = Collections.emptyList();
    private volatile Map<URI, T> wrappers = Collections.emptyMap();

    public Collection<T> getWrappers() {
        return this.wrappers.values();
    }

    public Collection<V> getCollection() {
        return this.roots;
    }

    public void loadWrappers(String locationPattern)
            throws ResourceStoreException {
        if (locationPattern == null || locationPattern.isEmpty()) {
            this.wrappers = Collections.emptyMap();
            this.roots = Collections.emptyList();
        } else {
            loadWrappers(locationPattern.split(","));
        }
    }

    public void loadWrappers(String[] locations) throws ResourceStoreException {
        Map<URI, T> newWrappers = new HashMap<URI, T>();
        for (String location : locations) {
            load(location, wrappers, newWrappers);
        }
        Set<V> newRoots = new HashSet<V>();
        for (T wrapper : newWrappers.values()) {
            newRoots.add(wrapper.getSecurityObject());
        }
        roots = Collections.unmodifiableCollection(newRoots);
        wrappers = Collections.unmodifiableMap(newWrappers);
    }

    private void load(String locationPattern, Map<URI, T> oldWrappers, Map<URI, T> newWrappers) throws ResourceStoreException {
        try {
            GlobusResource[] globusResources = new GlobusPathMatchingResourcePatternResolver().getResources(locationPattern);
            for (GlobusResource globusResource : globusResources){
                if (!globusResource.isReadable()) {
                    getLog().warn("Cannot read: " + globusResource.getURI());
                } else {
                    loadRecursively(globusResource.getFile(), oldWrappers, newWrappers);
                }
            }
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        }
    }

    private void loadRecursively(File file, Map<URI, T> oldWrappers, Map<URI, T> newWrappers) throws IOException, ResourceStoreException {
        if (file.isDirectory()) {
            File[] children = file.listFiles(getDefaultFilenameFilter());
            if (children != null) {
                for (File child : children) {
                    loadRecursively(child, oldWrappers, newWrappers);
                }
            }
        } else {
            GlobusResource resource = new GlobusResource(file.getAbsolutePath());
            URI uri = resource.getURI();
            T fbo = oldWrappers.get(uri);
            if (fbo == null) {
                fbo = create(resource);
            }
            newWrappers.put(uri, fbo);
        }
    }

    protected abstract T create(GlobusResource resource) throws ResourceStoreException;

    protected abstract FilenameFilter getDefaultFilenameFilter();

    protected abstract Log getLog();
}
