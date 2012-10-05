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

import org.globus.gsi.SigningPolicyException;

import org.globus.gsi.provider.SigningPolicyStoreException;

import org.apache.commons.logging.LogFactory;

import org.apache.commons.logging.Log;

import java.io.IOException;
import java.io.Reader;
import java.io.InputStreamReader;
import java.util.Collection;
import java.util.Map;


import javax.security.auth.x500.X500Principal;

import org.globus.gsi.SigningPolicy;
import org.globus.gsi.SigningPolicyParser;
import org.globus.util.GlobusResource;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 28, 2009
 * Time: 2:57:09 PM
 * To change this template use File | Settings | File Templates.
 */
public class ResourceSigningPolicy {
    protected GlobusResource globusResource;

    private Log logger = LogFactory.getLog(ResourceSigningPolicy.class.getCanonicalName());
    private boolean changed;
    private Map<X500Principal, SigningPolicy> signingPolicyMap;
    private long lastModified = -1;

    public ResourceSigningPolicy(GlobusResource resource) throws ResourceStoreException {
        init(resource);
    }

    protected void init(GlobusResource initResource) throws ResourceStoreException {
        this.globusResource = initResource;
        this.signingPolicyMap = create(this.globusResource);
        logger.debug(String.format("Loading initResource: %s", this.globusResource.toString()));
        try {
            this.lastModified = this.globusResource.lastModified();
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        }
    }

    protected void init(GlobusResource initResource, Map<X500Principal, SigningPolicy> initSigningPolicy)
            throws ResourceStoreException {
        if (initSigningPolicy == null) {
            // JGLOBUS-88 : better exception?
            throw new IllegalArgumentException("Object cannot be null");
        }
        this.signingPolicyMap = initSigningPolicy;
        this.globusResource = initResource;
    }

    public Collection<SigningPolicy> getSigningPolicies()
            throws SigningPolicyStoreException {

        try {
            Map<X500Principal, SigningPolicy> object = getObject();
            if (object != null) {
                return object.values();
            }
        } catch (ResourceStoreException e) {
            throw new SigningPolicyStoreException(e);
        }
        return null;
    }

    public Map<X500Principal, SigningPolicy> create(GlobusResource signingPolicyResource) throws ResourceStoreException {
        SigningPolicyParser parser = new SigningPolicyParser();
        Map<X500Principal, SigningPolicy> policies;
        Reader reader;
        try {
            reader = new InputStreamReader(signingPolicyResource.getInputStream());
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        }
        try {
            policies = parser.parse(reader);
        } catch (SigningPolicyException e) {
            throw new ResourceStoreException(e);
        } finally {
            try {
                reader.close();
            } catch (IOException e) {
                throw new ResourceStoreException(e);
            }
        }

        return policies;
    }


    protected void reload() throws ResourceStoreException {

        this.changed = false;
        long latestLastModified;
        try {
            latestLastModified = this.globusResource.lastModified();
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        }
        if (this.lastModified < latestLastModified) {
            this.signingPolicyMap = create(this.globusResource);
            this.lastModified = latestLastModified;
            this.changed = true;
        }
    }

    public GlobusResource getResource() {
        return this.globusResource;
    }

    protected Map<X500Principal, SigningPolicy> getObject() throws ResourceStoreException {
        reload();
        return this.signingPolicyMap;
    }

    public boolean hasChanged() {
        return this.changed;
    }
}
