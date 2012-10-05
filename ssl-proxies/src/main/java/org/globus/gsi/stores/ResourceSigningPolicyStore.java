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

import org.globus.gsi.provider.SigningPolicyStore;
import org.globus.gsi.provider.SigningPolicyStoreException;
import org.globus.gsi.provider.SigningPolicyStoreParameters;

import org.apache.commons.logging.LogFactory;

import org.apache.commons.logging.Log;

import java.io.IOException;
import java.net.URI;
import java.security.InvalidAlgorithmParameterException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;


import javax.security.auth.x500.X500Principal;

import org.globus.gsi.SigningPolicy;
import org.globus.gsi.util.CertificateIOUtil;

import org.globus.util.GlobusResource;
import org.globus.util.GlobusPathMatchingResourcePatternResolver;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class ResourceSigningPolicyStore implements SigningPolicyStore {

    private GlobusPathMatchingResourcePatternResolver globusResolver = new GlobusPathMatchingResourcePatternResolver();
    private Map<URI, ResourceSigningPolicy> signingPolicyFileMap = new HashMap<URI, ResourceSigningPolicy>();
    private Map<String, SigningPolicy> policyMap = new HashMap<String, SigningPolicy>();
    private ResourceSigningPolicyStoreParameters parameters;
    private Log logger = LogFactory.getLog(ResourceSigningPolicyStore.class.getCanonicalName());
    private final Map<String, Long> invalidPoliciesCache = new HashMap<String, Long>();
    private final Map<String, Long> validPoliciesCache = new HashMap<String, Long>();
    private final static long CACHE_TIME_MILLIS = 3600*1000;
    private long lastUpdate = 0;
    
    public ResourceSigningPolicyStore(SigningPolicyStoreParameters param) throws InvalidAlgorithmParameterException {
        if (param == null) {
            throw new IllegalArgumentException();
        }

        if (!(param instanceof ResourceSigningPolicyStoreParameters)) {
            throw new InvalidAlgorithmParameterException();

        }

        this.parameters = (ResourceSigningPolicyStoreParameters) param;
    }

    public synchronized SigningPolicy getSigningPolicy(X500Principal caPrincipal) throws SigningPolicyStoreException {

        if (caPrincipal == null) {
            return null;
        }
        String name = caPrincipal.getName();
        long now = System.currentTimeMillis();
        String hash = CertificateIOUtil.nameHash(caPrincipal);
        Long validCacheTime = validPoliciesCache.get(hash);
        Long invalidCacheTime = invalidPoliciesCache.get(hash);
        if ((invalidCacheTime != null) && (invalidCacheTime - now < 10*CACHE_TIME_MILLIS)) {
            return null;
        }
        if ((validCacheTime == null) || (validCacheTime-now > CACHE_TIME_MILLIS) || !this.policyMap.containsKey(name)) {
			logger.warn("Loading policy for hash " + hash);
            loadPolicy(hash);
        }
		logger.warn("Policy map: " + this.policyMap.get(name));
        return this.policyMap.get(name);
    }

    private synchronized void loadPolicy(String hash) throws SigningPolicyStoreException {

        String locations = this.parameters.getTrustRootLocations();
        GlobusResource[] resources;
        logger.warn("Locations: " + locations);
        resources = globusResolver.getResources(locations);

        long now = System.currentTimeMillis();

        for (GlobusResource resource : resources) {

            String filename = resource.getFilename();
            if (!filename.startsWith(hash)) {
                continue;
            }

            if (!resource.isReadable()) {
                logger.debug("Cannot read: " + resource.getFilename());
                continue;
            }

            try {
                loadSigningPolicy(resource, policyMap, signingPolicyFileMap);
            } catch (Exception e) {
                if (!invalidPoliciesCache.containsKey(filename)) {
                    logger.warn("Failed to load signing policy: " + filename);
                    logger.debug("Failed to load signing policy: " + filename, e);
                    invalidPoliciesCache.put(filename, now);
                }
            }
            validPoliciesCache.put(hash, now);
        }

    }

    private void loadSigningPolicy(
            GlobusResource policyResource, Map<String, SigningPolicy> policyMapToLoad,
            Map<URI, ResourceSigningPolicy> currentPolicyFileMap) throws SigningPolicyStoreException {

        URI uri;
        if (!policyResource.isReadable()) {
            throw new SigningPolicyStoreException("Cannot read file");
        }
        try {
            uri = policyResource.getURI();
        } catch (IOException e) {
            throw new SigningPolicyStoreException(e);
        }

        ResourceSigningPolicy filePolicy = this.signingPolicyFileMap.get(uri);
        if (filePolicy == null) {
            try {
                filePolicy = new ResourceSigningPolicy(policyResource);
            } catch (ResourceStoreException e) {
                throw new SigningPolicyStoreException(e);
            }
        }
        Collection<SigningPolicy> policies = filePolicy.getSigningPolicies();

        currentPolicyFileMap.put(uri, filePolicy);
        if (policies != null) {
            for (SigningPolicy policy : policies) {
                policyMapToLoad.put(policy.getCASubjectDN().getName(), policy);
            }
        }
    }
}
