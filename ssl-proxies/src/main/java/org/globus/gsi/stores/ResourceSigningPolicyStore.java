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

    private Map<URI, ResourceSigningPolicy> signingPolicyFileMap = new HashMap<URI, ResourceSigningPolicy>();
    private Map<String, SigningPolicy> policyMap = new HashMap<String, SigningPolicy>();
    private ResourceSigningPolicyStoreParameters parameters;
    private final static Log logger = LogFactory.getLog(ResourceSigningPolicyStore.class.getCanonicalName());
    private final Map<String, Long> invalidPoliciesCache = new HashMap<String, Long>();
    private final Map<String, Long> validPoliciesCache = new HashMap<String, Long>();
    private final static long CACHE_TIME_MILLIS = 3600*1000;

    /**
     * Please use the {@link Stores} class to generate Key/Cert stores
     */
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
        String caPrincipalName = caPrincipal.getName();
        long now = System.currentTimeMillis();
        String hash = CertificateIOUtil.nameHash(caPrincipal);

        Long validCacheTime = validPoliciesCache.get(caPrincipalName);
        Long invalidCacheTime = invalidPoliciesCache.get(caPrincipalName);

        if ((invalidCacheTime != null) && (now - invalidCacheTime < 10*CACHE_TIME_MILLIS)) {
            return null;
        }
        if ((validCacheTime == null) || (now - validCacheTime >= CACHE_TIME_MILLIS) || !this.policyMap.containsKey(caPrincipalName)) {
            loadPolicy(hash, caPrincipalName);
        }
        return this.policyMap.get(caPrincipalName);
    }

    private synchronized void loadPolicy(String hash, String caPrincipalName) throws SigningPolicyStoreException {

        String locations = this.parameters.getTrustRootLocations();
        GlobusResource[] resources = new GlobusPathMatchingResourcePatternResolver().
                getResources(locations);
        long now = System.currentTimeMillis();
        boolean found_policy = false;

        // Optimization: If we find a hash for this CA, only process that.
        // Otherwise, we will process all policies.
        for (GlobusResource resource : resources) {
            String filename = resource.getFilename();
            if (!filename.startsWith(hash)) {
                continue;
            }

            if (loadSigningPolicy(resource, policyMap, signingPolicyFileMap, now)) {
                found_policy = true;
            }
        }

        if (!found_policy) {
            // Poor-man's implementation.  Note it is much more expensive than a hashed directory
            for (GlobusResource resource : resources) {
                loadSigningPolicy(resource, policyMap, signingPolicyFileMap, now);
            }
        }

        if (!validPoliciesCache.containsKey(caPrincipalName)) {
            invalidPoliciesCache.put(caPrincipalName, now);
        }

    }

    private boolean loadSigningPolicy(
            GlobusResource policyResource, Map<String, SigningPolicy> policyMapToLoad,
            Map<URI, ResourceSigningPolicy> currentPolicyFileMap, long currentMillis) {

        String filename = policyResource.getFilename();
        long now = currentMillis;
        boolean loaded = false;

        Long invalidCacheTime = invalidPoliciesCache.get(filename);
        if ((invalidCacheTime != null) && (now - invalidCacheTime < 10 * CACHE_TIME_MILLIS)) {
            return false;
        }

        try {
            URI uri;
            if (!policyResource.isReadable()) {
                throw new SigningPolicyStoreException("file is not readable");
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
                    X500Principal caPrincipal = policy.getCASubjectDN();
                    policyMapToLoad.put(caPrincipal.getName(), policy);
                    validPoliciesCache.put(caPrincipal.getName(), now);
                }
            }
            loaded = true;
        } catch (SigningPolicyStoreException e) {
            if ((invalidCacheTime == null) || (now - invalidCacheTime >= 10 * CACHE_TIME_MILLIS)) {
                logger.warn("Failed to load signing policy: " + filename + " : " + e.getMessage());
                logger.debug("Failed to load signing policy: " + filename, e);
                invalidPoliciesCache.put(filename, now);
            }
        }

        return loaded;
    }
}
