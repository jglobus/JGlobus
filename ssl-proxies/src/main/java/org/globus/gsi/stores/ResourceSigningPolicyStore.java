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
import org.globus.gsi.SigningPolicy;
import org.globus.gsi.provider.SigningPolicyStore;
import org.globus.gsi.provider.SigningPolicyStoreException;
import org.globus.gsi.provider.SigningPolicyStoreParameters;
import org.globus.gsi.util.CertificateIOUtil;
import org.globus.util.GlobusPathMatchingResourcePatternResolver;
import org.globus.util.GlobusResource;

import javax.security.auth.x500.X500Principal;

import java.net.URI;
import java.security.InvalidAlgorithmParameterException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

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
    private static final long CACHE_TIME_MILLIS = 3600*1000;
    private long lastUpdate = 0;
    
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
        String name = caPrincipal.getName();
        long now = System.currentTimeMillis();
        String hash = CertificateIOUtil.nameHash(caPrincipal);
        Long validCacheTime = validPoliciesCache.get(hash);
        Long invalidCacheTime = invalidPoliciesCache.get(hash);
        if ((invalidCacheTime != null) && (now - invalidCacheTime < 10*CACHE_TIME_MILLIS)) {
            return null;
        }
        if ((validCacheTime == null) || (now - validCacheTime >= CACHE_TIME_MILLIS) || !this.policyMap.containsKey(name)) {
            loadPolicy(hash);
        }
        return this.policyMap.get(name);
    }

    private synchronized void loadPolicy(String hash) throws SigningPolicyStoreException {

        String locations = this.parameters.getTrustRootLocations();
        GlobusResource[] resources;
        resources = globusResolver.getResources(locations);

        long now = System.currentTimeMillis();
        boolean found_policy = false;

        // Optimization: If we find a hash for this CA, only process that.
        // Otherwise, we will process all policies.
        for (GlobusResource resource : resources) {

            String filename = resource.getFilename();

            // Note invalidPoliciesCache contains both filenames and hashes!
            Long invalidCacheTime = invalidPoliciesCache.get(filename);
            if ((invalidCacheTime != null) && (now - invalidCacheTime < 10*CACHE_TIME_MILLIS)) {
                continue;
            }

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
                invalidCacheTime = invalidPoliciesCache.get(filename);
                if ((invalidCacheTime == null) || (now - invalidCacheTime >= 10*CACHE_TIME_MILLIS)) {
                    logger.warn("Failed to load signing policy: " + filename);
                    logger.debug("Failed to load signing policy: " + filename, e);
                    invalidPoliciesCache.put(filename, now);
                    invalidPoliciesCache.put(hash, now);
                }
                continue;
            }
            found_policy = true;
        }
        if (found_policy) {
            if (!validPoliciesCache.containsKey(hash)) {
                invalidPoliciesCache.put(hash, now);
            }
            return;
        }
        // Poor-man's implementation.  Note it is much more expensive than a hashed directory
        for (GlobusResource resource : resources) {
            String filename = resource.getFilename();
            Long invalidCacheTime = invalidPoliciesCache.get(filename);
            if ((invalidCacheTime != null) && (now - invalidCacheTime < 10*CACHE_TIME_MILLIS)) {
                continue;
            }
            try {
                loadSigningPolicy(resource, policyMap, signingPolicyFileMap);
            } catch (Exception e) {
                invalidCacheTime = invalidPoliciesCache.get(filename);
                if ((invalidCacheTime == null) || (now - invalidCacheTime >= 10*CACHE_TIME_MILLIS)) {
                    logger.warn("Failed to load signing policy: " + filename);
                    logger.debug("Failed to load signing policy: " + filename, e);
                    invalidPoliciesCache.put(filename, now);
                    invalidPoliciesCache.put(hash, now);
                }
                continue;
            }
        }
        if (!validPoliciesCache.containsKey(hash)) {
            invalidPoliciesCache.put(hash, now);
        }

    }

    private void loadSigningPolicy(
            GlobusResource policyResource, Map<String, SigningPolicy> policyMapToLoad,
            Map<URI, ResourceSigningPolicy> currentPolicyFileMap) throws SigningPolicyStoreException {

        if (!policyResource.isReadable()) {
            throw new SigningPolicyStoreException("Cannot read file");
        }
        URI uri = policyResource.getURI();

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
            long now = System.currentTimeMillis();
            for (SigningPolicy policy : policies) {
                X500Principal caPrincipal = policy.getCASubjectDN();
                policyMapToLoad.put(caPrincipal.getName(), policy);
                String hash = CertificateIOUtil.nameHash(caPrincipal);
                validPoliciesCache.put(hash, now);
            }
        }
    }
}
