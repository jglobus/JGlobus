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
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class ResourceSigningPolicyStore implements SigningPolicyStore {
    
    private PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
    private Map<URI, ResourceSigningPolicy> signingPolicyFileMap = new HashMap<URI, ResourceSigningPolicy>();
    private Map<String, SigningPolicy> policyMap = new HashMap<String, SigningPolicy>();
    private ResourceSigningPolicyStoreParameters parameters;
    private Log logger = LogFactory.getLog(ResourceSigningPolicyStore.class.getCanonicalName());

    public ResourceSigningPolicyStore(SigningPolicyStoreParameters param) throws InvalidAlgorithmParameterException {
        if (param == null) {
            throw new IllegalArgumentException();
        }

        if (!(param instanceof ResourceSigningPolicyStoreParameters)) {
            throw new InvalidAlgorithmParameterException();

        }

        this.parameters = (ResourceSigningPolicyStoreParameters) param;
    }

    public SigningPolicy getSigningPolicy(X500Principal caPrincipal) throws SigningPolicyStoreException {

        if (caPrincipal == null) {
            return null;
        }
        loadPolicies();
        return this.policyMap.get(caPrincipal.getName());
    }

    private void loadPolicies() throws SigningPolicyStoreException {

        String locations = this.parameters.getTrustRootLocations();
        Resource[] resources;

        try {
            resources = resolver.getResources(locations);
        } catch (IOException e) {
            throw new SigningPolicyStoreException(e);
        }
        Map<String, SigningPolicy> newPolicyMap =
                new HashMap<String, SigningPolicy>();
        Map<URI, ResourceSigningPolicy> newPolicyFileMap =
                new HashMap<URI, ResourceSigningPolicy>();

        for (Resource resource : resources) {

            if (!resource.isReadable()) {
                logger.debug("Cannot read: " + resource.getFilename());
                continue;
            }

            try {
                loadSigningPolicy(resource, newPolicyMap, newPolicyFileMap);
            } catch (Exception e) {
                logger.warn("Failed to load signing policy: " + resource.getFilename(), e);
            }
        }

        this.policyMap = newPolicyMap;
        this.signingPolicyFileMap = newPolicyFileMap;
    }

    private void loadSigningPolicy(
            Resource policyResource, Map<String, SigningPolicy> policyMapToLoad,
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
