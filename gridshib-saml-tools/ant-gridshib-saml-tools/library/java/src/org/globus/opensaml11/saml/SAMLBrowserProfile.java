/*
 *  Copyright 2001-2005 Internet2
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.globus.opensaml11.saml;

import javax.servlet.http.HttpServletRequest;

/**
 *  Interface to the SAML 1.x browser profiles. The SAML 1.x profiles are
 *  destination/SP-side only, thus only "acceptance" of the profile message
 *  is modeled.
 *
 * @author     Scott Cantor (created February 3, 2005)
 */
public interface SAMLBrowserProfile
{
    public final static String PROFILE_ARTIFACT_URI = "urn:oasis:names:tc:SAML:1.0:profiles:artifact-01";
    public final static String PROFILE_POST_URI = "urn:oasis:names:tc:SAML:1.0:profiles:browser-post";

    /**
     *  Wrapper for the pieces of the profile response available to the caller
     */
    public class BrowserProfileResponse
    {
        /** The profile response after initial processing */
        public SAMLResponse response = null;

        /** The primary authn assertion (identified by its profile-specific features) */
        public SAMLAssertion assertion = null;

        /** The primary authn statement (the first qualifying statement in the authn assertion) */
        public SAMLAuthenticationStatement authnStatement = null;

        /** TARGET profile parameter received with response */
        public String TARGET = null;
    }

    /**
     *  Wrapper for the pieces of the profile request provided to the profile provider
     */
    public class BrowserProfileRequest
    {
        public String SAMLResponse = null;
        public String SAMLArt[] = null;
        public String TARGET = null;
    }

    /**
     * Interface provided by SAML application to enable SAML 1.x artifacts to be
     * resolved.
     */
    public interface ArtifactMapper
    {
        /**
         *  Resolves 1 or more SAML 1.x artifacts into assertions
         *
         * @param request  The SAML message containing the artifacts to resolve
         * @return  The SAML response containing the resolved assertions
         * @throws SAMLException    Raised if an error occurs while resolving the artifacts
         */
        public abstract SAMLResponse resolve(SAMLRequest request) throws SAMLException;
    }

    /**
     *  Processes an HTTP request into a browser profile request.
     *
     * @param requestContext    The HTTP request from the client
     * @return  The profile request information extracted from the HTTP request
     * @throws UnsupportedProfileException  Raised if the HTTP request data cannot be successfully parsed
     */
    public BrowserProfileRequest receive(HttpServletRequest requestContext) throws UnsupportedProfileException;

    /**
     *  Processes an incoming POST or Artifact profile response. Use the supportedProfiles
     *  parameter to specify support for one or both profiles. Upon completion, the response
     *  parameter will contain the SAML objects delivered by the profile. Signature verification
     *  is <b>not</b> performed by the default implementation but may be handled by alternate
     *  or subclassed versions.
     *
     * @param issuer            A buffer in which to store the issuer of the security
     *  token being processed, to assist in responding to errors
     * @param requestContext    The HTTP request containing the profile response
     * @param recipient         The HTTP endpoint to which the response was delivered
     * @param replayCache       An org.globus.opensaml11.saml.ReplayCache interface to enable replay detection
     * @param artifactMapper    An ArtifactMapper interface to support artifact lookup/mapping
     *  (may be null if only POST is supported)
     * @param minor             The minor version to support
     * @return  A wrapper object containing the data returned by the profile
     * @throws SAMLException    Raised if an error occurs during profile processing
     */
    public BrowserProfileResponse receive(
            StringBuffer issuer,
            BrowserProfileRequest requestContext,
            String recipient,
            ReplayCache replayCache,
            ArtifactMapper artifactMapper,
            int minor
            ) throws SAMLException;
}
