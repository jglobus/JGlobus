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

package org.globus.opensaml11.saml.provider;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.globus.opensaml11.saml.*;
import org.globus.opensaml11.saml.artifact.*;
import org.w3c.dom.Element;


/**
 *  Default implementation of the SAML 1.x browser profiles
 *
 * @author     Scott Cantor (created February 3, 2005)
 */
public class BrowserProfileProvider implements SAMLBrowserProfile
{
    private static Logger log = Logger.getLogger(BrowserProfileProvider.class.getName());
    private static int skew = 1000 * SAMLConfig.instance().getIntProperty("org.globus.opensaml11.saml.clock-skew");

    public BrowserProfileProvider(Element e) {
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLBrowserProfile#receive(javax.servlet.http.HttpServletRequest)
     */
    public BrowserProfileRequest receive(HttpServletRequest requestContext) throws UnsupportedProfileException {
        BrowserProfileRequest bpr = new BrowserProfileRequest();
        bpr.SAMLResponse = requestContext.getParameter("SAMLResponse");
        if (bpr.SAMLResponse == null) {
            bpr.SAMLArt = requestContext.getParameterValues("SAMLart");
            if (bpr.SAMLArt == null || bpr.SAMLArt.length == 0)
                throw new UnsupportedProfileException("no SAMLResponse or SAMLart parameters supplied in HTTP request");
        }
        bpr.TARGET = requestContext.getParameter("TARGET");
        return bpr;
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLBrowserProfile#receive(StringBuffer, org.globus.opensaml11.saml.SAMLBrowserProfile.BrowserProfileRequest, String, org.globus.opensaml11.saml.ReplayCache, org.globus.opensaml11.saml.SAMLBrowserProfile.ArtifactMapper, int)
     */
    public BrowserProfileResponse receive(
            StringBuffer issuer,
            BrowserProfileRequest requestContext,
            String recipient,
            ReplayCache replayCache,
            ArtifactMapper artifactMapper,
            int minorVersion
            ) throws SAMLException
    {
        long now = System.currentTimeMillis();

        // Java handles the parameter parsing, so we just check the results.
        SAMLResponse response = null;
        SAMLAssertion assertion = null;
        SAMLAuthenticationStatement authnStatement = null;
        boolean wasPost = true;
        if (requestContext.SAMLResponse != null) {
            response = new SAMLResponse(new ByteArrayInputStream(Base64.decodeBase64(requestContext.SAMLResponse.getBytes())),minorVersion);
            if (log.isDebugEnabled())
                log.debug("decoded SAML response:\n" + response.toString());

            try {
                // Check security bits in the outer wrapper (Recipient and IssueInstant).
                if (XML.isEmpty(recipient) || !XML.safeCompare(recipient,response.getRecipient()))
                    throw new FatalProfileException("detected recipient mismatch in POST profile response");

                if (response.getIssueInstant().getTime() < now-(2*skew))
                    throw new ExpiredAssertionException("detected expired POST profile response");

                // We don't verify the signature, but at least check for one.
                if (!response.isSigned())
                    throw new FatalProfileException("detected unsigned POST profile response");
            }
            catch (SAMLException e) {
                if (issuer != null) {
                    Iterator assertions=response.getAssertions();
                    if (assertions.hasNext())
                        issuer.append(((SAMLAssertion)assertions.next()).getIssuer());
                }
                throw e;
            }
        }
        else {
            // Check for artifacts.
            if (requestContext.SAMLArt == null || requestContext.SAMLArt.length == 0)
                throw new FatalProfileException("no SAMLResponse or SAMLart parameters supplied");

            if (artifactMapper == null) {
                throw new FatalProfileException("support of artifact profile requires ArtifactMapper interface object");
            }

            // Import the artifacts.
            Artifact[] artifacts = new Artifact[requestContext.SAMLArt.length];
            for (int index = 0; index < requestContext.SAMLArt.length; index++) {
                try {
                    log.debug("processing encoded artifact (" + requestContext.SAMLArt[index] + ")");

                    // If a replay cache was provided, check for replay.
                    if (replayCache != null) {
                        String key = "A_" + requestContext.SAMLArt[index];
                        if (!replayCache.check(key,new Date(System.currentTimeMillis() + 2*skew)))
                            throw new ReplayedAssertionException("rejecting replayed artifact (" + requestContext.SAMLArt[index] + ")");
                    }
                    else
                        log.warn("replay cache was not provided, this is a potential security risk!");
                    artifacts[index] = SAMLArtifact.getTypeCode(requestContext.SAMLArt[index]).getParser().parse(requestContext.SAMLArt[index]);
                }
                catch (ArtifactParseException e) {
                    log.error("invalid artifact (" + requestContext.SAMLArt[index] + ")");
                    throw new FatalProfileException("unable to parse artifact");
                }
                catch (ArtifactParserException e) {
                    log.error("unrecognized artifact type (" + requestContext.SAMLArt[index] + ")");
                    throw new FatalProfileException("unable to build parser for received artifact, unknown type");
                }
            }

            // That's actually the hard part. The rest of the work is mostly done by the caller.
            // An exception might get tossed here, of course.
            SAMLRequest request = new SAMLRequest(Arrays.asList(artifacts));
            request.setMinorVersion(minorVersion);
            response = artifactMapper.resolve(request);
            wasPost = false;
        }

        // At this point, we have a seemingly valid response, either via POST or from an artifact callback.
        // This is messy. We have to basically guess as to where the authentication statement is, by finding
        // one with an appropriate subject confirmation method. We go for the first match inside a valid assertion.
        try {
            boolean bExpired = false;
            for (Iterator assertions=response.getAssertions(); assertion == null && assertions.hasNext();) {
                bExpired=false;
                SAMLAssertion a=(SAMLAssertion)assertions.next();

                // The assertion must be bounded front and back.
                Date notBefore=a.getNotBefore();
                Date notOnOrAfter=a.getNotOnOrAfter();
                if (notBefore == null || notOnOrAfter == null) {
                    log.debug("skipping assertion without time conditions...");
                    continue;
                }

                if (now + skew < notBefore.getTime()) {
                    bExpired=true;
                    log.debug("skipping assertion that's not yet valid...");
                    continue;
                }

                if (notOnOrAfter.getTime() <= now - skew) {
                    bExpired=true;
                    log.debug("skipping expired assertion...");
                    continue;
                }

                // Look for an authentication statement.
                for (Iterator statements=a.getStatements(); authnStatement == null && statements.hasNext();) {
                    SAMLStatement s=(SAMLStatement)statements.next();
                    if (!(s instanceof SAMLAuthenticationStatement))
                        continue;
                    SAMLAuthenticationStatement as=(SAMLAuthenticationStatement)s;

                    SAMLSubject subject=as.getSubject();
                    for (Iterator methods=subject.getConfirmationMethods(); methods.hasNext();) {
                        String m=(String)methods.next();
                        if ((wasPost && m.equals(SAMLSubject.CONF_BEARER)) ||
                            m.equals(SAMLSubject.CONF_ARTIFACT) || m.equals(SAMLSubject.CONF_ARTIFACT01)) {
                            authnStatement=as;
                            assertion=a;
                            break;
                        }
                    }
                }
            }
            if (authnStatement == null) {
                if (bExpired == true && response.getAssertions().hasNext())
                    throw new ExpiredAssertionException("unable to accept assertion because of clock skew");
                throw new FatalProfileException("unable to locate a valid authentication statement");
            }
            else if (wasPost) {
                // Check for assertion replay. With artifact, the back-channel acts as a replay guard.
                if (replayCache != null) {
                    String key="P_" + assertion.getId();
                    if (!replayCache.check(key,assertion.getNotOnOrAfter()))
                        throw new ReplayedAssertionException("rejecting replayed assertion ID (" + assertion.getId() + ")");
                }
                else
                    log.warn("replay cache was not provided, this is a serious security risk!");
            }
        }
        catch (SAMLException e) {
            if (issuer != null) {
                Iterator assertions=response.getAssertions();
                if (assertions.hasNext())
                    issuer.append(((SAMLAssertion)assertions.next()).getIssuer());
            }
            throw e;
        }

        // Copy over profile data.
        BrowserProfileResponse profileResponse = new BrowserProfileResponse();
        profileResponse.response = response;
        profileResponse.assertion = assertion;
        profileResponse.authnStatement = authnStatement;

        // Extract TARGET parameter, if any. Might be required in SAML, but this is more forgiving.
        profileResponse.TARGET=requestContext.TARGET;

        return profileResponse;
    }
}