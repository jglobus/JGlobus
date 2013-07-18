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

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeMap;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;


/**
 *  Basic implementation of SAML POST browser profile.
 *  This is a deprecated and limited interface that will
 *  not be maintained and may be removed in a future version.
 *  Please use the SAMLBrowserProfile factory and default
 *  provider instead of this class.
 *
 * @author     Scott Cantor (created April 1, 2002)
 * @deprecated
 */
public class SAMLPOSTProfile
{
    private static Logger log = Logger.getLogger(SAMLPOSTProfile.class.getName());
    private static TreeMap replayExpMap = new TreeMap();
    private static HashSet replayCache = new HashSet();

    /**
     *  Locates an assertion containing a "bearer" AuthenticationStatement in
     *  the response and validates the enclosing assertion with respect to the
     *  POST profile
     *
     * @param  r          The response to the accepting site
     * @param  audiences  The set of audience values to test any conditions
     *      against
     * @return            An SSO assertion
     *
     * @throws org.globus.opensaml11.saml.SAMLException    Thrown if a valid SSO assertion cannot be found
     */
    public static SAMLAssertion getSSOAssertion(SAMLResponse r, Collection audiences)
        throws SAMLException
    {
        int acount = 0;
        boolean bExpired = false;

        Iterator assertions = r.getAssertions();
        assertion_loop :
        while (assertions.hasNext())
        {
            acount++;
            bExpired = false;
            SAMLAssertion a=(SAMLAssertion)assertions.next();

            // A SSO assertion must be bounded front and back.
            Date notBefore = a.getNotBefore();
            Date notOnOrAfter = a.getNotOnOrAfter();
            if (notBefore == null || notOnOrAfter == null)
                continue;

            if (notBefore.getTime() - 300000 > System.currentTimeMillis())
            {
                bExpired = true;
                continue;
            }

            if (notOnOrAfter.getTime() + 300000 <= System.currentTimeMillis())
            {
                bExpired = true;
                continue;
            }

            // Check conditions. The only type we know about is an audience restriction.
            Iterator conditions = a.getConditions();
            while (conditions.hasNext())
            {
                SAMLCondition c=(SAMLCondition)conditions.next();
                if (!(c instanceof SAMLAudienceRestrictionCondition) ||
                    !((SAMLAudienceRestrictionCondition)c).eval(audiences))
                    continue assertion_loop;
            }

            // Look for an authentication statement.
            Iterator statements = a.getStatements();
            while (statements.hasNext())
            {
                SAMLStatement s=(SAMLStatement)statements.next();
                if (!(s instanceof SAMLAuthenticationStatement))
                    continue;

                SAMLSubject subject=((SAMLAuthenticationStatement)s).getSubject();
                Iterator methods=subject.getConfirmationMethods();
                while (methods.hasNext())
                    if (((String)methods.next()).equals(SAMLSubject.CONF_BEARER))
                        return a;
            }
        }
        if (bExpired == true && acount == 1)
            throw new ExpiredAssertionException(SAMLException.RESPONDER,"SAMLPOSTProfile.getSSOAssertion() unable to find a SSO assertion with valid time condition");

        throw new FatalProfileException(SAMLException.RESPONDER,"SAMLPOSTProfile.getSSOAssertion() unable to find a valid SSO assertion");
    }

    /**
     *  Locates a "bearer" AuthenticationStatement in the assertion and
     *  validates the statement with respect to the POST profile
     *
     * @param  a  The SSO assertion sent to the accepting site
     * @return    A "bearer" authentication statement
     *
     * @throws org.globus.opensaml11.saml.SAMLException    Thrown if a SSO statement cannot be found
     */
    public static SAMLAuthenticationStatement getSSOStatement(SAMLAssertion a)
        throws SAMLException
    {
        // Look for an authentication statement.
        Iterator statements = a.getStatements();
        while (statements.hasNext())
        {
            SAMLStatement s=(SAMLStatement)statements.next();
            if (!(s instanceof SAMLAuthenticationStatement))
                continue;

            SAMLSubject subject=((SAMLAuthenticationStatement)s).getSubject();
            Iterator methods=subject.getConfirmationMethods();
            while (methods.hasNext())
                if (((String)methods.next()).equals(SAMLSubject.CONF_BEARER))
                    return (SAMLAuthenticationStatement)s;
        }

        throw new FatalProfileException(SAMLException.RESPONDER,"SAMLPOSTProfile.getSSOStatement() unable to find a valid SSO statement");
    }

    /**
     *  Searches the replay cache for the specified assertion and inserts a
     *  newly seen assertion into the cache<P>
     *
     *  Also performs garbage collection of the cache by deleting expired
     *  entries.
     *
     * @param  a  The assertion to look up and possibly add
     * @return    true iff the assertion has not been seen before
     */
    public static synchronized boolean checkReplayCache(SAMLAssertion a)
    {
        // Garbage collect any expired entries.
        Set trash = replayExpMap.headMap(new Date()).keySet();
        for (Iterator i = trash.iterator(); i.hasNext(); replayCache.remove(replayExpMap.get(i.next())))
            ;
        trash.clear();

        // If it's already been seen, bail.
        if (!replayCache.add(a.getId()))
            return false;

        // Not a multi-map, so if there's duplicate timestamp, increment by a millisecond.
        Date expires = new Date(a.getNotOnOrAfter().getTime() + 300000);
        while (replayExpMap.containsKey(expires))
            expires.setTime(expires.getTime() + 1);

        // Add the pair to the expiration map.
        replayExpMap.put(expires, a.getId());
        return true;
    }

    /**
     *  Parse a Base-64 encoded buffer back into a SAML response and optionally test its
     *  validity against the POST profile<P>
     *
     *  The signature over the response is not verified or examined, nor is the
     *  identity of the signer. The replay cache is also not checked.
     *
     * @param  buf                A Base-64 encoded buffer containing a SAML
     *      response
     * @param  receiver           The URL of the intended consumer of the
     *      response
     * @param  ttlSeconds         Seconds allowed to lapse from the issuance of
     *      the response
     * @param  process            Process the response or just decode and parse it?
     * @return                    SAML response sent by origin site
     * @exception  org.globus.opensaml11.saml.SAMLException  Thrown if the response is invalid
     */
    public static SAMLResponse accept(byte[] buf, String receiver, int ttlSeconds, boolean process)
        throws SAMLException
    {

        try
        {
            SAMLResponse r = new SAMLResponse(new ByteArrayInputStream(Base64.decode(buf)));
            if (process)
                process(r, receiver, ttlSeconds);
            return r;
        }
        catch (Base64DecodingException e)
        {
            throw new InvalidAssertionException(SAMLException.REQUESTER, "SAMLPOSTProfile.accept() unable to decode base64 response");
        }
    }

    /**
     *  Test the validity of a response against the POST profile<P>
     *
     *  The signature over the response is not verified or examined, nor is the
     *  identity of the signer. The replay cache is also not checked.
     *
     * @param  r                  The response to process
     * @param  receiver           The URL of the intended consumer of the
     *      response
     * @param  ttlSeconds         Seconds allowed to lapse from the issuance of
     *      the response
     * @exception  org.globus.opensaml11.saml.SAMLException  Thrown if the response is invalid
     */
    public static void process(SAMLResponse r, String receiver, int ttlSeconds)
        throws SAMLException
    {
        if (receiver == null || receiver.length() == 0 || !receiver.equals(r.getRecipient()))
            throw new InvalidAssertionException(SAMLException.REQUESTER, "SAMLPOSTProfile.accept() detected recipient mismatch: " + r.getRecipient());
        if (r.getIssueInstant().getTime() + (1000 * ttlSeconds) + 300000 < System.currentTimeMillis())
            throw new ExpiredAssertionException(SAMLException.RESPONDER, "SAMLPOSTProfile.accept() detected expired response");
    }

    /**
     *  Used by authenticating site to generate a SAML response conforming to
     *  the POST profile<P>
     *
     *  The response MUST be signed by the caller before sending to relying
     *  site.<P>
     *
     *  Implementations that need to embed additional statements or more complex
     *  conditions can override or ignore this class.
     *
     * @param  recipient          URL of intended consumer
     * @param  issuer             Issuer of assertion
     * @param  audiences          URIs identifying intended relying
     *      parties/communities (optional)
     * @param  name               Name of subject
     * @param  nameQualifier      Federates or qualifies subject name (optional)
     * @param  format             URI describing name semantics and format
     *      (optional)
     * @param  subjectIP          Client address of subject (optional)
     * @param  authMethod         URI of authentication method being asserted
     * @param  authInstant        Date and time of authentication being asserted
     * @param  bindings           Set of SAML authorities the relying party
     *      may contact (optional)
     * @return                    SAML response to send to accepting site
     * @exception  org.globus.opensaml11.saml.SAMLException  Base class of exceptions that may be thrown
     *      during processing
     * @deprecated              Callers should prefer the overloaded method
     *      that accepts <code>SAMLNameIdentifier</code> objects
     */
     public static SAMLResponse prepare(
        String recipient,
        String issuer,
        Collection audiences,
        String name,
        String nameQualifier,
        String format,
        String subjectIP,
        String authMethod,
        Date authInstant,
        Collection bindings)
        throws SAMLException {

        return prepare(
            recipient,
            issuer,
            audiences,
            new SAMLNameIdentifier(name, nameQualifier, format),
            subjectIP,
            authMethod,
            authInstant,
            bindings);

    }
    /**
     *  Used by authenticating site to generate a SAML response conforming to
     *  the POST profile<P>
     *
     *  The response MUST be signed by the caller before sending to relying
     *  site.<P>
     *
     *  Implementations that need to embed additional statements or more complex
     *  conditions can override or ignore this class.
     *
     * @param  recipient          URL of intended consumer
     * @param  issuer             Issuer of assertion
     * @param  audiences          URIs identifying intended relying
     *      parties/communities (optional)
     * @param  nameId             Name Identifier representing the subject
     * @param  subjectIP          Client address of subject (optional)
     * @param  authMethod         URI of authentication method being asserted
     * @param  authInstant        Date and time of authentication being asserted
     * @param  bindings           Set of SAML authorities the relying party
     *      may contact (optional)
     * @return                    SAML response to send to accepting site
     * @exception  org.globus.opensaml11.saml.SAMLException  Base class of exceptions that may be thrown
     *      during processing
     */
    public static SAMLResponse prepare(String recipient,
                                        String issuer,
                                        Collection audiences,
                                        SAMLNameIdentifier nameId,
                                        String subjectIP,
                                        String authMethod,
                                        Date authInstant,
                                        Collection bindings)
        throws SAMLException
    {
        log.info("Creating SAML Response.");

        if (recipient == null || recipient.length() == 0)
            throw new SAMLException(SAMLException.RESPONDER, "SAMLPOSTProfile.prepare() requires recipient");

        Vector conditions = new Vector(1);
        if (audiences != null && audiences.size() > 0)
            conditions.add(new SAMLAudienceRestrictionCondition(audiences));

        String[] confirmationMethods = {SAMLSubject.CONF_BEARER};
        SAMLSubject subject = new SAMLSubject(nameId, Arrays.asList(confirmationMethods), null, null);
        SAMLStatement[] statements =
            {new SAMLAuthenticationStatement(subject, authMethod, authInstant, subjectIP, null, bindings)};
        SAMLAssertion[] assertions = {
            new SAMLAssertion(issuer, new Date(System.currentTimeMillis()), new Date(System.currentTimeMillis() + 300000),
                                conditions, null, Arrays.asList(statements))
            };

        return new SAMLResponse(null, recipient, Arrays.asList(assertions), null);
    }
}

