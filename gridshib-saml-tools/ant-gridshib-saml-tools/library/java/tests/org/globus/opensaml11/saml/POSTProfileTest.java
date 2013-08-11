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

import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.xml.security.signature.XMLSignature;

import junit.framework.TestCase;

/**
 * @author Scott Cantor
 */
public class POSTProfileTest extends TestCase
{
    private String path = "data/org/globus/opensaml11/saml/test.jks";
    private String alias = "mykey";
    private char[] password = "opensaml".toCharArray();
    private KeyStore ks = null;

    /**
     * Constructor for POSTProfileTest.
     * @param arg0
     */
    public POSTProfileTest(String arg0)
    {
        super(arg0);
    }

    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(POSTProfileTest.class);
    }

    /**
     * @see TestCase#setUp()
     */
    protected void setUp() throws Exception
    {
        super.setUp();
        Logger.getRootLogger().setLevel(Level.OFF);
        ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(path), password);
    }

    /**
     * @see TestCase#tearDown()
     */
    protected void tearDown() throws Exception
    {
        super.tearDown();
    }

    public void testPOSTProfile() throws Exception
    {
        SAMLBrowserProfile profile = SAMLBrowserProfileFactory.getInstance();
        SAMLIdentifier idgen = SAMLIdentifierFactory.getInstance();
        SAMLResponse r = new SAMLResponse();
        SAMLAssertion a = new SAMLAssertion();
        SAMLAuthenticationStatement s = new SAMLAuthenticationStatement();
        SAMLSubject subject = new SAMLSubject(
                new SAMLNameIdentifier("foo", null, null),
                Collections.singleton(SAMLSubject.CONF_BEARER), null, null
                );
        s.setSubject(subject);
        s.setAuthInstant(new Date());
        s.setAuthMethod(SAMLAuthenticationStatement.AuthenticationMethod_Password);
        a.addStatement(s);
        a.setId(idgen.getIdentifier());
        a.setIssuer("http://www.opensaml.org");
        a.setNotBefore(new Date());
        a.setNotOnOrAfter(new Date(System.currentTimeMillis() + 60000));
        a.addCondition(new SAMLAudienceRestrictionCondition(Collections.singleton("http://www.opensaml.org")));
        r.addAssertion(a);
        r.setId(idgen.getIdentifier());
        r.setRecipient("http://www.opensaml.org");
        r.toDOM();

        a.sign(
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1,
            ks.getKey(alias,password),
            Arrays.asList(ks.getCertificateChain(alias))
            );
        r.sign(
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1,
            ks.getKey(alias,password),
            Arrays.asList(ks.getCertificateChain(alias))
            );
        assertTrue("SAMLResponse is not signed.",r.isSigned());
        //System.err.println("================ Generated Response ===============");
        //r.toStream(System.err);
        //System.err.println();

        r.verify(ks.getCertificate(alias));

        SAMLBrowserProfile.BrowserProfileRequest request = new SAMLBrowserProfile.BrowserProfileRequest();
        request.SAMLResponse = new String(r.toBase64());
        SAMLBrowserProfile.BrowserProfileResponse response = profile.receive(
                null,
                request,
                "http://www.opensaml.org",
                ReplayCacheFactory.getInstance(),
                null,
                1);
        assertTrue("SAMLResponse is not signed.",response.response.isSigned());
        response.assertion.verify(ks.getCertificate(alias));
        response.response.verify(ks.getCertificate(alias));
        //System.err.println("================ Verified Response ===============");
        //response.response.toStream(System.err);
        //System.err.println();
    }
}
