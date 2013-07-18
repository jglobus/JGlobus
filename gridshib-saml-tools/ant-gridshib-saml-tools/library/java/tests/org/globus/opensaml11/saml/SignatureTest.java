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
import java.io.FileInputStream;
import java.security.KeyStore;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;

import junit.framework.TestCase;

/**
 * @author Scott Cantor
 */
public class SignatureTest extends TestCase
{
    private String path = "data/org/globus/opensaml11/saml/test.jks";
    private String alias = "mykey";
    private char[] password = "opensaml".toCharArray();
    private KeyStore ks = null;
    private String xmlpath = "data/org/globus/opensaml11/saml/assertion.xml";
    private String sigalg = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
    private String digalg = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1;
    private int count = 1;

    /**
     * Constructor for SignatureTest.
     * @param arg0
     */
    public SignatureTest(String arg0)
    {
        super(arg0);
    }

    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(SignatureTest.class);
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

    public void testSignatureLoop() throws Exception
    {
        theTest t = new theTest();
        long total = 0;
        for (int i=0; i<count; i++) {
            long elapsed = System.currentTimeMillis();
            t.testSignature();
            total = total + System.currentTimeMillis() - elapsed;
        }
        //System.err.println("Avg Time (ms): " + (total / count));
    }

    private class theTest {
        private void testSignature() throws Exception
        {
            SAMLAssertion a = new SAMLAssertion(new FileInputStream(xmlpath));
            assertNotNull("No unsigned SAMLAssertion was generated.",a);
            a.sign(sigalg,digalg,ks.getKey(alias,password),null);
            String dump=a.toString();
            //System.err.println(dump);
            SAMLAssertion a2 = new SAMLAssertion(new ByteArrayInputStream(dump.getBytes()));
            assertNotNull("No signed SAMLAssertion was generated",a2);
            a.verify(ks.getCertificate(alias).getPublicKey());
        }
    }
}
