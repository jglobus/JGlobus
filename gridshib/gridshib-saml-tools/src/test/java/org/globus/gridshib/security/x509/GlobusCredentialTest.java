/*
 * Copyright 2007-2009 University of Illinois
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.globus.gridshib.security.x509;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.globus.gridshib.config.BootstrapConfigLoader;
import org.globus.gridshib.saml.SAMLToolsTestCase;

import org.globus.gsi.GSIConstants;
import org.globus.gsi.X509Credential;
import org.globus.gsi.X509Extension;
import org.globus.gsi.X509ExtensionSet;
import org.globus.gsi.bc.BouncyCastleCertProcessingFactory;
import org.globus.gsi.bc.BouncyCastleUtil;

/**
 * This test application issues a Globus proxy credential with
 * a non-critical certificate extension containing a simple
 * string.  It then recovers the extension content and compares
 * it to the original string.
 * <p>
 * This unit test originated with
 * <a href="http://bugzilla.globus.org/globus/show_bug.cgi?id=5601">Bug 5601</a>.
 *
 * @since 0.3.0
 */
public class GlobusCredentialTest extends SAMLToolsTestCase {

    private static final Class CLASS = GlobusCredentialTest.class;
    private static final String CLASSNAME = CLASS.getName();

    private static Log logger = LogFactory.getLog(CLASSNAME);

    // dummy test data:
    private static final String OID = "1.3.6.1.4.1.3536.1.0.0.0";
    private static final String TEST = "test";

    private static final int DEFAULT_LIFETIME;
    private static BouncyCastleCertProcessingFactory certFactory;

    static {

        DEFAULT_LIFETIME = 12*60*60;  // 12 hrs
        certFactory = BouncyCastleCertProcessingFactory.getDefault();
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CLASS);
    }

    public GlobusCredentialTest(String name) {
        super(name);
    }

    /**
     * @see SAMLToolsTestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();
    }

    /**
     * @see SAMLToolsTestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    public void testGlobusCredential() throws Exception {

        // get the default signing credential:
        X509Credential credential =
            BootstrapConfigLoader.getCredentialDefault();

        // create the certificate extension:
        DERUTF8String derString = new DERUTF8String(TEST);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream derOut = new DEROutputStream(bOut);
        try {
            derOut.writeObject(derString);
        } catch (IOException e) {
            String msg = "Unable to create certificate extension";
            logger.error(msg, e);
            fail(msg);
        }
        X509ExtensionSet extensions = new X509ExtensionSet();
        X509Extension extension =
            new X509Extension(OID, false, bOut.toByteArray());
        //X509Extension extension =
        //    new X509Extension(OID, false, TEST.getBytes());
        extensions.add(extension);

        // issue a proxy and bind the extension:
        X509Credential proxy = null;
        try {
            proxy = certFactory.createCredential(
                credential.getCertificateChain(),
                (PrivateKey)credential.getPrivateKey(),
                512,
                DEFAULT_LIFETIME,
                GSIConstants.CertificateType.GSI_4_IMPERSONATION_PROXY,
                extensions, null);
        } catch (GeneralSecurityException e) {
            String msg = "Unable to create proxy credential";
            logger.error(msg, e);
            fail(msg);
        }

        // recover the extension content:
        X509Certificate cert = proxy.getCertificateChain()[0];
        byte[] bytes = null;
        try {
            bytes = BouncyCastleUtil.getExtensionValue(cert, OID);
        } catch (IOException e) {
            String msg = "Unable to get extension value";
            logger.error(msg, e);
            fail(msg);
        }
        ASN1InputStream in =
            new ASN1InputStream(new ByteArrayInputStream(bytes));
        derString = null;
        try {
            derString = (DERUTF8String)in.readObject();
        } catch (IOException e) {
            String msg = "Cannot recover original extension value";
            logger.error(msg, e);
            fail(msg);
        }

        assertTrue("Extension values (\"" + TEST + "\" and \"" +
                   derString.getString() + "\") do not match",
                   TEST.equals(derString.getString()));
    }
}
