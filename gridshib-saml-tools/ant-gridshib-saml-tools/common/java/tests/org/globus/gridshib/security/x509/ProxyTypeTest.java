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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.globus.gridshib.config.BootstrapConfigLoader;
import org.globus.gridshib.saml.SAMLToolsTestCase;

import org.globus.gsi.GSIConstants;
import org.globus.gsi.X509Credential;
import org.globus.gsi.CredentialException;
import org.globus.gsi.X509Extension;
import org.globus.gsi.X509ExtensionSet;
import org.globus.gsi.bc.BouncyCastleCertProcessingFactory;

/**
 * This application tests the ability of the Globus code
 * to issue the correct type of proxy credential, based
 * on the type of the issuing credential.
 * <p>
 * This unit test originated with
 * <a href="http://bugzilla.globus.org/globus/show_bug.cgi?id=5715">Bug 5715</a>.
 *
 * @since 0.3.0
 */
public class ProxyTypeTest extends SAMLToolsTestCase {

    private static final Class CLASS = ProxyTypeTest.class;
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

    public ProxyTypeTest(String name) {
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

    public void testProxyTypes() throws Exception {

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
        extensions.add(extension);

        GSIConstants.CertificateType proxyTypeLegacy =
                GSIConstants.CertificateType.GSI_2_PROXY;
        GSIConstants.CertificateType proxyTypePreRFC =
                GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY;
        GSIConstants.CertificateType proxyTypeRFC =
                GSIConstants.CertificateType.GSI_4_IMPERSONATION_PROXY;

        /* The following block of code works around a Globus bug:
         *
         * http://bugzilla.globus.org/bugzilla/show_bug.cgi?id=5750
         *
         * If the issuing credential is an EEC, force the proxy to
         * be an RFC proxy.
         */
        X509Credential proxy1 = null;
        try {
            proxy1 =
                createProxy(credential,
                            extensions,
                            DEFAULT_LIFETIME,
                            proxyTypeRFC);
        } catch (CredentialException e) {
            String msg = "Unable to create proxy credential";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Proxy #1 is not an RFC proxy",
                   proxy1.getProxyType() == proxyTypeRFC);

        // issue a level 2 legacy proxy:
        X509Credential proxy2 = null;
        try {
            proxy2 =
                createProxy(createProxy(credential,
                                        extensions,
                                        DEFAULT_LIFETIME,
                                        proxyTypeLegacy),
                            extensions,
                            DEFAULT_LIFETIME,
                            GSIConstants.DelegationType.FULL);
        } catch (CredentialException e) {
            String msg = "Unable to create proxy credential";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Proxy #2 is not a legacy proxy",
                   proxy2.getProxyType() == proxyTypeLegacy);

        // issue a level 2 pre-RFC proxy:
        X509Credential proxy3 = null;
        try {
            proxy3 =
                createProxy(createProxy(credential,
                                        extensions,
                                        DEFAULT_LIFETIME,
                                        proxyTypePreRFC),
                            extensions,
                            DEFAULT_LIFETIME,
                            GSIConstants.DelegationType.FULL);
        } catch (CredentialException e) {
            String msg = "Unable to create proxy credential";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Proxy #3 is not a pre-RFC proxy",
                   proxy3.getProxyType() == proxyTypePreRFC);

        // issue a level 2 RFC proxy:
        X509Credential proxy4 = null;
        try {
            proxy4 =
                createProxy(createProxy(credential,
                                        extensions,
                                        DEFAULT_LIFETIME,
                                        proxyTypeRFC),
                            extensions,
                            DEFAULT_LIFETIME,
                            GSIConstants.DelegationType.FULL);
        } catch (CredentialException e) {
            String msg = "Unable to create proxy credential";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Proxy #4 is not an RFC proxy",
                   proxy4.getProxyType() == proxyTypeRFC);
    }

    private static X509Credential createProxy(X509Credential credential,
                                                X509ExtensionSet extensions,
                                                int lifetime, GSIConstants.CertificateType proxyType)
                                         throws CredentialException {
        try {
            return certFactory.createCredential(
                credential.getCertificateChain(),
                (PrivateKey)credential.getPrivateKey(),
                512,
                lifetime,
                proxyType,
                extensions, null);
        } catch (GeneralSecurityException e) {
            throw new CredentialException("Failed to load credentials.", e);
        }
    }

    private static X509Credential createProxy(X509Credential credential,
                                              X509ExtensionSet extensions,
                                              int lifetime, GSIConstants.DelegationType delegType)
                                        throws CredentialException {
        try {
            return certFactory.createCredential(
                    credential.getCertificateChain(),
                    (PrivateKey)credential.getPrivateKey(),
                    512,
                    lifetime,
                    delegType,
                    extensions, null);
        } catch (GeneralSecurityException e) {
            throw new CredentialException("Failed to load credentials.", e);
        }
    }
}