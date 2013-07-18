/*
 * Copyright 2008-2009 University of Illinois
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

package org.globus.gridshib.security.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;

import org.globus.gridshib.config.BootstrapConfigLoader;
import org.globus.gridshib.saml.SAMLToolsTestCase;
import org.globus.gridshib.security.saml.GlobusSAMLException;
import org.globus.gridshib.security.x509.GlobusSAMLCredential;

import org.globus.gsi.X509Credential;
import org.globus.gsi.CredentialException;

/**
 * @since 0.4.3
 */
public class GSIUtilTest extends SAMLToolsTestCase {

    private static final Class CLASS = GSIUtilTest.class;
    private static final String CLASSNAME = CLASS.getName();

    private static Log logger = LogFactory.getLog(CLASSNAME);

    private static final int SENDER_VOUCHES =
        GlobusSAMLCredential.SENDER_VOUCHES;

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CLASS);
    }

    public GSIUtilTest(String name) {
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

    public void testGetCredential() throws Exception {

        X509Credential cred = BootstrapConfigLoader.getCredentialDefault();
        String tmpdir = System.getProperty("java.io.tmpdir");
        File outfile = new File(tmpdir, "testcredential.pem");
        GSIUtil.writeCredentialToFile(cred, outfile);
        GSIUtil.getCredential(outfile, outfile);

        assertTrue("testGetCredential complete", true);
    }

    public void testCreateCredential() throws Exception {

        String keyStorePath =
            BootstrapConfigLoader.getKeyStorePathDefault();
        File keyStoreFile = new File(keyStorePath);
        char[] keyStorePassword =
            BootstrapConfigLoader.getKeyStorePasswordDefault();
        String keyStoreKeyAlias =
            BootstrapConfigLoader.getKeyStoreKeyAliasDefault();
        char[] keyStoreKeyPassword =
            BootstrapConfigLoader.getKeyStoreKeyPasswordDefault();

        X509Credential credential =
                GSIUtil.createCredential(keyStoreFile,
                                         keyStorePassword,
                                         keyStoreKeyAlias,
                                         keyStoreKeyPassword);
        logger.debug(credential.toString());

        // set the default issuing credential:
        GlobusSAMLCredential.setDefaultCredential(credential);

        // create new GlobusSAMLCredential:
        GlobusSAMLCredential issuingCred = null;
        try {
            issuingCred = new GlobusSAMLCredential("trscavo", SENDER_VOUCHES);
        } catch (GlobusSAMLException e) {
            String msg = "Unable to create Globus SAML credential";
            logger.error(msg, e);
            fail(msg);
        }

        /* The next block of code used to throw a wrapped
         * GeneralSecurityException because of the workaround
         * to Bug 5261 in GSIUtil.createCredential.
         * Or if that workaround was removed, and also the adjacent
         * workaround to Bug 4933, it would throw a ClassCastException.
         * The latter is fixed in CoG jglobus 1.5.2.  See
         *
         * http://bugzilla.globus.org/globus/show_bug.cgi?id=6220
         *
         * for details.
         *
         * The issue() method should not be expected to fail anymore.
         */

        X509Credential proxy = null;
        try {
            proxy = issuingCred.issue();
        } catch (GlobusSAMLException e) {
            String msg = "Unable to get the SAML token";
            logger.error(msg, e);
            fail(msg);
        } catch (CredentialException e) {
            String msg = "Unable to bind the SAML token to " +
                         "an X.509 proxy certificate";
            logger.error(msg, e);
            fail(msg);
        }
    }
}

