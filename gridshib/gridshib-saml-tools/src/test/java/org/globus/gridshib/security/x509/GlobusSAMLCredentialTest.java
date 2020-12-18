/*
 * Copyright 2008-2009 University of Illinois
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

import java.util.Date;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.config.BootstrapConfigLoader;
import org.globus.gridshib.saml.SAMLToolsTestCase;
import org.globus.gridshib.security.saml.GlobusSAMLException;
import org.globus.gridshib.security.saml.SelfIssuedAssertion;
import org.globus.gridshib.security.saml.SimpleAttribute;
import org.globus.gridshib.security.x509.GlobusSAMLCredential;

import org.globus.gsi.X509Credential;
import org.globus.gsi.CredentialException;

import org.globus.opensaml11.saml.SAMLAuthenticationStatement;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLNameIdentifier;

/**
 * Unit test for <code>GlobusSAMLCredential</code> class.
 *
 * @see org.globus.gridshib.security.x509.GlobusSAMLCredential
 *
 * @since 0.3.0
 */
public class GlobusSAMLCredentialTest extends SAMLToolsTestCase {

    private static final Class CLASS = GlobusSAMLCredentialTest.class;
    private static final String CLASSNAME = CLASS.getName();

    private static Log logger = LogFactory.getLog(CLASSNAME);

    private static final int HOLDER_OF_KEY =
        GlobusSAMLCredential.HOLDER_OF_KEY;
    private static final int SENDER_VOUCHES =
        GlobusSAMLCredential.SENDER_VOUCHES;

    private static final String username = "trscavo";
    private static final String email = "trscavo@gmail.com";

    // the urn:mace:dir:attribute-def:mail attribute:
    private static final String MAIL =
        "urn:oid:0.9.2342.19200300.100.1.3";

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CLASS);
    }

    public GlobusSAMLCredentialTest(String name) {
        super(name);
    }

    /**
     * @see SAMLToolsTestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();

        logger.debug("Setting up GlobusSAMLCredentialTest");
    }

    /**
     * @see SAMLToolsTestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        super.tearDown();

        logger.debug("Tearing down GlobusSAMLCredentialTest");
    }

    /**
     * Test <code>GlobusSAMLCredential</code> constructors.
     */
    public void testConstructors() throws Exception {

        GlobusSAMLCredential credential1 = null;
        try {
            credential1 = new GlobusSAMLCredential();
        } catch (GlobusSAMLException e) {
            String msg = "Unable to create Globus SAML credential";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Credential does not contain a " +
                   "holder-of-key SAML assertion",
                   credential1.isHolderOfKey());
        logger.debug(credential1.getSAMLToken().toString());

        GlobusSAMLCredential credential2 = null;
        try {
            credential2 = new GlobusSAMLCredential(null, HOLDER_OF_KEY);
        } catch (GlobusSAMLException e) {
            String msg = "Unable to create Globus SAML credential";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Credential does not contain a " +
                   "holder-of-key SAML assertion",
                   credential2.isHolderOfKey());
        logger.debug(credential2.getSAMLToken().toString());

        SelfIssuedAssertion assertion1 = null;
        SelfIssuedAssertion assertion2 = null;
        try {
            assertion1 = credential1.getSAMLToken();
            assertion2 = credential2.getSAMLToken();
        } catch (GlobusSAMLException e) {
            String msg = "Unable to get the SAML token";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Assertion #1 is null", assertion1 != null);
        assertTrue("Assertion #2 is null", assertion2 != null);

        String name1 = assertion1.getSubject().getNameIdentifier().getName();
        String name2 = assertion2.getSubject().getNameIdentifier().getName();
        assertTrue("Name #1 is null", name1 != null);
        assertTrue("Name #2 is null", name2 != null);
        assertTrue("SAML subject name identifiers are not equal",
                   name1.equals(name2));

        X500Principal dn1 = null;
        try {
            dn1 = new X500Principal(name1);
        } catch (NullPointerException e) {
            String msg = "Name #1 is null";
            logger.error(msg, e);
            fail(msg);
        } catch (IllegalArgumentException e) {
            String msg = "Name #1 is not a recognized DN";
            logger.error(msg, e);
            fail(msg);
        }
        X500Principal dn2 = null;
        try {
            dn2 = new X500Principal(name2);
        } catch (NullPointerException e) {
            String msg = "Name #2 is null";
            logger.error(msg, e);
            fail(msg);
        } catch (IllegalArgumentException e) {
            String msg = "Name #2 is not a recognized DN";
            logger.error(msg, e);
            fail(msg);
        }

        GlobusSAMLCredential credential3 = null;
        try {
            credential3 = new GlobusSAMLCredential(username, HOLDER_OF_KEY);
        } catch (GlobusSAMLException e) {
            String msg = "Unable to create Globus SAML credential";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Usernames (" + username + " and " +
                   credential3.getUsername() + ") do not match",
                   credential3.getUsername().equals(username));
        assertTrue("Credential does not contain a " +
                   "holder-of-key SAML assertion",
                   credential3.isHolderOfKey());
        logger.debug(credential3.getSAMLToken().toString());

        GlobusSAMLCredential credential4 = null;
        try {
            credential4 = new GlobusSAMLCredential(username, SENDER_VOUCHES);
        } catch (GlobusSAMLException e) {
            String msg = "Unable to create Globus SAML credential";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Usernames (" + username + " and " +
                   credential4.getUsername() + ") do not match",
                   credential4.getUsername().equals(username));
        assertTrue("Credential does not contain a " +
                   "sender-vouches SAML assertion",
                   credential4.isSenderVouches());
        logger.debug(credential4.getSAMLToken().toString());
    }

    /**
     * Test
     * {@link org.globus.gridshib.security.x509.GlobusSAMLCredential#setAuthnContext(String, Date, String)}
     * method.
     */
    public void testSetAuthnContextMethod() throws Exception {

        // create GlobusSAMLCredential with sender-vouches token:
        GlobusSAMLCredential credential = null;
        try {
            credential = new GlobusSAMLCredential(username, SENDER_VOUCHES);
        } catch (GlobusSAMLException e) {
            String msg = "Unable to create Globus SAML credential";
            logger.error(msg, e);
            fail(msg);
        }

        // add authn context (i.e., AuthenticationStatement):
        String authnMethod =
          SAMLAuthenticationStatement.AuthenticationMethod_Password;
        // wholly contrived authnInstant, 5 mins in the past:
        Date authnInstant = new Date(new Date().getTime() - 1000*60*5);
        String ipAddress = "255.255.255.255";
        credential.setAuthnContext(authnMethod, authnInstant, ipAddress);

        // issue a proxy with SAML token:
        X509Credential proxy = null;
        try {
            proxy = credential.issue();
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
        logger.debug(credential.getSAMLToken().toString());

        // create GlobusSAMLCredential with holder-of-key token:
        try {
            credential = new GlobusSAMLCredential();
        } catch (GlobusSAMLException e) {
            String msg = "Unable to create Globus SAML credential";
            logger.error(msg, e);
            fail(msg);
        }

        // oops, a holder-of-key token may not have an authn context:
        credential.setAuthnContext(authnMethod, authnInstant, ipAddress);

        logger.debug("Testing bogus SAML token");
        try {
            proxy = credential.issue();
            fail("Issued credential containing a bogus SAML token");
        } catch (GlobusSAMLException e) {
            String msg = "Successfully caught bogus SAML token";
            logger.debug(msg);
        } catch (CredentialException e) {
            String msg = "Unable to bind bogus SAML token to " +
                         "an X.509 proxy certificate";
            logger.error(msg, e);
            fail(msg);
        }
    }

    /**
     * Test
     * {@link org.globus.gridshib.security.x509.GlobusSAMLCredential#setDefaultCredential(X509Credential)}
     * and
     * {@link org.globus.gridshib.security.x509.GlobusSAMLCredential#setCredential(X509Credential)}
     * methods.
     * <p>
     * The default config file distributed with GS-ST does not
     * explicitly configure an issuing credential, so calling the
     * <code>setDefaultCredential</code> method has the desired
     * effect.  To make this test bulletproof, we could introduce
     * a config file into the unit test framework.
     */
    public void testSetCredentialMethods() throws Exception {

        // create GlobusSAMLCredential with sender-vouches token:
        GlobusSAMLCredential credential = null;
        try {
            credential = new GlobusSAMLCredential(username, SENDER_VOUCHES);
        } catch (GlobusSAMLException e) {
            String msg = "Unable to create Globus SAML credential";
            logger.error(msg, e);
            fail(msg);
        }

        // add authn context (i.e., AuthenticationStatement):
        String authnMethod =
          SAMLAuthenticationStatement.AuthenticationMethod_Password;
        // wholly contrived authnInstant, 5 mins in the past:
        Date authnInstant = new Date(new Date().getTime() - 1000*60*5);
        String ipAddress = "255.255.255.255";
        credential.setAuthnContext(authnMethod, authnInstant, ipAddress);

        // issue a level 1 proxy with a SAML token:
        X509Credential proxy1a = null;
        try {
            proxy1a = credential.issue();
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
        logger.debug(credential.getSAMLToken().toString());

        SelfIssuedAssertion assertion1a = null;
        try {
            assertion1a = credential.getSAMLToken();
        } catch (GlobusSAMLException e) {
            String msg = "Unable to get the SAML token";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Assertion1a is null", assertion1a != null);

        // save the default issuing credential for the final test:
        X509Credential savedCred =
            BootstrapConfigLoader.getCredentialDefault();

        // set the default issuing credential for the duration:
        GlobusSAMLCredential.setDefaultCredential(proxy1a);

        // create new GlobusSAMLCredential:
        try {
            credential = new GlobusSAMLCredential(username, SENDER_VOUCHES);
        } catch (GlobusSAMLException e) {
            String msg = "Unable to create Globus SAML credential";
            logger.error(msg, e);
            fail(msg);
        }

        // issue a level 2 proxy with a SAML token:
        X509Credential proxy2a = null;
        try {
            proxy2a = credential.issue();
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
        logger.debug(credential.getSAMLToken().toString());

        SelfIssuedAssertion assertion2a = null;
        try {
            assertion2a = credential.getSAMLToken();
        } catch (GlobusSAMLException e) {
            String msg = "Unable to get the SAML token";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Assertion #2a is null", assertion2a != null);

        // check chain length:
        assertTrue("Proxy certificate chain lengths do not check out",
                   1 + proxy1a.getCertNum() == proxy2a.getCertNum());

        // check issuers:
        assertTrue("Proxy issuers are equal",
                   !proxy1a.getIssuer().equals(proxy2a.getIssuer()));
        assertTrue("Assertion issuers are equal",
                   !assertion1a.getIssuer().equals(assertion2a.getIssuer()));

        // create new GlobusSAMLCredential:
        try {
            credential = new GlobusSAMLCredential(username, SENDER_VOUCHES);
        } catch (GlobusSAMLException e) {
            String msg = "Unable to create Globus SAML credential";
            logger.error(msg, e);
            fail(msg);
        }

        // create a new set of attributes:
        credential.setAttributes(null);
        SimpleAttribute attribute = null;
        try {
            attribute = new SimpleAttribute(MAIL, email);
        } catch (SAMLException e) {
            String msg = "Unable to create attribute: " + MAIL;
            logger.error(msg, e);
            fail(msg);
        }
        credential.addAttribute(attribute);

        // issue another level 2 proxy with a new SAML token:
        X509Credential proxy2b = null;
        try {
            proxy2b = credential.issue();
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
        logger.debug(credential.getSAMLToken().toString());

        SelfIssuedAssertion assertion2b = null;
        try {
            assertion2b = credential.getSAMLToken();
        } catch (GlobusSAMLException e) {
            String msg = "Unable to get the SAML token";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Assertion #2b is null", assertion2b != null);

        // check chain length:
        assertTrue("Proxy certificate chain lengths are not equal",
                   proxy2a.getCertNum() == proxy2b.getCertNum());

        // check issuers:
        assertTrue("Proxy issuers are not equal",
                   proxy2a.getIssuer().equals(proxy2b.getIssuer()));
        assertTrue("Assertion issuers are not equal",
                   assertion2a.getIssuer().equals(assertion2b.getIssuer()));

        // create new GlobusSAMLCredential:
        try {
            credential = new GlobusSAMLCredential(username, SENDER_VOUCHES);
        } catch (GlobusSAMLException e) {
            String msg = "Unable to create Globus SAML credential";
            logger.error(msg, e);
            fail(msg);
        }

        // set the issuing credential for this instance only:
        credential.setCredential(savedCred);

        // issue another level 1 proxy with a new SAML token:
        X509Credential proxy1b = null;
        try {
            proxy1b = credential.issue();
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
        logger.debug(credential.getSAMLToken().toString());

        SelfIssuedAssertion assertion1b = null;
        try {
            assertion1b = credential.getSAMLToken();
        } catch (GlobusSAMLException e) {
            String msg = "Unable to get the SAML token";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Assertion #1b is null", assertion1b != null);

        // check chain length:
        assertTrue("Proxy certificate chain lengths are not equal",
                   proxy1a.getCertNum() == proxy1b.getCertNum());

        // check issuers:
        assertTrue("Proxy issuers are not equal",
                   proxy1a.getIssuer().equals(proxy1b.getIssuer()));
        assertTrue("Assertion issuers are not equal",
                   assertion1a.getIssuer().equals(assertion1b.getIssuer()));
    }

    /**
     * Test
     * {@link org.globus.gridshib.security.x509.GlobusSAMLCredential#setNameQualifier(String)}
     * method.
     */
    public void testSetNameQualiferMethod() throws Exception {

        GlobusSAMLCredential credential1 = null;
        try {
            credential1 = new GlobusSAMLCredential(username, SENDER_VOUCHES);
        } catch (GlobusSAMLException e) {
            String msg = "Unable to create Globus SAML credential";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Credential does not contain a " +
                   "sender-vouches SAML assertion",
                   credential1.isSenderVouches());
        credential1.setNameQualifier("foo");
        logger.debug(credential1.getSAMLToken().toString());

        GlobusSAMLCredential credential2 = null;
        try {
            credential2 = new GlobusSAMLCredential(username, SENDER_VOUCHES);
        } catch (GlobusSAMLException e) {
            String msg = "Unable to create Globus SAML credential";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Credential does not contain a " +
                   "sender-vouches SAML assertion",
                   credential2.isSenderVouches());
        credential2.setNameQualifier("bar");
        logger.debug(credential2.getSAMLToken().toString());

        SelfIssuedAssertion assertion1 = null;
        SelfIssuedAssertion assertion2 = null;
        try {
            assertion1 = credential1.getSAMLToken();
            assertion2 = credential2.getSAMLToken();
        } catch (GlobusSAMLException e) {
            String msg = "Unable to get the SAML token";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Assertion #1 is null", assertion1 != null);
        assertTrue("Assertion #2 is null", assertion2 != null);

        String qualifier1 =
            assertion1.getSubject().getNameIdentifier().getNameQualifier();
        String qualifier2 =
            assertion2.getSubject().getNameIdentifier().getNameQualifier();
        assertTrue("Name #1 is null", qualifier1 != null);
        assertTrue("Name #2 is null", qualifier2 != null);
        assertTrue("SAML subject name qualifiers are equal",
                   !qualifier1.equals(qualifier2));

        credential2.setNameQualifier(credential1.getNameQualifier());
        logger.debug(credential2.getSAMLToken().toString());

        try {
            assertion2 = credential2.getSAMLToken();
        } catch (GlobusSAMLException e) {
            String msg = "Unable to get the SAML token";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Assertion #2 is null", assertion2 != null);

        qualifier2 =
            assertion2.getSubject().getNameIdentifier().getNameQualifier();
        assertTrue("Name #2 is null", qualifier2 != null);
        assertTrue("SAML subject name qualifiers are not equal",
                   qualifier1.equals(qualifier2));
    }

    /**
     * Test
     * {@link org.globus.gridshib.security.x509.GlobusSAMLCredential#setFormat(String,String)}
     * method.
     */
    public void testSetFormatMethod() throws Exception {

        String format1 = SAMLNameIdentifier.FORMAT_UNSPECIFIED;
        String template1 = "%PRINCIPAL%";
        String format2 = SAMLNameIdentifier.FORMAT_EMAIL;
        String template2 = "%PRINCIPAL%@gmail.com";

        GlobusSAMLCredential credential1 = null;
        try {
            credential1 = new GlobusSAMLCredential(email, SENDER_VOUCHES);
        } catch (GlobusSAMLException e) {
            String msg = "Unable to create Globus SAML credential";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Credential does not contain a " +
                   "sender-vouches SAML assertion",
                   credential1.isSenderVouches());
        credential1.setFormat(format1, template1);
        logger.debug(credential1.getSAMLToken().toString());

        GlobusSAMLCredential credential2 = null;
        try {
            credential2 = new GlobusSAMLCredential(username, SENDER_VOUCHES);
        } catch (GlobusSAMLException e) {
            String msg = "Unable to create Globus SAML credential";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Credential does not contain a " +
                   "sender-vouches SAML assertion",
                   credential2.isSenderVouches());
        credential2.setFormat(format2, template2);
        logger.debug(credential2.getSAMLToken().toString());

        SelfIssuedAssertion assertion1 = null;
        SelfIssuedAssertion assertion2 = null;
        try {
            assertion1 = credential1.getSAMLToken();
            assertion2 = credential2.getSAMLToken();
        } catch (GlobusSAMLException e) {
            String msg = "Unable to get the SAML token";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Assertion #1 is null", assertion1 != null);
        assertTrue("Assertion #2 is null", assertion2 != null);

        String name1 =
            assertion1.getSubject().getNameIdentifier().getName();
        String name2 =
            assertion2.getSubject().getNameIdentifier().getName();
        assertTrue("Name #1 is null", name1 != null);
        assertTrue("Name #2 is null", name2 != null);
        assertTrue("SAML subject name identifiers are not equal",
                   name1.equals(name2));

        assertTrue("Unexpected formatted name for credential1",
                   credential1.getFormattedName().equals(name2));
        assertTrue("Unexpected formatted name for credential2",
                   credential2.getFormattedName().equals(name1));
    }
}
