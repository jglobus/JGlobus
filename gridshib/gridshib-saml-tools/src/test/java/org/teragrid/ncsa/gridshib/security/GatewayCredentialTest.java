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

package org.teragrid.ncsa.gridshib.security;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Iterator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.saml.SAMLToolsTestCase;
import org.globus.gridshib.security.saml.GlobusSAMLException;
import org.globus.gridshib.security.saml.SelfIssuedAssertion;
import org.globus.gridshib.security.saml.SimpleAttribute;
import org.globus.gridshib.security.x509.SAMLX509Extension;

import org.globus.gsi.X509Credential;
import org.globus.gsi.CredentialException;

import org.globus.opensaml11.saml.SAMLAttribute;
import org.globus.opensaml11.saml.SAMLAttributeStatement;
import org.globus.opensaml11.saml.SAMLAuthenticationStatement;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLNameIdentifier;
import org.globus.opensaml11.saml.SAMLStatement;
import org.globus.opensaml11.saml.SAMLSubjectAssertion;

import org.teragrid.ncsa.gridshib.security.x509.GatewayCredential;

/**
 * Simple test of <code>GatewayCredential</code> class.
 *
 * @see org.teragrid.ncsa.gridshib.security.x509.GatewayCredential
 *
 * @since 0.3.0
 */
public class GatewayCredentialTest extends SAMLToolsTestCase {

    private static final Class CLASS = GatewayCredentialTest.class;
    private static final String CLASSNAME = CLASS.getName();

    private static Log logger = LogFactory.getLog(CLASSNAME);

    private static String username = null;

    private static final String MAIL = GatewayCredential.MAIL;
    private static String email1 = null;
    private static String email2 = null;

    private static String authnMethod = null;
    private static Date authnInstant = null;
    private static String ipAddress = null;

    private static String myAttributeName = null;
    private static String myAttributeValue1 = null;
    private static String myAttributeValue2 = null;

    private static GatewayCredential credential = null;

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CLASS);
    }

    public GatewayCredentialTest(String name) {
        super(name);
    }

    /**
     * @see SAMLToolsTestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();

        logger.debug("Setting up GatewayCredentialTest");

        // portal login:
        username = "trscavo";

        // e-mail addresses:
        email1 = "trscavo@gmail.com";
        email2 = "trscavo@ncsa.uiuc.edu";

        // authn context:
        authnMethod =
            SAMLAuthenticationStatement.AuthenticationMethod_Password;
        // wholly contrived authnInstant, 5 mins in the past:
        authnInstant = new Date(new Date().getTime() - 1000*60*5);
        ipAddress = "255.255.255.255";

        // urn:mace:dir:attribute-def:eduPersonAffiliation:
        myAttributeName = "urn:oid:1.3.6.1.4.1.5923.1.1.1.1";
        myAttributeValue1 = "member";
        myAttributeValue2 = "staff";

        logger.debug("Creating a GatewayCredential instance");
        try {
            credential = new GatewayCredential(username);
        } catch (GlobusSAMLException e) {
            String msg = "Unable to create GatewayCredential instance";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Usernames (" + username + " and " +
                   credential.getUsername() + ") do not match",
                   credential.getUsername().equals(username));
        assertTrue("Credential does not contain a " +
                   "sender-vouches SAML assertion",
                   credential.isSenderVouches());

        logger.debug("Adding an authn statement to GatewayCredential");
        credential.setAuthnContext(authnMethod, authnInstant, ipAddress);
    }

    /**
     * @see SAMLToolsTestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        super.tearDown();

        logger.debug("Tearing down GatewayCredentialTest");
    }

    /**
     * Issue a typical <code>GatewayCredential</code>
     * and verify its content.
     */
    public void testGatewayCredential() throws Exception {

        logger.debug("Running testGatewayCredential");

        // add an e-mail address:
        if (credential.addEmailAddress(email1)) {
            logger.debug("E-mail address added: " + email1);
        } else {
            String msg = "E-mail address not added: " + email1;
            logger.error(msg);
            fail(msg);
        }

        SelfIssuedAssertion assertion = null;
        try {
            assertion = credential.getSAMLToken();
        } catch (GlobusSAMLException e) {
            String msg = "Unable to get the SAML token";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Assertion is null", assertion != null);
        logger.debug(assertion.toString());

        checkNameID(assertion);
        checkEmailAddress(assertion);
        checkAuthnContext(assertion);

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

        SAMLSubjectAssertion assertion0 = null;
        X509Certificate cert = proxy.getCertificateChain()[0];
        try {
            assertion0 = SAMLX509Extension.getSAMLAssertion(cert);
        } catch (IOException e) {
            String msg = "Unable to decode certificate extension";
            logger.error(msg, e);
            fail(msg);
        } catch (SAMLException e) {
            String msg = "Unable to convert extension to SAMLAssertion";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Assertion is null", assertion0 != null);
        logger.debug(assertion0.toString());

        checkNameID(assertion0);
        checkEmailAddress(assertion0);
        checkAuthnContext(assertion0);
    }

    /**
     * Issue a <code>GatewayCredential</code> with other attributes
     * and verify its content.
     */
    public void testExtendedGatewayCredential() throws Exception {

        logger.debug("Running testExtendedGatewayCredential");

        // add two e-mail addresses:
        if (credential.addEmailAddresses(new String[]{email1, email2})) {
            logger.debug("Two e-mail addresses added: " +
                         email1 + " and " + email2);
        } else {
            String msg = "E-mail addresses not added";
            logger.error(msg);
            fail(msg);
        }

        // add another attribute:
        SimpleAttribute myAttribute = null;
        String[] myAttributeValues =
            new String[]{myAttributeValue1, myAttributeValue2};
        try {
            myAttribute =
                new SimpleAttribute(myAttributeName, myAttributeValues);
        } catch (SAMLException e) {
            String msg = "Unable to create attribute: " + myAttributeName;
            logger.error(msg, e);
            fail(msg);
        }
        if (credential.addAttribute(myAttribute)) {
            logger.debug("Custom attribute added: " + myAttributeName);
        } else {
            String msg = "Custom attribute not added: " + myAttributeName;
            logger.warn(msg);
            fail(msg);
        }

        SelfIssuedAssertion assertion = null;
        try {
            assertion = credential.getSAMLToken();
        } catch (GlobusSAMLException e) {
            String msg = "Unable to get the SAML token";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Assertion is null", assertion != null);
        logger.debug(assertion.toString());

        checkNameID(assertion);
        checkAuthnContext(assertion);
        checkAttributes(assertion);

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

        SAMLSubjectAssertion assertion0 = null;
        X509Certificate cert = proxy.getCertificateChain()[0];
        try {
            assertion0 = SAMLX509Extension.getSAMLAssertion(cert);
        } catch (IOException e) {
            String msg = "Unable to decode certificate extension";
            logger.error(msg, e);
            fail(msg);
        } catch (SAMLException e) {
            String msg = "Unable to convert extension to SAMLAssertion";
            logger.error(msg, e);
            fail(msg);
        }
        assertTrue("Assertion is null", assertion0 != null);
        logger.debug(assertion0.toString());

        checkNameID(assertion0);
        checkAuthnContext(assertion0);
        checkAttributes(assertion0);
    }

    private void checkNameID(SAMLSubjectAssertion assertion) {

        logger.debug("Running checkNameID");

        SAMLNameIdentifier nameid =
            assertion.getSubject().getNameIdentifier();
        logger.debug(nameid.toString());
        String name = nameid.getName();
        assertTrue("Name identifier is null", name != null);
        if (name.matches(".*" + username + ".*")) {
            logger.debug("Name identifier (" + name + ") " +
                         "contains username " + username);
            return;
        }
        fail("Name identifier (" + name + ") " +
             "does not contain username " + username);
    }

    private void checkEmailAddress(SAMLSubjectAssertion assertion) {

        logger.debug("Running checkEmailAddress");

        // search for SAML attribute statement:
        Iterator statements = assertion.getStatements();
        while (statements.hasNext()) {
            SAMLStatement statement = (SAMLStatement)statements.next();
            if (statement instanceof SAMLAttributeStatement) {
                logger.info("Checking SAML AttributeStatement");
                SAMLAttributeStatement attrStatement =
                    (SAMLAttributeStatement)statement;
                logger.debug(attrStatement.toString());
                Iterator attributes = attrStatement.getAttributes();
                while (attributes.hasNext()) {
                    SAMLAttribute attribute = (SAMLAttribute)attributes.next();
                    String name = attribute.getName();
                    if (name.equals(MAIL)) {
                        Iterator values = attribute.getValues();
                        if (values.hasNext()) {
                            String value = (String)values.next();
                            if (value.equals(email1)) {
                                logger.debug("Email address checked");
                                return;
                            }
                            fail("Found attribute value " + value +
                                 ", expected " + email1);
                        }
                    }
                    logger.debug("Found attribute " + name +
                                 ", looking for " + MAIL);
                }
            }
        }
        fail("Expected attribute not found");
    }

    private void checkAuthnContext(SAMLSubjectAssertion assertion) {

        logger.debug("Running checkAuthnContext");

        // search for SAML authentication statement:
        Iterator statements = assertion.getStatements();
        while (statements.hasNext()) {
            SAMLStatement statement = (SAMLStatement)statements.next();
            if (statement instanceof SAMLAuthenticationStatement) {
                logger.debug("Checking SAML AuthenticationStatement");
                SAMLAuthenticationStatement authnStmt =
                    (SAMLAuthenticationStatement)statement;
                logger.debug(authnStmt.toString());
                assertTrue("Authn methods are not equal",
                           authnStmt.getAuthMethod().equals(authnMethod));
                assertTrue("Authn instants are not equal",
                           authnStmt.getAuthInstant().equals(authnInstant));
                assertTrue("IP addresses are not equal",
                           authnStmt.getSubjectIP().equals(ipAddress));
                logger.debug("Authn context checked");
                return;
            }
        }
        fail("Authentication statement not found");
    }

    // TODO: check attribute values
    private void checkAttributes(SAMLSubjectAssertion assertion) {

        logger.debug("Running checkAttributes");

        // search for SAML attribute statement:
        Iterator statements = assertion.getStatements();
        while (statements.hasNext()) {
            SAMLStatement statement = (SAMLStatement)statements.next();
            if (statement instanceof SAMLAttributeStatement) {
                logger.info("Checking SAML AttributeStatement");
                SAMLAttributeStatement attrStatement =
                    (SAMLAttributeStatement)statement;
                logger.debug(attrStatement.toString());
                boolean hasMail, hasMyAttribute;
                hasMail = hasMyAttribute = false;
                Iterator attributes = attrStatement.getAttributes();
                while (attributes.hasNext()) {
                    SAMLAttribute attribute = (SAMLAttribute)attributes.next();
                    String name = attribute.getName();
                    if (name.equals(MAIL)) {
                        logger.debug("Found attribute " + name);
                        hasMail = true;
                        if (hasMyAttribute) { return; }
                    } else if (name.equals(myAttributeName)) {
                        logger.debug("Found attribute " + name);
                        hasMyAttribute = true;
                        if (hasMail) { return; }
                    } else {
                        logger.debug("Found attribute " + name +
                                     ", looking for " + MAIL +
                                     " or " + myAttributeName);
                    }
                }
            }
        }
        fail("Expected attributes not found");
    }
}
