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

package org.globus.gridshib.security;

import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.saml.SAMLToolsTestCase;
import org.globus.gridshib.security.SAMLIdentity;

import org.globus.opensaml11.saml.SAMLNameIdentifier;

/**
 * @since 0.4.3
 */
public class SAMLIdentityTest extends SAMLToolsTestCase {

    private static final Class CLASS = SAMLIdentityTest.class;
    private static final String CLASSNAME = CLASS.getName();

    private static Log logger = LogFactory.getLog(CLASSNAME);

    private static String id = null;
    private static String issuer = null;
    private static String name = null;
    private static String nameQualifier = null;
    private static String format = null;

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CLASS);
    }

    public SAMLIdentityTest(String name) {
        super(name);
    }

    /**
     * @see TestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();

        id = "1234567890";
        issuer = "https://gridshib.globus.org/idp";

        name = "trscavo";
        format = SAMLNameIdentifier.FORMAT_UNSPECIFIED;
    }

    /**
     * @see TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    public void testImmutableSAMLIdentity() throws Exception {

        SAMLIdentity identity =
            new SAMLIdentity(id, issuer, name, null, format);
        identity.setTrusted(true);   // identity is now immutable

        try {
            identity.setTrusted(false);
        } catch (IllegalArgumentException e) {
            logger.debug("Exception expected: " + e.getMessage());
        }
        assertTrue("SAMLIdentity should still be trusted",
                   identity.isTrusted());
    }

    public void testUnqualifiedSAMLIdentity() throws Exception {

        SAMLIdentity identity =
            new SAMLIdentity(id, issuer, name, null, format);
        assertTrue("Null SAMLPrincipal expected",
                   identity.getSAMLPrincipal() == null);
        identity.setTrusted(true);
        assertTrue("Non-null SAMLPrincipal expected",
                   identity.getSAMLPrincipal() != null);
    }

    public void testQualifiedSAMLIdentity() throws Exception {

        String nameQualifier = "ncsa.uiuc.edu";
        SAMLIdentity identity =
            new SAMLIdentity(id, issuer, name, nameQualifier, format);
        assertTrue("Null SAMLPrincipal expected",
                   identity.getSAMLPrincipal() == null);
        identity.setTrusted(true);
        assertTrue("Null SAMLPrincipal expected",
                   identity.getSAMLPrincipal() == null);
    }

    public void testSecurityAttributes() throws Exception {

        SAMLIdentity identity =
            new SAMLIdentity(id, issuer, name, null, format);

        // a new SAMLIdentity has no security attributes:
        Set attributes = identity.getAttributeNames();
        assertTrue("Unexpected security attribute found",
                   attributes.size() == 0);

        identity.setTrusted(true);

        // a trusted SAMLIdentity has exactly one security attribute:
        attributes = identity.getAttributeNames();
        assertTrue("No security attributes found",
                   attributes.size() > 0);
        assertTrue("More than one security attribute found",
                   attributes.size() == 1);

        // the security attribute value is the SAMLIdentity name:
        String value = identity.getAttributeValue(format);
        assertTrue("Unexpected security attribute found: " + value,
                   value.equals(name));
    }
}

