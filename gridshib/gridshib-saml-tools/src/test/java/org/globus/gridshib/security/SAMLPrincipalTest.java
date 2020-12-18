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
import org.globus.gridshib.security.SAMLPrincipal;

/**
 * @since 0.5.0
 */
public class SAMLPrincipalTest extends SAMLToolsTestCase {

    private static final Class CLASS = SAMLPrincipalTest.class;
    private static final String CLASSNAME = CLASS.getName();

    private static Log logger = LogFactory.getLog(CLASSNAME);

    private static String id = null;
    private static String issuer = null;
    private static String type = null;

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CLASS);
    }

    public SAMLPrincipalTest(String name) {
        super(name);
    }

    /**
     * @see TestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();

        id = "1234567890";
        issuer = "https://gridshib.globus.org/idp";
        type = "http://example.org/names/unspecified";
    }

    /**
     * @see TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    public void testSAMLPrincipal() throws Exception {

        SAMLPrincipal principal1 =
            new SAMLPrincipal(id, issuer, "john", type);
        assertTrue("Non-null SAMLPrincipal is null",
                   !principal1.equals(null));
        assertTrue("SAMLPrincipal is not equal to itself",
                   principal1.equals(principal1));

        SAMLPrincipal principal2 =
            new SAMLPrincipal(id, issuer, "john", type);
        assertTrue("Two SAMLPrincipals with same name not equal",
                   principal2.equals(principal1));

        SAMLPrincipal principal3 =
            new SAMLPrincipal(id, issuer, "mary", type);
        assertTrue("Unequal SAMLPrincipals are equal",
                   !principal3.equals(principal1));

        try {
            SAMLPrincipal principal4 =
                new SAMLPrincipal(id, issuer, null, type);
            String msg = "Failed to catch null principal name";
            logger.error(msg);
            fail(msg);
        } catch (IllegalArgumentException e) {
            logger.debug("Caught null principal name: " + e.getMessage());
        }
    }

    public void testSecurityAttributes() throws Exception {

        String name = "john";

        SAMLPrincipal principal =
            new SAMLPrincipal(id, issuer, name, type);

        // a new SAMLPrincipal has exactly one security attribute:
        Set attributes = principal.getAttributeNames();
        assertTrue("No security attributes found",
                   attributes.size() > 0);
        assertTrue("More than one security attribute found",
                   attributes.size() == 1);

        // the security attribute value is the SAMLPrincipal name:
        String value = principal.getAttributeValue(type);
        assertTrue("Unexpected security attribute found: " + value,
                   value.equals(name));
    }
}

