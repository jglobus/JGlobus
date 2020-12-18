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

//import java.io.BufferedWriter;
//import java.io.File;
//import java.io.FileWriter;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

//import org.globus.gridshib.common.StringSetFile;
//import org.globus.gridshib.config.BootstrapConfigLoader;
import org.globus.gridshib.saml.SAMLToolsTestCase;
import org.globus.gridshib.security.BasicAttribute;
import org.globus.gridshib.security.SAMLPrincipal;

/**
 * @since 0.4.3
 */
public class BasicAttributeTest extends SAMLToolsTestCase {

    private static final Class CLASS = BasicAttributeTest.class;
    private static final String CLASSNAME = CLASS.getName();

    private static Log logger = LogFactory.getLog(CLASSNAME);

    private static String id = null;
    private static String issuer = null;

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CLASS);
    }

    public BasicAttributeTest(String name) {
        super(name);
    }

    /**
     * @see TestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();

        // This unit test is dependent on the default bootstrap
        // properties file

        //File f = File.createTempFile("identity-attributes", "txt");
        //BufferedWriter writer = new BufferedWriter(new FileWriter(f));
        //writer.write("urn:mace:dir:attribute-def:mail");
        //writer.newLine();
        //writer.write("urn:oid:0.9.2342.19200300.100.1.3");
        //writer.close();

        //StringSetFile idAttributes = new StringSetFile(f);
        //BootstrapConfigLoader.setIdentityAttributes(idAttributes);

        id = "1234567890";
        issuer = "https://gridshib.globus.org/idp";
    }

    /**
     * @see TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    public void testImmutableBasicAttribute() throws Exception {

        String name = "urn:mace:dir:attribute-def:mail";
        String nameFormat = null;
        String value1 = "trscavo@gmail.com";
        String value2 = "trscavo@illinois.edu";

        BasicAttribute attribute =
            new BasicAttribute(id, issuer, name, nameFormat, value1);
        attribute.setTrusted(true);   // attribute is now immutable

        try {
            attribute.setTrusted(false);
        } catch (IllegalArgumentException e) {
            logger.debug("Exception expected: " + e.getMessage());
        }
        assertTrue("BasicAttribute should still be trusted",
                   attribute.isTrusted());

        assertTrue("Unexpected number of attribute values",
                   attribute.getValues().length == 1);
        attribute.addValue(value2);
        assertTrue("Unexpected number of attribute values",
                   attribute.getValues().length == 1);
    }

    public void testIdentityAttribute() throws Exception {

        String name = "urn:mace:dir:attribute-def:mail";
        String nameFormat = null;
        String value = "trscavo@gmail.com";

        BasicAttribute attribute =
            new BasicAttribute(id, issuer, name, nameFormat, value);
        assertTrue("No SAMLPrincipals expected",
                   attribute.getSAMLPrincipals().size() == 0);
        attribute.setTrusted(true);   // attribute is now immutable
        assertTrue("One SAMLPrincipal expected",
                   attribute.getSAMLPrincipals().size() == 1);
        SAMLPrincipal principal1 =
            new SAMLPrincipal(id, issuer, value, name);
        assertTrue("The SAMLPrincipals do not contain the expected value",
                   attribute.getSAMLPrincipals().contains(principal1));
        String email = "trscavo@uiuc.edu";
        attribute.addValue(email);  // ignored (see logs)
        SAMLPrincipal principal2 =
            new SAMLPrincipal(id, issuer, email, name);
        assertTrue("The SAMLPrincipals contain an unexpected value",
                   !attribute.getSAMLPrincipals().contains(principal2));
    }

    public void testNonIdentityAttribute() throws Exception {

        String name = "urn:mace:dir:attribute-def:eduPersonPrincipalName";
        String nameFormat = null;
        String value = "trscavo@uiuc.edu";

        BasicAttribute attribute =
            new BasicAttribute(id, issuer, name, nameFormat, value);
        assertTrue("No SAMLPrincipals expected",
                   attribute.getSAMLPrincipals().size() == 0);
        attribute.setTrusted(true);   // attribute is now immutable
        assertTrue("No SAMLPrincipals expected",
                   attribute.getSAMLPrincipals().size() == 0);
    }

    public void testSecurityAttributes() throws Exception {

        String name = "urn:mace:dir:attribute-def:mail";
        String nameFormat = null;
        String value1 = "trscavo@gmail.com";
        String value2 = "trscavo@illinois.edu";

        // testing a single-valued BasicAttribute:
        BasicAttribute attribute =
            new BasicAttribute(id, issuer, name, nameFormat, value1);

        // a new BasicAttribute has no security attributes:
        Set attributes = attribute.getAttributeNames();
        assertTrue("Unexpected security attribute found",
                   attributes.size() == 0);

        attribute.setTrusted(true);

        // a trusted BasicAttribute has exactly one security attribute:
        attributes = attribute.getAttributeNames();
        assertTrue("No security attributes found",
                   attributes.size() > 0);
        assertTrue("More than one security attribute found",
                   attributes.size() == 1);

        // this security attribute has exactly one value:
        Set values = attribute.getAttributeValues(name);
        assertTrue("No security attribute values found",
                   values.size() > 0);
        assertTrue("More than one security attribute value found",
                   values.size() == 1);
        String value = attribute.getAttributeValue(name);
        assertTrue("Security attribute value found: " + value1,
                   value.equals(value1));

        // testing a multi-valued BasicAttribute:
        attribute = new BasicAttribute(id, issuer, name, nameFormat, value1);
        attribute.addValue(value2);

        // a new BasicAttribute has no security attributes:
        attributes = attribute.getAttributeNames();
        assertTrue("Unexpected security attribute found",
                   attributes.size() == 0);

        attribute.setTrusted(true);

        // a trusted BasicAttribute has exactly one security attribute:
        attributes = attribute.getAttributeNames();
        assertTrue("No security attributes found",
                   attributes.size() > 0);
        assertTrue("More than one security attribute found",
                   attributes.size() == 1);

        // this security attribute has exactly two values:
        values = attribute.getAttributeValues(name);
        assertTrue("No security attribute values found",
                   values.size() > 0);
        assertTrue("Only one security attribute value found",
                   values.size() > 1);
        assertTrue("More than two security attribute values found",
                   values.size() == 2);
        assertTrue("Security attribute value not found: " + value1,
                   values.contains(value1));
        assertTrue("Security attribute value not found: " + value2,
                   values.contains(value2));
    }
}

