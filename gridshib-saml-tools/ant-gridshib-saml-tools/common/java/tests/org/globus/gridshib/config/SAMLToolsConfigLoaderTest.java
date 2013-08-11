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

package org.globus.gridshib.config;

import java.io.ByteArrayInputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.GridShibConfigException;
import org.globus.gridshib.saml.SAMLToolsTestCase;
import org.globus.gsi.X509Credential;
import org.globus.opensaml11.saml.SAMLAttribute;

/**
 * @since 0.4.3
 */
public class SAMLToolsConfigLoaderTest extends SAMLToolsTestCase {

    private static final Class CLASS = SAMLToolsConfigLoaderTest.class;
    private static final String CLASSNAME = CLASS.getName();

    private static Log logger = LogFactory.getLog(CLASSNAME);

    private static X509Credential defaultCred = null;
    private static String configProps = null;
    private static String entityID = null;
    private static String format = null;
    private static String template = null;
    private static String attributeName = null;
    private static String attributeValue = null;

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CLASS);
    }

    public SAMLToolsConfigLoaderTest(String name) {
        super(name);
    }

    /**
     * @see SAMLToolsTestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();

        defaultCred = BootstrapConfigLoader.getCredentialDefault();

        entityID = "https://gridshib.example.org/idp";
        format = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6";
        template = "%PRINCIPAL%@example.org";
        attributeName = "urn:oid:1.3.6.1.4.1.5923.1.5.1.1";
        attributeValue = "group://example.org/example";
        configProps =
            "IdP.entityID=" + entityID + "\n" +
            "NameID.Format=" + format + "\n" +
            "NameID.Format.template=" + template + "\n" +
            "Attribute.isMemberOf.Name=" + attributeName + "\n" +
            "Attribute.isMemberOf.Value=" + attributeValue + "\n";
    }

    /**
     * @see SAMLToolsTestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    public void testGetToolConfigMethod() throws Exception {

        SAMLToolsConfig config = SAMLToolsConfigLoader.getToolConfig();

        String configEntityID = config.getEntityID();
        assertTrue("The configured entityID is not null: " + configEntityID,
                   configEntityID == null);
        // the default config file sets the format to the default format:
        String configFormat = config.getFormat();
        assertTrue("Unexpected NameID format: " + configFormat,
                   configFormat.equals(SAMLToolsConfig.DEFAULT_FORMAT));
        // the default config file sets the template to the default template:
        String configTemplate = config.getTemplate();
        assertTrue("Unexpected NameID formatting template: " + configTemplate,
                   configTemplate.equals(SAMLToolsConfig.DEFAULT_TEMPLATE));
        String configQualifier = config.getNameQualifier();
        assertTrue("The configured NameQualifier is not null: " +
                   configQualifier, configQualifier == null);
        String dateTimePattern = config.getDateTimePattern();
        assertTrue("Unexpected dateTime pattern: " + dateTimePattern,
                   dateTimePattern.equals(SAMLToolsConfig.DEFAULT_PATTERN));
        X509Credential issuingCred = config.getCredential();
        assertTrue("The configured issuing credential is not equal to " +
                   "the default issuing credential",
                   (defaultCred == null ? issuingCred == null
                                        : issuingCred.equals(defaultCred)));
    }

    public void testLoadMethod() throws Exception {

        byte[] bytes = configProps.getBytes();
        SAMLToolsConfigLoader.load(new ByteArrayInputStream(bytes));
        SAMLToolsConfig config = SAMLToolsConfigLoader.getToolConfig();

        String configEntityID = config.getEntityID();
        assertTrue("Unexpected entityID: " + configEntityID,
                   configEntityID.equals(entityID));
        String configFormat = config.getFormat();
        assertTrue("Unexpected NameID format: " + configFormat,
                   configFormat.equals(format));
        String configTemplate = config.getTemplate();
        assertTrue("Unexpected NameID formatting template: " + configTemplate,
                   configTemplate.equals(template));
        String configQualifier = config.getNameQualifier();
        assertTrue("The configured NameQualifier is not null: " +
                   configQualifier, configQualifier == null);
        String dateTimePattern = config.getDateTimePattern();
        assertTrue("The configured dateTime pattern is " +
                   "unexpected: " + dateTimePattern,
                   dateTimePattern.equals(SAMLToolsConfig.DEFAULT_PATTERN));
        SAMLAttribute[] attributes = config.getAttributes();
        assertTrue("Unexpected number of configured attributes: " +
                   attributes.length, attributes.length == 1);
        assertTrue("Unexpected attribute name: " + attributes[0].getName(),
                   attributes[0].getName().equals(attributeName));
        String value = (String)(attributes[0].getValues().next());
        assertTrue("Unexpected attribute value: " + value,
                   value.equals(attributeValue));
        X509Credential issuingCred = config.getCredential();
        assertTrue("The configured issuing credential is not equal to " +
                   "the default issuing credential",
                   (defaultCred == null ? issuingCred == null
                                        : issuingCred.equals(defaultCred)));
    }

    public void testOverlayMethod() throws Exception {

        byte[] bytes = configProps.getBytes();
        SAMLToolsConfigLoader.load(new ByteArrayInputStream(bytes));
        entityID = "https://gridshib.example.org/idp2";
        attributeName = "urn:oid:0.9.2342.19200300.100.1.3";
        attributeValue = "trscavo@gmail.com";
        configProps =
            "IdP.entityID=" + entityID + "\n" +
            "Attribute.mail.Name=" + attributeName + "\n" +
            "Attribute.mail.Value=" + attributeValue + "\n";
        bytes = configProps.getBytes();
        SAMLToolsConfigLoader.overlay(new ByteArrayInputStream(bytes));
        SAMLToolsConfig config = SAMLToolsConfigLoader.getToolConfig();

        String configEntityID = config.getEntityID();
        assertTrue("Unexpected entityID: " + configEntityID,
                   configEntityID.equals(entityID));
        SAMLAttribute[] attributes = config.getAttributes();
        assertTrue("Unexpected number of configured attributes: " +
                   attributes.length, attributes.length == 2);
    }

    public void testCertsAndKeys() throws Exception {

        byte[] bytes;

        // test certLocation but no keyLocation:
        configProps ="certLocation=foo\n";
        bytes = configProps.getBytes();
        try {
            SAMLToolsConfigLoader.load(new ByteArrayInputStream(bytes));
            fail("certLocation but no keyLocation test failed");
        } catch (GridShibConfigException e) {
            logger.debug("Test correctly failed: " + e.getMessage());
        }

        // test keyLocation but no certLocation:
        configProps ="keyLocation=bar\n";
        bytes = configProps.getBytes();
        try {
            SAMLToolsConfigLoader.load(new ByteArrayInputStream(bytes));
            fail("keyLocation but no certLocation test failed");
        } catch (GridShibConfigException e) {
            logger.debug("Test correctly failed: " + e.getMessage());
        }

        // test certPath but no keyPath:
        configProps ="certPath=foo\n";
        bytes = configProps.getBytes();
        try {
            SAMLToolsConfigLoader.load(new ByteArrayInputStream(bytes));
            fail("certPath but no keyPath test failed");
        } catch (GridShibConfigException e) {
            logger.debug("Test correctly failed: " + e.getMessage());
        }

        // test keyPath but no certPath:
        configProps ="keyPath=bar\n";
        bytes = configProps.getBytes();
        try {
            SAMLToolsConfigLoader.load(new ByteArrayInputStream(bytes));
            fail("keyPath but no certPath test failed");
        } catch (GridShibConfigException e) {
            logger.debug("Test correctly failed: " + e.getMessage());
        }

        // test both locations and paths:
        configProps =
            "certLocation=foo\n" +
            "keyLocation=bar\n" +
            "certPath=foo\n" +
            "keyPath=bar\n";
        bytes = configProps.getBytes();
        try {
            SAMLToolsConfigLoader.load(new ByteArrayInputStream(bytes));
            fail("both key/cert locations and paths test failed");
        } catch (GridShibConfigException e) {
            logger.debug("Test correctly failed: " + e.getMessage());
        }
    }
}

