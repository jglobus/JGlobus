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
import java.io.IOException;
import java.util.HashMap;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import junit.framework.TestCase;

/**
 * @author Scott Cantor
 */
public class SOAPHTTPBindingTest extends TestCase implements EntityResolver
{
    private String path = "data/org/globus/opensaml11/saml/test.jks";
    private String alias = "mykey";
    private String password = "opensaml";
    private String endpoint = "https://wayf.internet2.edu:8443/shibboleth-idp/AA";

    private String schemaContent =
        "<schema targetNamespace=\"urn:mace:shibboleth:1.0\" xmlns=\"http://www.w3.org/2001/XMLSchema\">" +
        "<complexType name=\"AttributeValueType\" mixed=\"true\">" +
        "<complexContent><extension base=\"anyType\"/></complexContent>" +
        "</complexType></schema>";

    /**
     * Constructor for POSTProfileTest.
     * @param arg0
     */
    public SOAPHTTPBindingTest(String arg0)
    {
        super(arg0);
    }

    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(SOAPHTTPBindingTest.class);
    }

    /**
     * @see TestCase#setUp()
     */
    protected void setUp() throws Exception
    {
        super.setUp();
        Logger.getRootLogger().setLevel(Level.OFF);
        HashMap map = new HashMap();
        map.put("shibboleth.xsd", this);
        XML.parserPool.registerSchemas(map);
        SAMLConfig.instance().setProperty("org.globus.opensaml11.saml.ssl.truststore", path);
        SAMLConfig.instance().setProperty("org.globus.opensaml11.saml.ssl.truststore-pwd", password);
    }

    /**
     * @see TestCase#tearDown()
     */
    protected void tearDown() throws Exception
    {
        super.tearDown();
    }

    public void testSOAPBinding() throws Exception
    {
        SAMLRequest r= new SAMLRequest(
            new SAMLAttributeQuery(
                new SAMLSubject(
                        new SAMLNameIdentifier("test-handle","urn:mace:inqueue:example.edu","urn:mace:shibboleth:test:nameIdentifier"),
                        null,null,null),
                null,null)
            );

        SAMLBinding b = SAMLBindingFactory.getInstance(SAMLSOAPBinding.SOAP);
        SAMLResponse r2 = b.send(endpoint,r,null);
        //r2.toStream(System.err);
        assertEquals(
            "Unable to obtain an affiliation attribute of member from SAML AA",
            ((SAMLAttribute)((SAMLAttributeStatement)((SAMLAssertion)r2.getAssertions().next()).getStatements().next()).getAttributes().next()).getValues().next().toString(),
            "member"
            );
    }

    /* (non-Javadoc)
     * @see org.xml.sax.EntityResolver#resolveEntity(java.lang.String, java.lang.String)
     */
    public InputSource resolveEntity(String publicId, String systemId) throws SAXException, IOException {
        if (systemId.equals("shibboleth.xsd"))
            return new InputSource(new ByteArrayInputStream(schemaContent.getBytes()));
        return null;
    }
}
