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
import java.io.FileInputStream;
import java.util.Iterator;

import javax.xml.namespace.QName;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import junit.framework.TestCase;

/**
 * @author Scott Cantor
 */
public class SAMLAttributeTest extends TestCase {

    private String xmlpath = "data/org/globus/opensaml11/saml/SAMLAttributeTest.xml";

    public SAMLAttributeTest(String arg0) {

        super(arg0);
        Logger.getRootLogger().setLevel(Level.OFF);
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(SAMLAttributeTest.class);
    }

    public void testSAMLAttribute() throws Exception {

        SAMLAttribute attribute =
            new SAMLAttribute(new FileInputStream(xmlpath));
        attribute.addValue("Bar");
        attribute.setType(new QName(XML.XSD_NS,"string"));
        //attribute.toStream(System.err);

        String name = attribute.getName();
        String namespace = attribute.getNamespace();
        QName type = attribute.getType();
        SAMLAttribute attribute2 =
            new SAMLAttribute(name, namespace, type, 0, null);
        assertTrue("Attributes are not equal",
                   attribute.equals(attribute2));

        byte[] bytes = attribute.toString().getBytes();
        SAMLAttribute attribute3 =
            new SAMLAttribute(new ByteArrayInputStream(bytes));

        Iterator values = attribute3.getValues();
        assertEquals(values.next().toString(), "");
        assertEquals(values.next().toString(), "Bar");
        assertEquals(attribute3.getType(), new QName(XML.XSD_NS,"string"));

        assertTrue("Attribute values do not match",
                   attribute.hasEqualValues(attribute3));
    }
}
