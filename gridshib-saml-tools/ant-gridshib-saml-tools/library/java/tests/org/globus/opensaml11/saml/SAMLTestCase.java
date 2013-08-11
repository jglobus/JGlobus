/*
 * Copyright 2005-2009 University of Illinois
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

import java.io.FileInputStream;
import java.io.InputStream;

import javax.xml.namespace.QName;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import junit.framework.TestCase;

/**
 * A test case with pre-formed SAML objects.
 * Test cases should extend this test case.
 *
 * @author Tom Scavo
 */
public class SAMLTestCase extends TestCase {

    private static Logger log =
        Logger.getLogger(SAMLTestCase.class.getName());

    private SAMLNameIdentifier nameid0 = null;
    private SAMLSubject subject0 = null;
    private SAMLAttribute attribute0 = null;
    private SAMLAttributeStatement statement0 = null;
    private SAMLAssertion assertion0 = null;

    public static void main(String[] args) {
        junit.textui.TestRunner.run(SAMLTestCase.class);
        BasicConfigurator.configure();
    }

    public SAMLTestCase(String name) {
        super(name);
        BasicConfigurator.resetConfiguration();
        BasicConfigurator.configure();
    }

    /**
     * @see TestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();

        Logger.getRootLogger().setLevel(Level.OFF);
        //Logger.getRootLogger().setLevel(Level.DEBUG);
        log.setLevel(Level.OFF);
        //log.setLevel(Level.DEBUG);

        String xmlPath = null;
        InputStream in = null;

        xmlPath =
            "data/org/globus/opensaml11/saml/nameid.xml";
        log.debug("XML path: " + xmlPath);
        in = new FileInputStream(xmlPath);
        nameid0 = new SAMLNameIdentifier(in);
        log.debug("Using nameid: " + nameid0.toString());

        SAMLNameIdentifier nameid = null;
        nameid = (SAMLNameIdentifier) nameid0.clone();
        subject0 = new SAMLSubject(nameid, null, null, null);
        log.debug("Using subject: " + subject0.toString());

        xmlPath =
            "data/org/globus/opensaml11/saml/attribute.xml";
        log.debug("XML path: " + xmlPath);
        in = new FileInputStream(xmlPath);
        attribute0 = SAMLAttribute.getInstance(in);
        attribute0.addValue("Bar");
        attribute0.setType(new QName(XML.XSD_NS,"string"));
        log.debug("Using attribute: " + attribute0.toString());

        statement0 = new SAMLAttributeStatement();
        SAMLSubject subject = (SAMLSubject) subject0.clone();
        statement0.setSubject(subject);
        SAMLAttribute attribute = (SAMLAttribute) attribute0.clone();
        statement0.addAttribute(attribute);
        log.debug("Using statement: " + statement0.toString());

        xmlPath =
            "data/org/globus/opensaml11/saml/assertion.xml";
        log.debug("XML path: " + xmlPath);
        in = new FileInputStream(xmlPath);
        assertion0 = new SAMLAssertion(in);
        log.debug("Using assertion: " + assertion0.toString());

    }

    /**
     * @see TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Get this SAMLNameIdentifier object.
     *
     * @return a SAMLNameIdentifier object
     * @see org.globus.opensaml11.saml.SAMLNameIdentifier
     */
    protected SAMLNameIdentifier getNameIdentifier() {
        return nameid0;
    }

    /**
     * Get this SAMLSubject object.
     *
     * @return a SAMLSubject object
     * @see org.globus.opensaml11.saml.SAMLSubject
     */
    protected SAMLSubject getSubject() {
        return subject0;
    }

    /**
     * Get this SAMLAttribute object.
     *
     * @return a SAMLAttribute object
     * @see org.globus.opensaml11.saml.SAMLAttribute
     */
    protected SAMLAttribute getAttribute() {
        return attribute0;
    }

    /**
     * Get this SAMLAttributeStatement object.
     *
     * @return a SAMLAttributeStatement object
     * @see org.globus.opensaml11.saml.SAMLAttributeStatement
     */
    protected SAMLAttributeStatement getAttributeStatement() {
        return statement0;
    }

    /**
     * Get this SAMLAssertion object.
     *
     * @return a SAMLAssertion object
     * @see org.globus.opensaml11.saml.SAMLAssertion
     */
    protected SAMLAssertion getAssertion() {
        return assertion0;
    }

}
