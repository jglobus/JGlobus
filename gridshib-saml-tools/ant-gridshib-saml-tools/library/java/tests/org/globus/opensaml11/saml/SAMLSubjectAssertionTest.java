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
import java.util.ArrayList;
import java.util.Date;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import org.w3c.dom.*;

import junit.framework.TestCase;

/**
 * @author Tom Scavo
 */
public class SAMLSubjectAssertionTest extends SAMLTestCase {

    /* TODO:
     * - expand testNoSubjectStatement
     */

    private static Logger log =
        Logger.getLogger(SAMLSubjectAssertionTest.class.getName());

    private static String propName =
        "org.globus.opensaml11.saml.strict-dom-checking";
    private static boolean propValue;

    private static final String ISSUER =
        "https://idp.example.org/shibboleth";

    public static void main(String[] args) {
        junit.textui.TestRunner.run(SAMLSubjectAssertionTest.class);
        BasicConfigurator.configure();
    }

    public SAMLSubjectAssertionTest(String name) {
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
        log.setLevel(Level.DEBUG);

        propValue =
            SAMLConfig.instance().getBooleanProperty(propName);
        SAMLConfig.instance().setBooleanProperty(propName, Boolean.TRUE);
    }

    /**
     * @see TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        super.tearDown();

        Boolean b = new Boolean(propValue);
        SAMLConfig.instance().setBooleanProperty(propName, b);
    }

    public void testEmptyConstructor() throws Exception {
        log.debug("TESTING empty constructor...");

        SAMLAttributeStatement statement =
            (SAMLAttributeStatement) getAttributeStatement().clone();
        statement.checkValidity();

        SAMLSubjectAssertion assertion = new SAMLSubjectAssertion();
        assertion.setIssuer(ISSUER);
        assertion.addStatement(statement);
        log.debug("Created assertion: " + assertion.toString());
        assertion.checkValidity();

        assertEquals("NameIdentifier is incorrect",
                     getNameIdentifier(),
                     assertion.getSubject().getNameIdentifier());
    }

    public void testVeryStronglyMatches() throws Exception {
        log.debug("TESTING veryStronglyMatches...");

        SAMLSubject s1 = getSubject();
        SAMLSubject s2 = (SAMLSubject) s1.clone();
        assertTrue("Subject does not very strongly match its clone",
                   SAMLSubjectAssertion.veryStronglyMatches(s1, s2));

        // modify NameIdentifier:
        SAMLNameIdentifier nameid = s2.getNameIdentifier();
        nameid.setNameQualifier(ISSUER);
        s2.setNameIdentifier((SAMLNameIdentifier) nameid.clone());
        log.debug("Created subject: " + s2.toString());
        assertTrue("Non-matching subjects very strongly match",
                   !SAMLSubjectAssertion.veryStronglyMatches(s1, s2));

        // modify SubjectConfirmation:
        s2 = (SAMLSubject) s1.clone();
        s2.addConfirmationMethod(ISSUER);
        log.debug("Created subject: " + s2.toString());
        assertTrue("Non-matching subjects very strongly match",
                   !SAMLSubjectAssertion.veryStronglyMatches(s1, s2));
    }

    public void testNonEmptyConstructors() throws Exception {
        log.debug("TESTING nonempty constructors...");

        SAMLAttributeStatement attrStatement =
            (SAMLAttributeStatement) getAttributeStatement().clone();
        attrStatement.checkValidity();

        // create authn statement w/o subject:
        SAMLAuthenticationStatement authnStatement;
        authnStatement = new SAMLAuthenticationStatement();
        String authMethod =
            SAMLAuthenticationStatement.AuthenticationMethod_Unspecified;
        authnStatement.setAuthMethod(authMethod);
        Date authnInstant = new Date(System.currentTimeMillis());
        authnStatement.setAuthInstant(authnInstant);

        ArrayList statements = new ArrayList();
        statements.add(attrStatement);
        statements.add(authnStatement);

        SAMLSubjectAssertion assertion1 =
            new SAMLSubjectAssertion(
                ISSUER,
                null,
                null,
                null,
                null,
                statements
                );
        log.debug("Created assertion: " + assertion1.toString());
        assertion1.checkValidity();

        assertEquals("NameIdentifier is incorrect",
                     getNameIdentifier(),
                     assertion1.getSubject().getNameIdentifier());

        // no-subject authn statement now has a subject:
        SAMLSubject s = authnStatement.getSubject();
        assertTrue("Subjects do not very strongly match",
                   SAMLSubjectAssertion.veryStronglyMatches(getSubject(), s));

        statements = new ArrayList();
        statements.add((SAMLAttributeStatement) attrStatement.clone());
        statements.add((SAMLAuthenticationStatement) authnStatement.clone());

        SAMLSubjectAssertion assertion2 =
            (SAMLSubjectAssertion) assertion1.clone();
        assertion2.setStatements(statements);
        log.debug("Created assertion: " + assertion2.toString());
        assertion2.checkValidity();

        assertEquals("Assertions are not equal",
                     assertion1.toString(), assertion2.toString());
    }

    public void testSubjectStatement() throws Exception {
        log.debug("TESTING subject statement...");

        // produce assertion with single SubjectStatement:
        SAMLSubjectAssertion assertion1 =
            new SAMLSubjectAssertion(getAssertion());
        assertion1.setStatements(null);
        assertion1.addSubjectStatement(getSubject());
        log.debug("Created assertion: " + assertion1.toString());
        assertion1.checkValidity();

        SAMLSubject s = assertion1.getSubject();
        assertTrue("Subjects do not very strongly match",
                   SAMLSubjectAssertion.veryStronglyMatches(getSubject(), s));

        SAMLSubjectAssertion assertion2 =
            new SAMLSubjectAssertion(assertion1);
        assertion2.checkValidity();

        InputStream in = null;
        String xmlPath =
            "data/org/globus/opensaml11/saml/subjectStatement.xml";
        log.debug("XML path: " + xmlPath);

        in = new FileInputStream(xmlPath);
        SAMLAttributeStatement attrStatement = new SAMLAttributeStatement(in);
        log.debug("Created attribute statement: " + attrStatement.toString());
        attrStatement.checkValidity();

        in = new FileInputStream(xmlPath);
        SubjectStatement subjectStatement = new SubjectStatement(in);
        log.debug("Created subject statement: " + subjectStatement.toString());
        subjectStatement.checkValidity();
    }

    public void testSubjectStatements() throws Exception {
        log.debug("Testing subject statements...");

        String xmlPath = null;
        InputStream in = null;

        xmlPath =
            "data/org/globus/opensaml11/saml/subjectAssertion.xml";
        log.debug("XML path: " + xmlPath);
        in = new FileInputStream(xmlPath);
        SAMLAssertion assertion1 = new SAMLAssertion(in);
        log.debug("Using assertion: " + assertion1.toString());
        assertion1.checkValidity();

        SAMLSubjectAssertion assertion2 =
            new SAMLSubjectAssertion(assertion1);
        assertion2.checkValidity();  // redundant

        assertEquals("Assertions are not equal",
                     assertion1.toString(), assertion2.toString());
    }

    public void testNoSubjectStatement() throws Exception {
        log.debug("TESTING no-subject statement...");

        SAMLSubjectAssertion assertion =
            new SAMLSubjectAssertion(getAssertion());
        try {
            assertion.addStatement(new SAMLNoSubjectStatement());
        } catch (MalformedException e) {
            log.debug("Caught expected MalformedException: " + e.getMessage());
            return;
        }
        log.debug("Created bogus assertion: " + assertion.toString());
        fail("Added no-subject statement to SAMLSubjectAssertion");
    }
}

class SAMLNoSubjectStatement extends SAMLStatement
                          implements Cloneable {

    /**
     * Default constructor
     */
    protected SAMLNoSubjectStatement() {}

    /**
     * Reconstructs a no-subject statement from a DOM tree
     *
     * @param  e                  The root of a DOM tree
     * @exception  org.globus.opensaml11.saml.SAMLException
     *             Thrown if the object cannot be constructed
     */
    protected SAMLNoSubjectStatement(Element e) throws SAMLException {
        fromDOM(e);
    }

    /**
     * Reconstructs a no-subject statement from a stream
     *
     * @param  in                   A stream containing XML
     * @exception  org.globus.opensaml11.saml.SAMLException
     *             Raised if an exception occurs while constructing
     *             the object.
     */
    protected SAMLNoSubjectStatement(InputStream in) throws SAMLException {
        fromDOM(fromStream(in));
    }

    /**
     * @see SAMLObject#fromDOM(org.w3c.dom.Element)
     */
    public void fromDOM(Element e) throws SAMLException {
        super.fromDOM(e);
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#buildRoot(org.w3c.dom.Document,boolean)
     */
    protected Element buildRoot(Document doc, boolean xmlns) {
        Element s = doc.createElementNS(XML.SAML_NS, "NoSubjectStatement");
        if (xmlns) {
            s.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
            s.setAttributeNS(XML.XMLNS_NS, "xmlns:xsd", XML.XSD_NS);
            s.setAttributeNS(XML.XMLNS_NS, "xmlns:xsi", XML.XSI_NS);
        }
        return s;
    }

    /**
     * @see SAMLObject#toDOM(org.w3c.dom.Document,boolean)
     */
    public Node toDOM(Document doc, boolean xmlns) throws SAMLException {
        // Let the base build/verify the DOM root.
        super.toDOM(doc, xmlns);
        return root;
    }

    /**
     * @see SAMLObject#checkValidity()
     */
    public void checkValidity() throws SAMLException {
        // no-op
    }

    /**
     * Copies a SAML object such that no dependencies exist
     * between the original and the copy
     *
     * @return      The new object
     * @see Object#clone()
     */
    public Object clone() throws CloneNotSupportedException {
        SAMLNoSubjectStatement dup = (SAMLNoSubjectStatement) super.clone();
        return dup;
    }
}
