/*
 * Copyright 2001-2005 Internet2
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

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import junit.framework.TestCase;

/**
 * @author Scott Cantor
 * @author Tom Scavo
 */
public class SAMLSubjectTest extends TestCase {

    private static Logger log =
        Logger.getLogger(SAMLSubjectTest.class.getName());

    public static void main(String[] args) {
        junit.textui.TestRunner.run(SAMLSubjectTest.class);
        BasicConfigurator.configure();
    }

    public SAMLSubjectTest(String name) {
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
    }

    /**
     * @see TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    public void testValidSAMLSubjects() throws Exception {
        log.debug("TESTING valid SAML subjects...");

        String xmlPath;

        // test a valid Subject with both NameIdentifier and SubjectConfirmation:
        xmlPath = "data/org/globus/opensaml11/saml/subject.xml";
        SAMLSubject s1 = new SAMLSubject(new FileInputStream(xmlPath));
        log.debug("Subject to test: " + s1.toString().replaceAll("\\s+", " "));
        assertTrue("Subject has no name identifier",
                   s1.getNameIdentifier() != null);
        assertTrue("Subject has no confirmation methods",
                   s1.getConfirmationMethods().hasNext());

        // test a valid Subject with no SubjectConfirmation:
        xmlPath = "data/org/globus/opensaml11/saml/subjectNoSubjectConfirmation.xml";
        SAMLSubject s2 = new SAMLSubject(new FileInputStream(xmlPath));
        log.debug("Subject to test: " + s2.toString().replaceAll("\\s+", " "));
        assertTrue("Subject has no name identifier",
                   s2.getNameIdentifier() != null);
        assertTrue("Subject has confirmation methods",
                   !s2.getConfirmationMethods().hasNext());

        // test a valid Subject with no NameIdentifier:
        xmlPath = "data/org/globus/opensaml11/saml/subjectNoNameIdentifier.xml";
        SAMLSubject s3 = new SAMLSubject(new FileInputStream(xmlPath));
        log.debug("Subject to test: " + s3.toString().replaceAll("\\s+", " "));
        assertTrue("Subject has a name identifier",
                   s3.getNameIdentifier() == null);
        assertTrue("Subject has no confirmation methods",
                   s3.getConfirmationMethods().hasNext());

    }

    public void testInvalidSAMLSubjects() throws Exception {
        log.debug("TESTING invalid SAML subjects...");

        String subjectStr;

        // test an invalid Subject with no content:
        subjectStr  = "<saml:Subject";
        subjectStr += "  xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\">";
        subjectStr += "</saml:Subject>";
        SAMLSubject s1 = null;
        try {
            s1 = new SAMLSubject(new ByteArrayInputStream(subjectStr.toString().getBytes()));
            log.debug("Bogus SAML subject: " + s1.toString().replaceAll("\\s+", " "));
            fail("Bogus SAML subject passed validity check");
        } catch (MalformedException e) {
            log.debug("Subject to test: " + subjectStr.replaceAll("\\s+", " "));
            log.debug("Caught expected MalformedException: " + e.getMessage());
        }

        // test an invalid Subject with no ConfirmationMethod:
        subjectStr  = "<saml:Subject";
        subjectStr += "  xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\">";
        subjectStr += "  <saml:SubjectConfirmation>";
        subjectStr += "  </saml:SubjectConfirmation>";
        subjectStr += "</saml:Subject>";
        SAMLSubject s2 = null;
        try {
            s2 = new SAMLSubject(new ByteArrayInputStream(subjectStr.toString().getBytes()));
            log.debug("Bogus SAML subject: " + s2.toString().replaceAll("\\s+", " "));
            fail("Bogus SAML subject passed validity check");
        } catch (MalformedException e) {
            log.debug("Subject to test: " + subjectStr.replaceAll("\\s+", " "));
            log.debug("Caught expected MalformedException: " + e.getMessage());
        }

        // test an invalid Subject with no KeyInfo:
        subjectStr  = "<saml:Subject";
        subjectStr += "  xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\">";
        subjectStr += "  <saml:SubjectConfirmation>";
        subjectStr += "    <saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:holder-of-key</saml:ConfirmationMethod>";
        subjectStr += "  </saml:SubjectConfirmation>";
        subjectStr += "</saml:Subject>";
        SAMLSubject s3 = null;
        try {
            s3 = new SAMLSubject(new ByteArrayInputStream(subjectStr.toString().getBytes()));
            log.debug("Bogus SAML subject: " + s3.toString().replaceAll("\\s+", " "));
            fail("Bogus SAML subject passed validity check");
        } catch (MalformedException e) {
            log.debug("Subject to test: " + subjectStr.replaceAll("\\s+", " "));
            log.debug("Caught expected MalformedException: " + e.getMessage());
        }

    }

}
