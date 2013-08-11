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
import java.util.Iterator;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import org.w3c.dom.*;

import junit.framework.TestCase;

/**
 * @author Tom Scavo
 */
public class SAMLSubjectStatementTest extends TestCase {

    private static Logger log =
        Logger.getLogger(SAMLSubjectStatementTest.class.getName());

    private static String propName =
        "org.globus.opensaml11.saml.strict-dom-checking";
    private static boolean propValue;

    public static void main(String[] args) {
        junit.textui.TestRunner.run(SAMLSubjectStatementTest.class);
        BasicConfigurator.configure();
    }

    public SAMLSubjectStatementTest(String name) {
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

    public void testSubjectStatements() throws Exception {
        log.debug("Testing subject statements...");

        String xmlPath = null;
        InputStream in = null;

        xmlPath =
            "data/org/globus/opensaml11/saml/subjectAssertion.xml";
        log.debug("XML path: " + xmlPath);
        in = new FileInputStream(xmlPath);
        SAMLSubjectAssertion assertion = new SAMLSubjectAssertion(in);
        log.debug("Using assertion: " + assertion.toString());
        assertion.checkValidity();  // redundant

        int n;
        n = assertion.statements.size();
        log.debug("There are " + n + " statements");
        int m = n;  // save for later comparisons

        // an invariant wrt SAMLSubjectAssertion:
        assertTrue("Assertion contains a redundant SubjectStatement",
                   !assertion.hasRedundantSubjectStatement());

        // this method will not add a redundant SubjectStatement:
        assertion.addSubjectStatement(assertion.getSubject());

        n = assertion.statements.size();
        log.debug("There are still " + n + " statements");

        // the number of SubjectStatements has not changed:
        assertTrue("The number of statements changed", m == n);

        // this method will not add a redundant SubjectStatement:
        assertion.addStatement(new SubjectStatement(assertion.getSubject()));

        n = assertion.statements.size();
        log.debug("There are still " + n + " statements");

        // the number of SubjectStatements has not changed:
        assertTrue("The number of statements changed", m == n);

        assertTrue("Assertion contains a redundant SubjectStatement",
                   !assertion.hasRedundantSubjectStatement());
    }
}

