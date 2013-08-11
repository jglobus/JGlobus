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

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import junit.framework.TestCase;

/**
 * @author Tom Scavo
 */
public class SAMLAttributeStatementTest extends TestCase {

    private static Logger log =
        Logger.getLogger(SAMLAttributeStatementTest.class.getName());

    public static void main(String[] args) {
        junit.textui.TestRunner.run(SAMLAttributeStatementTest.class);
        BasicConfigurator.configure();
    }

    public SAMLAttributeStatementTest(String name) {
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

    public void testSubjectStatement() throws Exception {
        log.debug("Testing subject statement...");

        String propName = "org.globus.opensaml11.saml.strict-dom-checking";
        boolean b;
        b = SAMLConfig.instance().getBooleanProperty(propName);
        SAMLConfig.instance().setBooleanProperty(propName, Boolean.TRUE);

        String xmlPath = null;
        InputStream in = null;

        xmlPath =
            "data/org/globus/opensaml11/saml/subjectStatement.xml";
        log.debug("XML path: " + xmlPath);
        in = new FileInputStream(xmlPath);
        SAMLAttributeStatement statement = new SAMLAttributeStatement(in);
        log.debug("Using statement: " + statement.toString());
        statement.checkValidity();

        SAMLConfig.instance().setBooleanProperty(propName, new Boolean(b));
    }

}

