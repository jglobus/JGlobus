/*
 * Copyright 2006-2009 University of Illinois
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

package org.globus.opensaml11.saml.nameid;

import java.io.FileInputStream;
import java.io.InputStream;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import org.globus.opensaml11.saml.SAMLNameIdentifier;

/**
 * @see org.globus.opensaml11.saml.nameid.NameIdentifierTestCase
 *
 * @author Tom Scavo
 */
public class X509SubjectNameNameIdentifierTest extends NameIdentifierTestCase {

    private static Logger log =
        Logger.getLogger(X509SubjectNameNameIdentifierTest.class.getName());

    private final static String FORMAT_X509;

    static {
        FORMAT_X509 = SAMLNameIdentifier.FORMAT_X509;
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(X509SubjectNameNameIdentifierTest.class);
        BasicConfigurator.configure();
        Logger.getRootLogger().setLevel(Level.OFF);
        //Logger.getRootLogger().setLevel(Level.DEBUG);
        log.setLevel(Level.DEBUG);
        NameIdentifierTestCase.log.setLevel(Level.DEBUG);
    }

    public X509SubjectNameNameIdentifierTest() {}

    public X509SubjectNameNameIdentifierTest(String name) {
        super(name);
        BasicConfigurator.resetConfiguration();
        BasicConfigurator.configure();
        Logger.getRootLogger().setLevel(Level.OFF);
        //Logger.getRootLogger().setLevel(Level.DEBUG);
        log.setLevel(Level.DEBUG);
        NameIdentifierTestCase.log.setLevel(Level.DEBUG);
    }

    /**
     * Set up for each test
     */
    protected void setUp() throws Exception {
        super.setUp();
    }

    /**
     * Tear down for each test
     */
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    public void testClone() throws Exception {
        log.debug("testClone() called");

        String name = "uid=userid,dc=example,dc=org";
        testClone(FORMAT_X509, name);
    }

    public void testEquals() throws Exception {
        log.debug("testEquals() called");

        String name1 = "uid=userid,dc=example,dc=org";
        String name2 = "uid=userid,dc=example,dc=com";
        String name3 = "uid=userid,dc=example,dc=net";
        testEquals(FORMAT_X509, name1, name2, name3);
    }

    public void testGetInstanceByFormat() throws Exception {
        log.debug("testGetInstanceByFormat() called");

        String name = "uid=userid,dc=example,dc=org";
        testTwoEqualInstances(FORMAT_X509, FORMAT_X509, name);
    }

    public void testGetInstanceByStream() throws Exception {
        log.debug("testGetInstanceByStream() called");

        String xmlPath =
            "data/org/globus/opensaml11/saml/nameid/X509SubjectNameNameIdentifier.xml";
        InputStream in = new FileInputStream(xmlPath);
        SAMLNameIdentifier nameid = SAMLNameIdentifier.getInstance(in);

        log.debug("calling assertEquals");
        assertEquals("NameIdentifier value is wrong",
                     nameid.getName(), "uid=userid,dc=example,dc=org");
        log.debug("calling assertEquals");
        assertEquals("NameIdentifier Format is wrong",
                     nameid.getFormat(), FORMAT_X509);
    }

    public void testMissingName() throws Exception {
        log.debug("testMissingName() called");

        testMissingName(FORMAT_X509);
    }

    public void testInvalidNameFormat() throws Exception {
        log.debug("testInvalidNameFormat() called");

        testInvalidNameFormat(FORMAT_X509);
    }

    public void testTwoUnequalInstances() throws Exception {
        log.debug("testTwoUnequalInstances() called");

        String name1 = "uid=userid,dc=example,dc=org";
        String name2 = "uid=userid,dc=example,dc=com";
        testTwoUnequalInstances(FORMAT_X509, FORMAT_X509, name1, name2);

    }

}
