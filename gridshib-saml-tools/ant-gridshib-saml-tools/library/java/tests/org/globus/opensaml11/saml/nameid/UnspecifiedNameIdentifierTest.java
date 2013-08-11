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
public class UnspecifiedNameIdentifierTest extends NameIdentifierTestCase {

    private static Logger log =
        Logger.getLogger(UnspecifiedNameIdentifierTest.class.getName());

    private final static String FORMAT_UNSPECIFIED;

    static {
        FORMAT_UNSPECIFIED = SAMLNameIdentifier.FORMAT_UNSPECIFIED;
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(UnspecifiedNameIdentifierTest.class);
        BasicConfigurator.configure();
        Logger.getRootLogger().setLevel(Level.OFF);
        //Logger.getRootLogger().setLevel(Level.DEBUG);
        log.setLevel(Level.DEBUG);
        NameIdentifierTestCase.log.setLevel(Level.DEBUG);
    }

    public UnspecifiedNameIdentifierTest() {}

    public UnspecifiedNameIdentifierTest(String name) {
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

        testClone(FORMAT_UNSPECIFIED);
    }

    public void testEquals() throws Exception {
        log.debug("testEquals() called");

        testEquals(FORMAT_UNSPECIFIED);
    }

    public void testGetInstanceByFormat() throws Exception {
        log.debug("testGetInstanceByFormat() called");

        testTwoEqualInstances(FORMAT_UNSPECIFIED, FORMAT_UNSPECIFIED);
        testTwoEqualInstances(FORMAT_UNSPECIFIED, null);
    }

    public void testGetInstanceByStream() throws Exception {
        log.debug("testGetInstanceByStream() called");

        String xmlPath =
            "data/org/globus/opensaml11/saml/nameid/UnspecifiedNameIdentifier.xml";
        InputStream in = new FileInputStream(xmlPath);
        SAMLNameIdentifier nameid = SAMLNameIdentifier.getInstance(in);

        log.debug("calling assertEquals");
        assertEquals("NameIdentifier value is wrong",
                     nameid.getName(), "some user at example.org");
        log.debug("calling assertEquals");
        assertEquals("NameIdentifier Format is wrong",
                     nameid.getFormat(), FORMAT_UNSPECIFIED);
    }

    public void testMissingName() throws Exception {
        log.debug("testMissingName() called");

        testMissingName(FORMAT_UNSPECIFIED);
    }

    public void testTwoUnequalInstances() throws Exception {
        log.debug("testTwoUnequalInstances() called");

        String name1 = "a name";
        String name2 = "another name";
        testTwoUnequalInstances(FORMAT_UNSPECIFIED, FORMAT_UNSPECIFIED,
                                name1, name2);

    }

}
