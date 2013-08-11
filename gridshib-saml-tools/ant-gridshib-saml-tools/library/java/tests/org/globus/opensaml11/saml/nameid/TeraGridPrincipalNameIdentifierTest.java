/*
 * Copyright 2009 University of Illinois
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
public class TeraGridPrincipalNameIdentifierTest extends NameIdentifierTestCase {

    private static Logger log =
        Logger.getLogger(TeraGridPrincipalNameIdentifierTest.class.getName());

    private final static String FORMAT_TGPN;

    static {
        FORMAT_TGPN = TeraGridPrincipalNameIdentifier.FORMAT_TGPN;
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(TeraGridPrincipalNameIdentifierTest.class);
        BasicConfigurator.configure();
        Logger.getRootLogger().setLevel(Level.OFF);
        //Logger.getRootLogger().setLevel(Level.DEBUG);
        log.setLevel(Level.DEBUG);
        NameIdentifierTestCase.log.setLevel(Level.DEBUG);
    }

    public TeraGridPrincipalNameIdentifierTest() {}

    public TeraGridPrincipalNameIdentifierTest(String name) {
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

        String name = "user@vo.teragrid.org";
        testClone(FORMAT_TGPN, name);
    }

    public void testEquals() throws Exception {
        log.debug("testEquals() called");

        String name1 = "user@vo1.teragrid.org";
        String name2 = "user@vo2.teragrid.org";
        String name3 = "user@vo3.teragrid.org";
        testEquals(FORMAT_TGPN, name1, name2, name3);
    }

    public void testGetInstanceByFormat() throws Exception {
        log.debug("testGetInstanceByFormat() called");

        String name = "user@vo.teragrid.org";
        testTwoEqualInstances(FORMAT_TGPN, FORMAT_TGPN, name);
    }

    public void testGetInstanceByStream() throws Exception {
        log.debug("testGetInstanceByStream() called");

        String xmlPath =
            "data/org/globus/opensaml11/saml/nameid/TeraGridPrincipalNameIdentifier.xml";
        InputStream in = new FileInputStream(xmlPath);
        SAMLNameIdentifier nameid = SAMLNameIdentifier.getInstance(in);

        log.debug("calling assertEquals");
        assertEquals("NameIdentifier value is wrong",
                     nameid.getName(), "user@vo.teragrid.org");
        log.debug("calling assertEquals");
        assertEquals("NameIdentifier Format is wrong",
                     nameid.getFormat(), FORMAT_TGPN);
    }

    public void testMissingName() throws Exception {
        log.debug("testMissingName() called");

        testMissingName(FORMAT_TGPN);
    }

    public void testInvalidNameFormat() throws Exception {
        log.debug("testInvalidNameFormat() called");

        testInvalidNameFormat(FORMAT_TGPN);
    }

    public void testTwoUnequalInstances() throws Exception {
        log.debug("testTwoUnequalInstances() called");

        String name1 = "user@vo1.teragrid.org";
        String name2 = "user@vo2.teragrid.org";
        testTwoUnequalInstances(FORMAT_TGPN, FORMAT_TGPN, name1, name2);

    }

}
