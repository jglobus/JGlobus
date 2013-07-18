/*
 *  Copyright 2001-2005 Internet2
 *  Copyright 2005-2009 University of Illinois
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

import org.globus.opensaml11.saml.nameid.NameIdentifierTestCase;

/**
 * @author     Scott Cantor
 * @author     Tom Scavo
 */
public class SAMLNameIdentifierTest extends NameIdentifierTestCase {

    private static Logger log =
        Logger.getLogger(SAMLNameIdentifierTest.class.getName());

    private final static String FORMAT_UNSPECIFIED =
        SAMLNameIdentifier.FORMAT_UNSPECIFIED;
    private final static String FORMAT_EMAIL =
        SAMLNameIdentifier.FORMAT_EMAIL;
    private final static String FORMAT_X509 =
        SAMLNameIdentifier.FORMAT_X509;
    private final static String FORMAT_WINDOWS =
        SAMLNameIdentifier.FORMAT_WINDOWS;

    public static void main(String[] args) {
        junit.textui.TestRunner.run(SAMLNameIdentifierTest.class);
        BasicConfigurator.configure();
        Logger.getRootLogger().setLevel(Level.OFF);
        //Logger.getRootLogger().setLevel(Level.DEBUG);
        log.setLevel(Level.DEBUG);
    }

    public SAMLNameIdentifierTest(String name) {
        super(name);
        BasicConfigurator.resetConfiguration();
        BasicConfigurator.configure();
        Logger.getRootLogger().setLevel(Level.OFF);
        //Logger.getRootLogger().setLevel(Level.DEBUG);
        log.setLevel(Level.DEBUG);
    }

    public void testClone() throws Exception {
        log.debug("testClone() called");

        testClone(FORMAT_UNSPECIFIED);

        String name;
        name = "user@example.org";
        testClone(FORMAT_EMAIL, name);

        name = "uid=userid,dc=example,dc=org";
        testClone(FORMAT_X509, name);
    }

    public void testEquals() throws Exception {
        log.debug("testEquals() called");

        testEquals(FORMAT_UNSPECIFIED);

        String name1, name2, name3;
        name1 = "user@example.org";
        name2 = "user@example.com";
        name3 = "user@example.net";
        testEquals(FORMAT_EMAIL, name1, name2, name3);

        name1 = "uid=userid,dc=example,dc=org";
        name2 = "uid=userid,dc=example,dc=com";
        name3 = "uid=userid,dc=example,dc=net";
        testEquals(FORMAT_X509);
    }

    public void testUnspecifiedByFormat() throws Exception {
        log.debug("testUnspecifiedByFormat() called");

        testTwoEqualInstances(FORMAT_UNSPECIFIED, null);
        testTwoEqualInstances(null, FORMAT_UNSPECIFIED);
    }

    public void testEmailByFormat() throws Exception {
        log.debug("testEmailByFormat() called");

        String name = "user@example.org";
        testTwoEqualInstances(FORMAT_EMAIL, FORMAT_EMAIL, name);
    }

    public void testX509ByFormat() throws Exception {
        log.debug("testX509ByFormat() called");

        String name = "uid=userid,dc=example,dc=org";
        testTwoEqualInstances(FORMAT_X509, FORMAT_X509, name);
    }

    public void testUnspecifiedByStream() throws Exception {
        log.debug("testUnspecifiedByStream() called");

        String xmlPath =
            "data/org/globus/opensaml11/saml/nameid/UnspecifiedNameIdentifier.xml";
        InputStream in = new FileInputStream(xmlPath);
        SAMLNameIdentifier nameid = new SAMLNameIdentifier(in);

        log.debug("calling assertEquals");
        assertEquals("NameIdentifier value is wrong",
                     nameid.getName(), "some user at example.org");
        log.debug("calling assertEquals");
        assertEquals("NameIdentifier Format is wrong",
                     nameid.getFormat(), FORMAT_UNSPECIFIED);
    }

    public void testEmailByStream() throws Exception {
        log.debug("testEmailByStream() called");

        String xmlPath =
            "data/org/globus/opensaml11/saml/nameid/EmailAddressNameIdentifier.xml";
        InputStream in = new FileInputStream(xmlPath);
        SAMLNameIdentifier nameid = new SAMLNameIdentifier(in);

        log.debug("calling assertEquals");
        assertEquals("NameIdentifier value is wrong",
                     nameid.getName(), "user@example.org");
        log.debug("calling assertEquals");
        assertEquals("NameIdentifier Format is wrong",
                     nameid.getFormat(), FORMAT_EMAIL);
    }

    public void testX509ByStream() throws Exception {
        log.debug("testX509ByStream() called");

        String xmlPath =
            "data/org/globus/opensaml11/saml/nameid/X509SubjectNameNameIdentifier.xml";
        InputStream in = new FileInputStream(xmlPath);
        SAMLNameIdentifier nameid = new SAMLNameIdentifier(in);

        log.debug("calling assertEquals");
        assertEquals("NameIdentifier value is wrong",
                     nameid.getName(), "uid=userid,dc=example,dc=org");
        log.debug("calling assertEquals");
        assertEquals("NameIdentifier Format is wrong",
                     nameid.getFormat(), FORMAT_X509);
    }

    public void testMissingName() throws Exception {
        log.debug("testMissingName() called");

        testMissingName(FORMAT_WINDOWS);
    }

    public void testInvalidFormatURI() throws Exception {
        super.testInvalidFormatURI();
    }

    public void testTwoUnequalInstances() throws Exception {
        log.debug("testTwoUnequalInstances() called");

        String name1 = "a name";
        String name2 = "another name";
        testTwoUnequalInstances(null, null,
                                name1, name2);

    }

}
