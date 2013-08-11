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

import junit.framework.TestCase;

import org.apache.log4j.Logger;

import org.globus.opensaml11.saml.SAMLNameIdentifier;

/**
 * A specialized JUnit <code>TestCase</code> for name identifiers.
 * Includes a comprehensive test case for the equals method.
 * <p>
 * Some of the tests require a modified version of
 * <code>SAMLNameIdentifier</code> that only exists in the
 * Globus SAML library.  This <code>TestCase</code> searches
 * for the modified <code>SAMLNameIdentifier</code>, and if
 * not found, certain tests are skipped by necessity.
 *
 * @see junit.framework.TestCase
 * @see org.globus.opensaml11.saml.SAMLNameIdentifier
 *
 * @author Tom Scavo
 */
public class NameIdentifierTestCase extends TestCase {

    protected static Logger log =
        Logger.getLogger(NameIdentifierTestCase.class.getName());

    private static boolean oldSAMLNameIdentifierClassFound;
    private static String shortCircuitMsg;

    static {
        Class c = org.globus.opensaml11.saml.SAMLNameIdentifier.class;
        try {
            c.getDeclaredMethod("localEquals", new Class[]{Object.class});
            shortCircuitMsg = "New SAMLNameIdentifier class found";
            oldSAMLNameIdentifierClassFound = false;
        } catch (Exception e) {
            shortCircuitMsg = "Old SAMLNameIdentifier class found";
            oldSAMLNameIdentifierClassFound = true;
        }
        log.debug(shortCircuitMsg);
    }

    public NameIdentifierTestCase() {}

    public NameIdentifierTestCase(String arg) {
        super(arg);
    }

    protected void setUp() throws Exception {
        super.setUp();
    }

    protected void tearDown() throws Exception {
        super.tearDown();
    }

    public static void testClone(String format,
                                 String name) throws Exception {

        log.debug("testClone(String,String) called");

        // clone a name identifier:
        SAMLNameIdentifier nameid1, nameid2;
        nameid1 = SAMLNameIdentifier.getInstance(format);
        nameid1.setName(name);
        nameid2 = (SAMLNameIdentifier) nameid1.clone();

        assertTrue("NameIdentifier is identical to its clone",
                   nameid1 != nameid2);
        assertTrue("NameIdentifier class is not equal to that of its clone",
                   nameid1.getClass() == nameid2.getClass());

        if (oldSAMLNameIdentifierClassFound) {
            log.debug("Unable to fully testClone: " + shortCircuitMsg);
            return;
        }

        assertEquals("NameIdentifier is not equivalent to its clone",
                     nameid1, nameid2);
    }

    public static void testClone(String format) throws Exception {
        log.debug("testClone(String) called");
        testClone(format, "any name");
    }

    public static void testEquals(String format,
                                  String name1,
                                  String name2,
                                  String name3) throws Exception {

        log.debug("testEquals(String,String,String,String) called");

        String nameQualifier = "any name qualifier";

        // start with a single name identifier:
        SAMLNameIdentifier nameid1;
        nameid1 = new SAMLNameIdentifier(name1, nameQualifier, format);

        // test for reference equality:
        testEquals(nameid1, nameid1, nameid1);

        if (oldSAMLNameIdentifierClassFound) {
            log.debug("Unable to fully testEquals: " + shortCircuitMsg);
            return;
        }

        // create two additional name identifiers equal to the first:
        SAMLNameIdentifier nameid2, nameid3;
        nameid2 = new SAMLNameIdentifier(null, null, null);
        nameid2.setName(name1);
        nameid2.setNameQualifier(nameQualifier);
        nameid2.setFormat(format);
        nameid3 = SAMLNameIdentifier.getInstance(format);
        nameid3.setName(name1);
        nameid3.setNameQualifier(nameQualifier);

        // test for object equivalence:
        testEquals(nameid1, nameid2, nameid3);
        // vary the name and repeat:
        nameid2.setName(name2);
        testEquals(nameid1, nameid2, nameid3);
        nameid3.setName(name3);
        testEquals(nameid1, nameid2, nameid3);
    }

    public static void testEquals(String format) throws Exception {
        log.debug("testEquals(String) called");
        testEquals(format, "Larry", "Moe", "Curly");
    }

    public static void testEquals(SAMLNameIdentifier nameid1,
                                  SAMLNameIdentifier nameid2,
                                  SAMLNameIdentifier nameid3)
                           throws Exception {

        log.debug("testEquals(SAMLNameIdentifier,SAMLNameIdentifier,SAMLNameIdentifier) called");

        assertTrue("Null reference", nameid1 != null);
        assertTrue("Null reference", nameid2 != null);
        assertTrue("Null reference", nameid3 != null);

        assertTrue("Non-null reference is equal to null object",
                   !nameid1.equals(null));
        assertTrue("Non-null reference is equal to null object",
                   !nameid2.equals(null));
        assertTrue("Non-null reference is equal to null object",
                   !nameid3.equals(null));

        assertTrue("Consistency test failed",
                   nameid1.equals(nameid2) == nameid1.equals(nameid2));
        assertTrue("Consistency test failed",
                   nameid1.equals(nameid3) == nameid1.equals(nameid3));
        assertTrue("Consistency test failed",
                   nameid2.equals(nameid3) == nameid2.equals(nameid3));

        assertTrue("Reflexive test failed",
                   isReflexive(nameid1));
        assertTrue("Reflexive test failed",
                   isReflexive(nameid2));
        assertTrue("Reflexive test failed",
                   isReflexive(nameid3));

        assertTrue("Symmetric test failed",
                   isSymmetric(nameid1, nameid2));
        assertTrue("Symmetric test failed",
                   isSymmetric(nameid1, nameid3));
        assertTrue("Symmetric test failed",
                   isSymmetric(nameid2, nameid3));

        assertTrue("Transitive test failed",
                   isTransitive(nameid1, nameid2, nameid3));
        assertTrue("Transitive test failed",
                   isTransitive(nameid2, nameid3, nameid1));
        assertTrue("Transitive test failed",
                   isTransitive(nameid3, nameid1, nameid2));

        assertTrue("Hash code test failed",
                   hashCodeEquals(nameid1, nameid2));
        assertTrue("Hash code test failed",
                   hashCodeEquals(nameid1, nameid3));
        assertTrue("Hash code test failed",
                   hashCodeEquals(nameid2, nameid3));
    }

    private static boolean isReflexive(SAMLNameIdentifier nameid) {
        return nameid.equals(nameid);
    }

    private static boolean isSymmetric(SAMLNameIdentifier nameid1,
                                       SAMLNameIdentifier nameid2) {
        return nameid1.equals(nameid2) == nameid2.equals(nameid1);
    }

    private static boolean isTransitive(SAMLNameIdentifier nameid1,
                                        SAMLNameIdentifier nameid2,
                                        SAMLNameIdentifier nameid3) {
        return !nameid1.equals(nameid2) ||
               !nameid2.equals(nameid3) ||
                nameid1.equals(nameid3);
    }

    private static boolean hashCodeEquals(SAMLNameIdentifier nameid1,
                                          SAMLNameIdentifier nameid2) {
        return !nameid1.equals(nameid2) ||
                nameid1.hashCode() == nameid2.hashCode();
    }

    public static void testTwoEqualInstances(String format1,
                                             String format2,
                                             String name)
                                      throws Exception {

        log.debug("testTwoEqualInstances(String,String,String) called");

        if (oldSAMLNameIdentifierClassFound) {
            log.debug("Unable to testTwoEqualInstances: " + shortCircuitMsg);
            return;
        }

        String nameQualifier = "any name qualifier";

        SAMLNameIdentifier nameid1, nameid2;
        nameid1 = SAMLNameIdentifier.getInstance(format1);
        nameid1.setName(name);
        nameid1.setNameQualifier(nameQualifier);
        nameid2 = new SAMLNameIdentifier(name, nameQualifier, format2);

        // equality tests:
        assertEquals("NameIdentifiers not equal", nameid1, nameid1);
        assertEquals("NameIdentifiers not equal", nameid1, nameid2);
    }

    public static void testTwoEqualInstances(String format1,
                                             String format2)
                                      throws Exception {

        log.debug("testTwoEqualInstances(String) called");
        testTwoEqualInstances(format1, format2, "a name");
    }

    public static void testTwoUnequalInstances(String format1,
                                               String format2,
                                               String name1,
                                               String name2)
                                        throws Exception {

        log.debug("testTwoUnequalInstances(String,String,String,String) called");

        if (oldSAMLNameIdentifierClassFound) {
            log.debug("Unable to testTwoUnequalInstances: " + shortCircuitMsg);
            return;
        }

        String nameQualifier1 = "a name qualifier";
        String nameQualifier2 = "another name qualifier";

        SAMLNameIdentifier nameid1, nameid2;
        nameid1 = SAMLNameIdentifier.getInstance(format1);
        nameid1.setName(name1);
        nameid1.setNameQualifier(nameQualifier1);
        nameid2 = new SAMLNameIdentifier(name2, nameQualifier1, format2);

        // name test:
        assertTrue("Unequal NameIdentifiers are equal",
                   !nameid1.equals(nameid2));

        // name qualifer test:
        nameid2.setName(name1);
        nameid2.setNameQualifier(nameQualifier2);
        assertTrue("Unequal NameIdentifiers are equal",
                   !nameid1.equals(nameid2));
    }

    public static void testMissingName(String format) throws Exception {

        log.debug("testMissingName(String) called");

        SAMLNameIdentifier nameid =
            SAMLNameIdentifier.getInstance(format);
        try {
            nameid.checkValidity();
            String msg = "Intentionally missing name not detected";
            fail(msg);
        } catch (Exception e) {
            String msg = "Intentionally missing name detected";
            log.debug(msg + ": " + e.getMessage());
        }
    }

    public void testInvalidFormatURI() throws Exception {

        log.debug("testInvalidFormatURI() called");

        /*
         * This test only makes sense for <code>SAMLNameIdentifier</code>
         * in Globus SAML, since the version in the OpenSAML library does
         * not validate the value of the Format attribute throughout.
         */
        if (oldSAMLNameIdentifierClassFound) {
            log.debug("Unable to testInvalidFormatURI: " + shortCircuitMsg);
            return;
        }

        String format = "invalid format";
        SAMLNameIdentifier nameid = new SAMLNameIdentifier(null, null, format);
        nameid.setName("foo");
        try {
            nameid.checkValidity();
            String msg = "Intentionally invalid format not detected";
            fail(msg);
        } catch (Exception e) {
            String msg = "Intentionally invalid format detected";
            log.debug(msg + ": " + e.getMessage());
        }
    }

    public static void testInvalidNameFormat(String format) throws Exception {

        log.debug("testInvalidNameFormat(String) called");

        String name = "invalid-name";
        SAMLNameIdentifier nameid =
            SAMLNameIdentifier.getInstance(format);
        nameid.setName(name);
        try {
            nameid.checkValidity();
            String msg = "Intentionally invalid name not detected";
            fail(msg);
        } catch (Exception e) {
            String msg = "Intentionally invalid name detected";
            log.debug(msg + ": " + e.getMessage());
        }
    }

}
