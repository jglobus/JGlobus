/*
 * Copyright 1999-2006 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.globus.axis.transport.commons.tests;

import org.apache.commons.httpclient.HostConfiguration;

import org.globus.axis.transport.commons.ExtendedHostConfiguration;

import junit.framework.TestCase;
import junit.framework.Test;
import junit.framework.TestSuite;

public class ExtendedHostConfigurationTest extends TestCase {

    private static final String [] PARAMS = { "A", "B" };
    private static int counter = 0;

    public ExtendedHostConfigurationTest(String name) {
	super(name);
    }

    public static void main (String[] args) {
	junit.textui.TestRunner.run (suite());
    }

    public static Test suite() {
	return new TestSuite(ExtendedHostConfigurationTest.class);
    }

    public void testEqualsAndHashNoExtra() {

        HostConfiguration h1 = getHostConfiguration(null);
        HostConfiguration h2 = getHostConfiguration(null);

        assertEquals(h1.hashCode(), h2.hashCode());
        assertTrue(h1.equals(h2));
        assertTrue(h2.equals(h1));

        System.out.println(h1);
    }

    public void testEqualsAndHashSame() {

        HostConfiguration h1 = getHostConfiguration(PARAMS);
        HostConfiguration h2 = getHostConfiguration(PARAMS);

        assertEquals(h1.hashCode(), h2.hashCode());
        assertTrue(h1.equals(h2));
        assertTrue(h2.equals(h1));

        System.out.println(h1);
    }

    public void testEqualsAndHashDifferent() {

        HostConfiguration h1 = getHostConfiguration(PARAMS, "foo", "B");
        HostConfiguration h2 = getHostConfiguration(PARAMS, "foo", "C");

        assertTrue(h1.hashCode() != h2.hashCode());
        assertTrue(!h1.equals(h2));
        assertTrue(!h2.equals(h1));

        System.out.println(h1);
        System.out.println(h2);
    }

    private HostConfiguration getHostConfiguration(String [] params) {
        return getHostConfiguration(params, "foo", "bar");
    }

    private HostConfiguration getHostConfiguration(String [] params,
                                                   String valueA,
                                                   String valueB) {
        HostConfiguration h1 = new HostConfiguration();
        h1.setHost("foobar", 80);

        ExtendedHostConfiguration eh1 = new ExtendedHostConfiguration(h1,
                                                                      params);

        eh1.getParams().setParameter("A", valueA);
        eh1.getParams().setParameter("B", valueB);
        // even if C is different it's not included in the test
        eh1.getParams().setParameter("C", String.valueOf(counter++));

        return eh1;
    }

}

