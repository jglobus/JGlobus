/*
 * Copyright 2008-2009 University of Illinois
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

package org.globus.gridshib.common.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.saml.SAMLToolsTestCase;

/**
 * @since 0.5.3
 */
public class PropertiesUtilTest extends SAMLToolsTestCase {

    private static final Class CLASS = PropertiesUtilTest.class;
    private static final String CLASSNAME = CLASS.getName();

    private static Log logger = LogFactory.getLog(CLASSNAME);

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CLASS);
    }

    public PropertiesUtilTest(String name) {
        super(name);
    }

    /**
     * @see TestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();
    }

    /**
     * @see TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    public void testResolvePropValue() throws Exception {

        String testProps =
            "name1=value1\n" +
            "name2=*${name1}2\n" +
            "name3=*${name1}*${name2}3*\n" +
            "user.name=foo\n" +
            "name4=${GLOBUS_LOCATION}\n" +
            "name5=$2.50\n" +
            "name6=${name5}\n";
        byte[] bytes = testProps.getBytes();

        // load the properties file:
        Properties props = new Properties();
        try {
            props.load(new ByteArrayInputStream(bytes));
        } catch (IOException e) {
            String msg = "Unable to load test properties: ";
            msg += e.getMessage();
            logger.error(msg);
            fail(msg);
        }

        // token resolution is recursive:
        String propValue = "**${name1}*${name2}*${name3}*";
        String testPropValue =
            PropertiesUtil.resolvePropValue(props, propValue);
        String resolvedPropValue =
            "**value1**value12**value1**value123**";
        assertTrue("Unresolved property value: " + testPropValue,
                   resolvedPropValue.equals(testPropValue));

        // a system property trumps a local property of the same name:
        String username = System.getProperty("user.name");
        testPropValue =
            PropertiesUtil.resolvePropValue(props, "${user.name}");
        assertTrue("Unresolved property value: " + testPropValue,
                   username.equals(testPropValue));

        // the backslash character is special:
        String sysPropName = "GLOBUS_LOCATION";
        String sysPropValue = "c:\\globus\\ws-core-4.0.8-bin\\ws-core-4.0.8";
        String oldSysPropValue = System.setProperty(sysPropName, sysPropValue);
        testPropValue = PropertiesUtil.resolvePropValue(props, "${name4}");
        assertTrue("Unresolved property value: " + testPropValue,
                   sysPropValue.equals(testPropValue));
        if (oldSysPropValue == null) {
            System.clearProperty(sysPropName);
        } else {
            System.setProperty(sysPropName, oldSysPropValue);
        }

        // the dollar sign character is special:
        String localProp = props.getProperty("name5");
        testPropValue = PropertiesUtil.resolvePropValue(props, "${name6}");
        assertTrue("Unresolved property value: " + testPropValue,
                   localProp.equals(testPropValue));
    }
}

