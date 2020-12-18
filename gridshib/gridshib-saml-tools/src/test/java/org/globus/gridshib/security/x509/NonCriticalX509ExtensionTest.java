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

package org.globus.gridshib.security.x509;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.saml.SAMLToolsTestCase;

/**
 * @since 0.3.0
 */
public class NonCriticalX509ExtensionTest extends SAMLToolsTestCase {

    private static final Class CLASS = NonCriticalX509ExtensionTest.class;
    private static final String CLASSNAME = CLASS.getName();

    private static Log logger = LogFactory.getLog(CLASSNAME);

    // dummy test data:
    private static final String OID = "1.3.6.1.4.1.3536.1.0.0.0";

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CLASS);
    }

    public NonCriticalX509ExtensionTest(String name) {
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

    public void testNonCriticalX509Extension() throws Exception {

        NonCriticalX509Extension ext = new NonCriticalX509Extension(OID);
        assertTrue("Non-critical X.509 extension is initially critical",
                   !ext.isCritical());
        ext.setCritical(true);  // this method does nothing
        assertTrue("Non-critical X.509 extension has become critical",
                   !ext.isCritical());
        assertTrue("Non-critical X.509 extension OIDs do not match",
                   ext.getOid().equals(OID));
    }
}

