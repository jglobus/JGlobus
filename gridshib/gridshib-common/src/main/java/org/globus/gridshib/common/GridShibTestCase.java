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

package org.globus.gridshib.common;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.BaseLogging;

import junit.framework.TestCase;

/**
 * The superclass of all GridShib unit tests.
 * A subclass MUST implement the <code>BaseLogging</code>
 * interface.
 *
 * @see org.globus.gridshib.common.BaseLogging
 *
 * @since 0.3.0
 */
public abstract class GridShibTestCase extends TestCase
                                    implements BaseLogging {

    private static final Class CLASS = GridShibTestCase.class;
    private static final String CLASSNAME = CLASS.getName();

    private static Log logger = LogFactory.getLog(CLASSNAME);

    public static void main(String[] args) {
        logger.info("Running test case");
        junit.textui.TestRunner.run(CLASS);
    }

    public GridShibTestCase(String name) {
        super(name);
        logger.info("Creating test case: " + name);
        configureLogger();
        setDebugLogLevel();
    }

    /**
     * @see TestCase#setUp()
     */
    protected void setUp() throws Exception {
        logger.info("Setting up test case");
        super.setUp();
        //setDebugLogLevel();
    }

    /**
     * @see TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        logger.info("Tearing down test case");
        super.tearDown();
    }
}
