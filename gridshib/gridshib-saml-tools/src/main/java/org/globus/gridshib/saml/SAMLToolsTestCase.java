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

package org.globus.gridshib.saml;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import org.globus.gridshib.common.BaseLogging;
import org.globus.gridshib.common.GridShibTestCase;
import org.globus.gridshib.config.BootstrapConfigLoader;

import junit.framework.TestCase;

/**
 * The superclass of all GridShib SAML Tools unit tests.
 *
 * @see org.globus.gridshib.common.GridShibTestCase
 *
 * @since 0.3.0
 */
public class SAMLToolsTestCase extends GridShibTestCase
                            implements BaseLogging {

    private static final Class CLASS = SAMLToolsTestCase.class;
    private static final String CLASSNAME = CLASS.getName();

    private static Logger log = Logger.getLogger(CLASSNAME);

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CLASS);
    }

    public SAMLToolsTestCase(String name) {
        super(name);
    }

    /**
     * @see GridShibTestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();
    }

    /**
     * @see GridShibTestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * @see BaseLogging#getLogConfigPath()
     */
    public String getLogConfigPath() {
        return BootstrapConfigLoader.getLogConfigPathDefault();
    }

    /**
     * @see BaseLogging#configureLogger()
     */
    public void configureLogger() {
        log.info("Configuring logger");
        PropertyConfigurator.configure(getLogConfigPath());
    }

    /**
     * @see BaseLogging#setDebugLogLevel()
     */
    public void setDebugLogLevel() {
        log.info("Setting log level to debug");
        Logger.getRootLogger().setLevel(Level.DEBUG);
    }
}
