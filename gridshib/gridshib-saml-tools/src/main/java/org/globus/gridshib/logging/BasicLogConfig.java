/*
 * Copyright 2008-2009 University of Illinois
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.globus.gridshib.logging;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import org.globus.gridshib.common.BaseLogging;
import org.globus.gridshib.config.BootstrapConfigLoader;

/**
 * Basic log configuration
 *
 * @see org.globus.gridshib.common.BaseLogging
 *
 * @since 0.3.0
 */
public abstract class BasicLogConfig implements BaseLogging {

    private static Logger log =
        Logger.getLogger(BasicLogConfig.class.getName());

    public String getLogConfigPath() {
        return BootstrapConfigLoader.getLogConfigPathDefault();
    }

    public void configureLogger() {
        PropertyConfigurator.configure(getLogConfigPath());
    }

    public void setDebugLogLevel() {
        Logger.getRootLogger().setLevel(Level.DEBUG);
    }
}

