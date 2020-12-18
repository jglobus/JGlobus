/*
 * Copyright 2009 University of Illinois
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

package org.globus.gridshib.saml;

import java.io.File;
import java.io.IOException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.OptionBuilder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.cli.Testable;

/**
 * Basic command-line options used by components
 * of the GridShib SAML Tools.
 *
 * @see org.globus.gridshib.common.BaseLoggingCLI
 *
 * @since 0.5.5
 */
public abstract class BasicConfigCLI extends BaseLoggingCLI
                                  implements Testable {

    private static Log logger =
        LogFactory.getLog(BasicConfigCLI.class.getName());

    /**
     * Description of <code>--config</code> option.
     */
    protected static String CONFIG_DESCRIPTION =
        "The path to a configuration file";

    /**
     * Description of <code>--properties</code> option.
     */
    protected static String PROPERTIES_DESCRIPTION =
        "Arbitrary configuration properties";

    /**
     * The <code>--config</code> option.
     */
    protected static Option CONFIG;
    protected static String CONFIG_ARGNAME = "path";
    protected static String CONFIG_LONGOPT = "config";
    protected static String CONFIG_OPT = "F";

    /**
     * The <code>--properties</code> option.
     */
    protected static Option PROPERTIES;
    protected static String PROPERTIES_ARGNAME = "name=value";
    protected static String PROPERTIES_LONGOPT = "properties";
    protected static String PROPERTIES_OPT = "D";

    private File configFile = null;
    private String configProperties = null;

    protected File getConfigFile() { return this.configFile; }
    protected String getConfigProperties() { return this.configProperties; }

    protected BasicConfigCLI(String[] args) {

        super(args);
        this.addOptions();
    }

    private void addOptions() {

        CONFIG =
            OptionBuilder.withArgName(CONFIG_ARGNAME).hasArg()
            .withDescription(CONFIG_DESCRIPTION)
            .withLongOpt(CONFIG_LONGOPT).create(CONFIG_OPT);

        PROPERTIES =
            OptionBuilder.withArgName(PROPERTIES_ARGNAME)
            .hasArgs().withValueSeparator(' ')
            .withDescription(PROPERTIES_DESCRIPTION)
            .withLongOpt(PROPERTIES_LONGOPT).create(PROPERTIES_OPT);

        Options options = getOptions();
        options.addOption(CONFIG);
        options.addOption(PROPERTIES);
    }

    protected void validate() throws Exception {

        super.validate();
        CommandLine line = this.getCommandLine();

        // where is the config file?
        if (line.hasOption(CONFIG.getOpt())) {
            String configPath =
                line.getOptionValue(CONFIG.getOpt()).trim();
            logger.debug("Option config: " + configPath);
            this.configFile = new File(configPath);
        } else {
            logger.debug("Option config not set");
        }

        // any config props specified on the command line?
        if (line.hasOption(PROPERTIES.getOpt())) {
            String[] props = line.getOptionValues(PROPERTIES.getOpt());
            StringBuffer buf = new StringBuffer();
            for (int i = 0; i < props.length; i++) {
                logger.debug("Property " + i + ": " + props[i]);
                if (props[i].trim().equals("")) {
                    logger.debug("Ignoring empty argument");
                    continue;
                }
                buf.append(props[i].trim());
                buf.append("\n");
            }
            this.configProperties = buf.toString();
            logger.debug("Option properties: " + this.configProperties);
        } else {
            logger.debug("Option properties not set");
        }
    }
}

