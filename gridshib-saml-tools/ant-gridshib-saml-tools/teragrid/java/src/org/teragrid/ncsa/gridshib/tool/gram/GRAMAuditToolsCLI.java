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

package org.teragrid.ncsa.gridshib.tool.gram;

import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.saml.BasicConfigCLI;

/**
 * Command-line interface for the GRAM Audit Tools.
 *
 * @see org.globus.gridshib.saml.BasicConfigCLI
 *
 * @since 0.5.5
 */
public abstract class GRAMAuditToolsCLI extends BasicConfigCLI {

    private static Log logger =
        LogFactory.getLog(GRAMAuditToolsCLI.class.getName());

    final protected static int MAX_DELTA_HRS;
    final protected static String DEFAULT_DATETIME_PATTERN;
    final protected static String UTC_DATETIME_PATTERN;

    static {

        // initialize constants:
        MAX_DELTA_HRS = 24;
        DEFAULT_DATETIME_PATTERN = "yyyy-MM-dd'T'HH:mm:ssZ";
        UTC_DATETIME_PATTERN = "yyyy-MM-dd'T'HH:mm:ss'Z'";

        // Override description of <code>--config</code> option.
        CONFIG_DESCRIPTION =
            "The path to a DB connection properties configuration file";
    }

    /**
     * Description of <code>--maxDelta</code> option.
     */
    protected static String MAXDELTA_DESCRIPTION =
        "Selects all jobs created within the given number of hours " +
        "(defaults to " + MAX_DELTA_HRS + ")";

    /**
     * Description of <code>--UTC</code> option.
     */
    protected static String UTC_DESCRIPTION =
        "Indicates the output dateTime strings are in Coordinated " +
        "Universal Time (UTC) format (defaults to local time)";

    /**
     * The <code>--maxDelta</code> option.
     */
    protected static Option MAXDELTA;  // defined in a subclass
    protected static String MAXDELTA_ARGNAME = "hours";
    protected static String MAXDELTA_LONGOPT = "maxDelta";
    protected static String MAXDELTA_OPT = "t";

    /**
     * The <code>--UTC</code> option.
     */
    protected static Option UTC;
    protected static String UTC_LONGOPT = "UTC";
    protected static String UTC_OPT = "Z";

    private int maxDelta;
    protected int getMaxDeltaHours() { return this.maxDelta; }
    protected long getMaxDeltaMillis() { return this.maxDelta*60*60*1000L; }

    private SimpleDateFormat formatter;
    protected String format(Timestamp timestamp) {

        if (timestamp == null) { return null; }
        return this.formatter.format(new Date(timestamp.getTime()));
    }

    protected GRAMAuditToolsCLI(String[] args) {

        super(args);
        this.addOptions();
    }

    private void addOptions() {

        MAXDELTA =
            OptionBuilder.withArgName(MAXDELTA_ARGNAME).hasArg()
            .withDescription(MAXDELTA_DESCRIPTION)
            .withLongOpt(MAXDELTA_LONGOPT).create(MAXDELTA_OPT);

        UTC =
            OptionBuilder.hasArg(false)
            .withDescription(UTC_DESCRIPTION)
            .withLongOpt(UTC_LONGOPT).create(UTC_OPT);

        Options options = this.getOptions();
        options.addOption(MAXDELTA);
        options.addOption(UTC);
    }

    protected void validate() throws Exception {

        super.validate();
        CommandLine line = this.getCommandLine();

        // what is the maximum time difference allowed?
        if (line.hasOption(MAXDELTA.getOpt())) {
            String s = line.getOptionValue(MAXDELTA.getOpt()).trim();
            this.maxDelta = Integer.parseInt(s);
            logger.debug("Option maxDelta: " + this.maxDelta);
        } else {
            this.maxDelta = MAX_DELTA_HRS;
            logger.debug("Option maxDelta is not set " +
                         "and therefore defaults to " + MAX_DELTA_HRS);
        }

        // using UTC dateTime format?
        String pattern;
        if (line.hasOption(UTC.getOpt())) {
            logger.debug("Option UTC set");
            pattern = UTC_DATETIME_PATTERN;
            this.formatter = new SimpleDateFormat(pattern);
            this.formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
        } else {
            logger.debug("Option UTC not set");
            pattern = DEFAULT_DATETIME_PATTERN;
            this.formatter = new SimpleDateFormat(pattern);
            this.formatter.setTimeZone(TimeZone.getDefault());
        }
        logger.debug("Using dateTime pattern: " + pattern);
    }
}

