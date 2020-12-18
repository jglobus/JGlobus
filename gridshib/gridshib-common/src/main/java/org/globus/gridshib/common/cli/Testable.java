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

package org.globus.gridshib.common.cli;

/**
 * A testing interface for Java command-line applications.
 *
 * @since 0.5.0
 */
public interface Testable {

    // exit codes:
    public static final int SUCCESS_CODE = 0;
    public static final int SECURITY_ERROR = -2;
    public static final int CONFIG_FILE_ERROR = -1;
    public static final int COMMAND_LINE_ERROR = 1;
    public static final int APPLICATION_ERROR = 2;

    /**
     * Gets the command-line arguments used to
     * invoke the application.
     *
     * @return an array of command-line arguments
     */
    public String[] getArgs();

    /**
     * Execute the command-line application. This
     * method MUST call {@link #setExitCode(int)} but
     * MUST NOT call {@link java.lang.System#exit(int)}.
     *
     * @exception org.globus.gridshib.common.cli.ApplicationRuntimeException
     *            if execution of the application fails
     */
    public void run() throws ApplicationRuntimeException;

    /**
     * Sets the exit code of the application.
     *
     * @param exitCode the exit code
     */
    public void setExitCode(int exitCode);

    /**
     * Gets the exit code.  This method MUST be called
     * before calling the {@link #setExitCode(int)} method,
     * otherwise this method returns {@link #SECURITY_ERROR}.
     *
     * @return the exit code
     */
    public int getExitCode();

    /**
     * A convenience method that executes the application
     * and gets the exit code.
     *
     * @return the exit code
     */
    public int getExitCode(boolean forceRun);
}

