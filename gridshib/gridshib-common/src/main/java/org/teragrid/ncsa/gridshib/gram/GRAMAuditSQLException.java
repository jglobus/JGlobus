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

package org.teragrid.ncsa.gridshib.gram;

import java.sql.SQLException;

/**
 * @since 0.5.5
 */
public class GRAMAuditSQLException extends SQLException {

    public GRAMAuditSQLException(String msg) {
        super(msg);
    }

    public GRAMAuditSQLException(String msg, Throwable t) {
        super(msg);
        super.initCause(t);
    }

    public int getErrorCode() {

        int n = super.getErrorCode();
        return (n == 0) ? -99 : n;
    }
}
