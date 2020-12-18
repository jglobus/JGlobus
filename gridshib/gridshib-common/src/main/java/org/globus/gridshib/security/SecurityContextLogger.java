/*
 * Copyright 2007-2009 University of Illinois
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

package org.globus.gridshib.security;

import javax.security.auth.Subject;

/**
 * A concrete implementation of this interface
 * is associated with every implementation of
 * the <code>SecurityContext</code> interface.
 *
 * @see org.globus.gridshib.security.SecurityContext
 *
 * @since 0.5.4
 */
public interface SecurityContextLogger {

    /**
     * Logs the security context associated with the given subject.
     *
     * @param callerID a string identifier for the caller of this method
     * @param subject the authenticated subject
     */
    public void log(String callerID, Subject subject);
}

