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

package org.teragrid.ncsa.gridshib.security.util;

import java.security.Principal;
import javax.security.auth.Subject;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.security.SecurityContext;
import org.globus.gridshib.security.SecurityContextFactory;

import org.teragrid.ncsa.gridshib.security.TGSecurityContext;
import org.teragrid.ncsa.gridshib.security.TeraGridPrincipal;

/**
 * A utility class used by GRAM to determine the value of
 * the <code>gateway_user</code> column of the GRAM audit
 * table.
 *
 * @since 0.5.1
 */
public class SAMLUtil {

    private static Log logger =
        LogFactory.getLog(SAMLUtil.class.getName());

    /**
     * Gets the gateway user identity.
     *
     * @param subject the authenticated subject
     *
     * @return the SAML identity of the end user if the request
     *         is from a trusted gateway; otherwise returns null
     */
    public static String getGatewayIdentity(Subject subject) {

        String CLASSNAME = TGSecurityContext.class.getName();

        SecurityContext secCtx =
            SecurityContextFactory.getInstance(subject);

        if (secCtx instanceof TGSecurityContext) {
            logger.debug("SecurityContextImpl is an implementation of " +
                         CLASSNAME);
            TeraGridPrincipal principal =
                ((TGSecurityContext)secCtx).getTeraGridPrincipal();
            if (principal == null) {
                logger.debug("TeraGrid principal is null");
                return null;
            }
            String name = principal.getName();
            assert (name != null);
            logger.debug("Principal name is: " + name);
            return name;
        } else {
            logger.debug("SecurityContextImpl is not an implementation of " +
                         CLASSNAME);
            return null;
        }
    }
}
