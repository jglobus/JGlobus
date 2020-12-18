/*
 * Copyright 2006-2009 University of Illinois
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.security.SAMLSecurityContext;
import org.globus.gridshib.security.SecurityContext;
import org.globus.gridshib.security.SecurityContextFactory;

import org.globus.gsi.X509Credential;

/**
 * Extend <code>SAMLSecurityContext</code> by adding a new
 * piece of security information to the security context,
 * namely, the issuing credential.
 */
public class ExtSecurityContext extends SAMLSecurityContext {

    private static final String CLASSNAME =
        ExtSecurityContext.class.getName();

    private static Log logger = LogFactory.getLog(CLASSNAME);

    /**
     * Set the security context implementation so that all
     * newly created instances of <code>SecurityContext</code>
     * are of type <code>ExtSecurityContext</code>.
     */
    public static void init() {
        try {
            SecurityContextFactory.setSecurityContextImpl(CLASSNAME);
        } catch (ClassNotFoundException e) {
            String msg = "Class not found: " + CLASSNAME;
            throw new RuntimeException(msg, e);
        }
    }

    /**
     * A convenience method to get the one and only
     * <code>ExtSecurityContext</code> instance
     * associated with the given <code>Subject</code>.
     */
    public static ExtSecurityContext getSecurityContext(Subject subject) {

        SecurityContext secCtx = null;
        try {
            secCtx = SecurityContextFactory.getInstance(subject, CLASSNAME);
        } catch (ClassNotFoundException e) {
            String msg = "Class not found: " + CLASSNAME;
            throw new RuntimeException(msg, e);
        }
        assert (secCtx != null);

        return (ExtSecurityContext)secCtx;
    }

    private X509Credential issuingCredential;

    public ExtSecurityContext(Subject subject) {
        super(subject);
        this.issuingCredential = null;
    }

    public X509Credential getIssuingCredential() {

        return this.issuingCredential;
    }

    public boolean addIssuingCredential(X509Credential credential) {
        if (credential == null) { return false; }
        this.issuingCredential = credential;
        return true;
    }

    public String toString() {

        return toString(false);
    }

    public String toString(boolean verbose) {

        StringBuffer buf = new StringBuffer();
        buf.append(super.toString(verbose));

        if (this.issuingCredential != null) {
            buf.append("IssuingCredential:\n");
            buf.append(this.issuingCredential.toString());
            buf.append("\n");
        }

        return buf.toString();
    }
}
