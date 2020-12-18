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

import java.security.Principal;
import java.security.cert.X509Certificate;

import javax.security.auth.Subject;

/**
 * A <em>security context</em> is an abstract representation of
 * the security information associated with a particular subject.
 */
public interface SecurityContext {

    public boolean isEmpty();

    public Subject getSubject();

    public Principal[] getPrincipals();

    public X509Certificate[] getCertificateChain();

    public boolean addPrincipal(Principal principal);

    public boolean addPrincipals(Principal[] principals);

    public boolean addCertificateChain(X509Certificate[] certs);

    public String toString();

    /**
     * A <code>SecurityPrincipal</code> is a distinguished
     * principal for this <code>SecurityContext</code>.
     *
     * @since 0.5.4
     */
    public SecurityPrincipal getSecurityPrincipal();

    /**
     * An implementation of this <code>SecurityContext</code>
     * interface may distinguish multiple principals.

     * @since 0.5.4
     */
    public SecurityPrincipal[] getSecurityPrincipals();

    /**
     * @since 0.5.4
     */
    public SecurityContextLogger getSecurityContextLogger();

    /**
     * @since 0.5.4
     */
    public void log(String callerID);
}
