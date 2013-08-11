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
import java.util.Iterator;
import java.util.Set;

import javax.security.auth.Subject;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * @see org.globus.gridshib.security.SecurityContext
 */
public abstract class BaseSecurityContext implements SecurityContext {

    private static final String CLASSNAME =
        BaseSecurityContext.class.getName();

    static Log logger = LogFactory.getLog(CLASSNAME);

    protected Subject subject;

    protected BaseSecurityContext(Subject subject) {

        if (subject == null) {
            String msg = "Null subject";
            throw new IllegalArgumentException(msg);
        }
        this.subject = subject;
    }

    public Subject getSubject() { return this.subject; }

    public boolean isEmpty() {
        return this.getPrincipals().length == 0;
    }

    public Principal[] getPrincipals() {

        assert (this.subject != null);

        Object[] o = this.subject.getPrincipals().toArray(new Principal[0]);
        return (Principal[])o;
    }

    public boolean addPrincipal(Principal principal) {

        assert (this.subject != null);

        if (principal != null) {
            this.subject.getPrincipals().add(principal);
            return true;
        }
        return false;
    }

    public boolean addPrincipals(Principal[] principals) {

        assert (this.subject != null);

        if (principals != null && principals.length > 0) {
            for (int i = 0; i < principals.length; i++) {
                this.subject.getPrincipals().add(principals[i]);
            }
            return true;
        }
        return false;
    }

    public X509Certificate[] getCertificateChain() {

        assert (this.subject != null);

        X509Certificate[] certs = null;

        Set credset =
            this.subject.getPublicCredentials(X509Certificate[].class);
        Iterator creds = credset.iterator();
        if (creds.hasNext()) {  // first credset is primary
            certs = (X509Certificate[])creds.next();
            logger.debug("Certificate chain found in Subject object");
            logger.debug("Certificate chain length is " + certs.length);
            if (creds.hasNext()) {
                logger.warn("Additional certificate chains ignored");
            }
        }

        if (certs == null) {
            logger.warn("Certificate chain not found in Subject object");
        }
        return certs;
    }

    public boolean addCertificateChain(X509Certificate[] certs) {

        assert (this.subject != null);

        if (certs != null && certs.length > 0) {
            this.subject.getPublicCredentials().add(certs);
            return true;
        }
        return false;
    }

    public String toString() {

        StringBuffer buf = new StringBuffer();

        // buffer X.509 certificates:
        X509Certificate[] certs = this.getCertificateChain();
        assert (certs != null);
        for (int i = 0; i < certs.length; i++) {
            buf.append("X509Certificate ");
            buf.append("{\n  ").append(certs[i].toString());
            buf.append("}\n");
        }

        // buffer principals:
        Principal[] principals = this.getPrincipals();
        for (int i = 0; i < principals.length; i++) {
            buf.append("Principal ");
            buf.append("{\n  name='").append(principals[i].getName());
            buf.append("'\n}");
            buf.append("\n");
        }

        return buf.toString();
    }

    /**
     * @since 0.5.4
     */
    final public void log(String callerID) {
        this.getSecurityContextLogger().log(callerID, this.subject);
    }
}
