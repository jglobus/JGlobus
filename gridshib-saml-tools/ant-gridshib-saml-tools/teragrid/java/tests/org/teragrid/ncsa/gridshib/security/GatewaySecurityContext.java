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

package org.teragrid.ncsa.gridshib.security;

import java.util.ArrayList;
import java.util.List;
import javax.security.auth.Subject;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.security.SAMLIdentity;
import org.globus.gridshib.security.SAMLSecurityContext;
import org.globus.gridshib.security.SecurityContext;
import org.globus.gridshib.security.SecurityContextFactory;
import org.globus.gridshib.security.SecurityPrincipal;

import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLNameIdentifier;
import org.globus.opensaml11.saml.SAMLSubject;
import org.globus.opensaml11.saml.nameid.TeraGridPrincipalNameIdentifier;

import org.teragrid.ncsa.gridshib.security.TGSecurityContext;
import org.teragrid.ncsa.gridshib.security.TeraGridPrincipal;

/**
 * @since 0.5.1
 */
public class GatewaySecurityContext extends SAMLSecurityContext
                                 implements TGSecurityContext {

    private static final String CLASSNAME =
        GatewaySecurityContext.class.getName();

    private static Log logger = LogFactory.getLog(CLASSNAME);

    /**
     * By convention, the prefix of an <code>entityID</code>
     * associated with a science gateway.
     */
    final private static String ENTITYID_PREFIX =
        "https://saml.teragrid.org/gateway";

    /**
     * The formal name of the
     * <a href="http://www.teragridforum.org/mediawiki/index.php?title=SAML_NameIDs_for_TeraGrid"><code>TeraGridPrincipalName</code></a>
     * identifier, used as the value of XML attribute
     * <code>NameIdentifier/@Format</code>
     * in a SAML token issued by a science gateway.
     */
    final private static String TGPN =
        TeraGridPrincipalNameIdentifier.FORMAT_TGPN;

    /**
     * Set the security context implementation so that all
     * newly created instances of <code>SecurityContext</code>
     * are of type <code>GatewaySecurityContext</code>.
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
     * <code>GatewaySecurityContext</code> instance
     * associated with the given <code>Subject</code>.
     */
    public static GatewaySecurityContext getSecurityContext(Subject subject) {

        SecurityContext secCtx = null;
        try {
            secCtx = SecurityContextFactory.getInstance(subject, CLASSNAME);
        } catch (ClassNotFoundException e) {
            String msg = "Class not found: " + CLASSNAME;
            throw new RuntimeException(msg, e);
        }
        assert (secCtx != null);

        return (GatewaySecurityContext)secCtx;
    }

    public GatewaySecurityContext(Subject subject) {
        super(subject);
    }

    /**
     * Gets the TeraGrid principal associated with this security
     * context implementation.  Calls the
     * {@link #getSecurityPrincipals()} method of the superclass.
     * If the latter contains more than one TeraGrid principal,
     * this method arbitrarily returns the first one found.
     *
     * @return the (possibly null) TeraGrid principal
     */
    public TeraGridPrincipal getTeraGridPrincipal() {

        SecurityPrincipal[] principals = this.getSecurityPrincipals();

        int n = principals.length;
        if (n == 0) {
            logger.debug("No security principals found");
        } else if (n > 1) {
            logger.debug("Multiple security principals found");
        } else {
            logger.debug("Exactly one security principal found");
        }

        int m = 0;
        TeraGridPrincipal principal = null;
        for (int i = 0; i < n; i++) {
            if (principals[i].getType().equals(TGPN)) {
                m++;
                if (principal == null) {
                    String id = principals[i].getId();
                    String issuer = principals[i].getIssuer();
                    String name = principals[i].getName();
                    principal = new TeraGridPrincipal(id, issuer, name);
                }
            }
        }

        if (m == 0) {
            logger.debug("No TeraGrid principals found");
        } else if (m > 1) {
            logger.warn("Multiple TeraGrid principals found (" + m +
                        "), returning the first one");
        } else {
            logger.debug("Exactly one TeraGrid principal found");
        }

        return principal;
    }

    public boolean addUntrustedSAMLIdentity() {

        String id = "_11111111111";
        String issuer = ENTITYID_PREFIX + "/nanohub";
        SAMLNameIdentifier nameid = new SAMLNameIdentifier();
        nameid.setFormat(TGPN);
        nameid.setName("trscavo@nanohub.teragrid.org");
        SAMLSubject subject = new SAMLSubject();
        try {
            subject.setNameIdentifier(nameid);
        } catch (SAMLException e) {
            logger.error("Unable to set NameIdentifier: " + e.getMessage());
            return false;
        }

        return addSAMLSubject(id, issuer, subject);
    }

    public boolean addNonGatewaySAMLIdentity() {

        String id = "_22222222222";
        String issuer = "https://saml.example.org/gridshib";
        String name = "trscavo@example.org";
        String format = SAMLNameIdentifier.FORMAT_EMAIL;

        SAMLNameIdentifier nameid = new SAMLNameIdentifier();
        nameid.setFormat(format);
        nameid.setName(name);
        SAMLSubject subject = new SAMLSubject();
        try {
            subject.setNameIdentifier(nameid);
        } catch (SAMLException e) {
            logger.error("Unable to set NameIdentifier: " + e.getMessage());
            return false;
        }

        if (!addSAMLSubject(id, issuer, subject)) {
            return false;
        }

        // trust non-gateway SAMLIdentity:
        SAMLIdentity identity =
            new SAMLIdentity(id, issuer, name, null, format);
        SAMLIdentity[] identities = this.getSAMLIdentities();
        assert (identities != null);
        for (int i = 0; i < identities.length; i++) {
            if (!identities[i].isTrusted()) {
                if (identities[i].equals(identity)) {
                    identities[i].setTrusted(true);
                    break;
                }
            }
        }

        return true;
    }

    public boolean addGatewaySAMLIdentity() {

        String id = "_3333333333";
        String issuer = ENTITYID_PREFIX + "/gisolve";
        String name = "trscavo@gisolve.teragrid.org";

        SAMLNameIdentifier nameid = new SAMLNameIdentifier();
        nameid.setFormat(TGPN);
        nameid.setName(name);
        SAMLSubject subject = new SAMLSubject();
        try {
            subject.setNameIdentifier(nameid);
        } catch (SAMLException e) {
            logger.error("Unable to set NameIdentifier: " + e.getMessage());
            return false;
        }

        if (!addSAMLSubject(id, issuer, subject)) {
            return false;
        }

        // trust gateway SAMLIdentity:
        SAMLIdentity identity =
            new SAMLIdentity(id, issuer, name, null, TGPN);
        SAMLIdentity[] identities = this.getSAMLIdentities();
        assert (identities != null);
        for (int i = 0; i < identities.length; i++) {
            if (!identities[i].isTrusted()) {
                if (identities[i].equals(identity)) {
                    identities[i].setTrusted(true);
                    break;
                }
            }
        }

        return true;
    }

    public String toString() {

        return toString(false);
    }

    public String toString(boolean verbose) {

        StringBuffer buf = new StringBuffer();
        buf.append(super.toString(verbose));

        return buf.toString();
    }
}
