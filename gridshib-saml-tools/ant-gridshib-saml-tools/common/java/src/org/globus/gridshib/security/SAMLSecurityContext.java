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

import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.security.auth.Subject;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.LoadException;
import org.globus.gridshib.security.AttributeSet;
import org.globus.gridshib.security.BasicAttribute;
import org.globus.gridshib.security.SAMLAuthnContext;
import org.globus.gridshib.security.SAMLIdentity;
import org.globus.gridshib.security.SAMLPrincipal;
import org.globus.gridshib.security.SAMLSecurityContextLogger;
import org.globus.gridshib.security.SecurityContextLogger;

import org.globus.opensaml11.saml.SAMLAttribute;
import org.globus.opensaml11.saml.SAMLAttributeStatement;
import org.globus.opensaml11.saml.SAMLAuthenticationStatement;
import org.globus.opensaml11.saml.SAMLAuthorizationDecisionStatement;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLNameIdentifier;
import org.globus.opensaml11.saml.SAMLStatement;
import org.globus.opensaml11.saml.SAMLSubject;
import org.globus.opensaml11.saml.SAMLSubjectAssertion;
import org.globus.opensaml11.saml.SubjectStatement;

/**
 * This <code>SAMLSecurityContext</code> object encapsulates the
 * following information:
 * <ol>
 *   <li>an ordered list of <code>SAMLSubjectAssertion</code> objects</li>
 *   <li>an ordered list of <code>SAMLIdentity</code> objects</li>
 *   <li>a set of <code>SAMLAuthnContext</code> objects</li>
 *   <li>a set of <code>BasicAttribute</code> objects</li>
 *   <li>a set of <code>SAMLAuthzDecision</code> objects</li>
 * </ol>
 * The <code>SAMLSubjectAssertion</code> objects are the SAML
 * assertions that were parsed by this <code>SAMLSecurityContext</code>
 * instance.  The <code>SAMLIdentity</code> objects are used for
 * IdP discovery whereas the <code>SAMLAuthnContext</code> objects
 * are used strictly for access control.  The <code>BasicAttribute</code>
 * objects are used for access control as well as whitelisting and
 * blacklisting.  The <code>SAMLAuthzDecision</code> class is not yet
 * implemented.
 * <p>
 * This class implements the notion of a <em>current SAML identity</em>,
 * which is a distinguished instance of <code>SAMLIdentity</code>
 * that is used primarily for query purposes.  An application may
 * set the <code>currentSAMLIdentity</code> object explicitly with
 * the {@link #setCurrentSAMLIdentity(SAMLIdentity)} method.
 * Otherwise, the <code>currentSAMLIdentity</code> is the first
 * item in the ordered list of SAML <code>SAMLIdentity</code> objects
 * associated with this <code>SecurityContext</code>.
 *
 * @see org.globus.gridshib.security.BaseSecurityContext
 */
public class SAMLSecurityContext extends BaseSecurityContext {

    private static final String CLASSNAME =
        SAMLSecurityContext.class.getName();

    static Log logger = LogFactory.getLog(CLASSNAME);

    /**
     * @since 0.3.0
     */
    public static SAMLSecurityContext getSAMLSecurityContext(Subject subject) {

        SecurityContext secCtx = null;
        try {
            secCtx = SecurityContextFactory.getInstance(subject, CLASSNAME);
        } catch (ClassNotFoundException e) {
            String msg = "Class not found: " + CLASSNAME;
            throw new RuntimeException(msg, e);
        }
        assert (secCtx != null);

        return (SAMLSecurityContext)secCtx;
    }

    protected SAMLIdentity currentSAMLIdentity;
    protected List assertions;
    protected List tokens;
    protected List identities;
    protected Set authnContexts;
    protected Set attributes;

    // Does this need to be public so that SecurityContextFactory
    // can create an instance?  (Evidently not.)
    protected SAMLSecurityContext(Subject subject) {
        super(subject);
        this.currentSAMLIdentity = null;
        this.assertions = new ArrayList();
        this.tokens = new ArrayList();
        this.identities = new ArrayList();
        this.authnContexts = new HashSet();
        this.attributes = new AttributeSet();
    }

    /**
     * Determines if this instance is empty.
     * This method overrides the corresponding method
     * in the superclass
     */
    public boolean isEmpty() {
        return this.identities.size() == 0 &&
               this.authnContexts.size() == 0 &&
               this.attributes.size() == 0;
    }

    public boolean hasCurrentSAMLIdentity() {
        return getCurrentSAMLIdentity() != null;
    }

    public SAMLIdentity getCurrentSAMLIdentity() {
        SAMLIdentity id = this.currentSAMLIdentity;
        if (id == null && this.identities.size() > 0) {
            id = (SAMLIdentity)(identities.get(0));
        }
        return id;
    }

    public void setCurrentSAMLIdentity(SAMLIdentity id) {
        this.currentSAMLIdentity = id;
    }

    /**
     * @return the SAML assertions that were parsed by this
     * <code>SAMLSecurityContext</code> instance
     *
     * @since 0.3.0
     *
     * @deprecated
     */
    public SAMLSubjectAssertion[] getSAMLAssertions() {
        logger.debug("Found " + this.assertions.size() +
                     " parsed assertion" +
                     ((this.assertions.size() == 1) ? "" : "s"));
        Object[] o = this.assertions.toArray(new SAMLSubjectAssertion[0]);
        return (SAMLSubjectAssertion[])o;
    }

    /**
     * @return the SAML tokens associated with this
     * <code>SAMLSecurityContext</code> instance
     *
     * @since 0.5.4
     */
    public SAMLToken[] getSAMLTokens() {
        logger.debug("Found " + this.tokens.size() +
                     " token" +
                     ((this.tokens.size() == 1) ? "" : "s"));
        Object[] o = this.tokens.toArray(new SAMLToken[0]);
        return (SAMLToken[])o;
    }

    /**
     * @return the SAML identities associated with this
     * <code>SAMLSecurityContext</code> instance
     */
    public SAMLIdentity[] getSAMLIdentities() {
        logger.debug("Found " + this.identities.size() +
                     " identit" +
                     ((this.identities.size() == 1) ? "y" : "ies"));
        Object[] o = this.identities.toArray(new SAMLIdentity[0]);
        return (SAMLIdentity[])o;
    }

    /**
     * Gets a distinguished security principal.  In this case, the
     * security principal is an instance of <code>SAMLPrincipal</code>.
     *
     * @return an arbitrary security principal associated
     *         with this <code>SAMLSecurityContext</code> instance
     *
     * @see #getSAMLPrincipal(SAMLIdentity)
     *
     * @since 0.5.4
     */
    public SecurityPrincipal getSecurityPrincipal() {

        SAMLIdentity[] identities = this.getSAMLIdentities();
        for (int i = 0; i < identities.length; i++) {
            SAMLPrincipal principal = getSAMLPrincipal(identities[i]);
            if (principal != null) {
                return principal;
            }
        }

        return null;
    }

    /**
     * Gets the distinguished security principals.  In this case, the
     * security principals are all the <code>SAMLPrincipal</code>
     * instances associated with this <code>SAMLSecurityContext</code>
     * instance.
     * <p>
     * This method is called by <code>SAMLSecurityContextLogger</code>.
     * Subclasses are encouraged to override this method to add other
     * implementations of the <code>SecurityPrincipal</code> interface
     * to the return value and thereby add to the log output.
     *
     * @return the security principals associated with this
     *         <code>SAMLSecurityContext</code> instance
     *
     * @see #getSAMLPrincipal(SAMLIdentity)
     * @see #getSAMLPrincipals(BasicAttribute)
     * @see org.globus.gridshib.security.SAMLSecurityContextLogger
     *
     * @since 0.5.4
     */
    public SecurityPrincipal[] getSecurityPrincipals() {

        List principals = new ArrayList();

        SAMLIdentity[] identities = this.getSAMLIdentities();
        int m = identities.length;
        for (int i = 0; i < m; i++) {
            SAMLPrincipal principal = getSAMLPrincipal(identities[i]);
            if (principal != null) {
                principals.add(principal);
            }
        }
        int p1 = principals.size();
        logger.debug("Found " + p1 + " SAML principal" +
                     ((p1 == 1) ? " " : "s ") +
                     "associated with " + m + " SAMLIdentit" +
                     ((m == 1) ? "y" : "ies"));

        BasicAttribute[] attributes = this.getAttributes();
        int n = attributes.length;
        for (int i = 0; i < n; i++) {
            List list = getSAMLPrincipals(attributes[i]);
            if (!list.isEmpty()) {
                principals.addAll(list);
            }
        }
        int p2 = principals.size();
        logger.debug("Found " + (p2 - p1) + " SAML principal" +
                     ((p2 - p1 == 1) ? " " : "s ") +
                     "associated with " + n + " BasicAttribute" +
                     ((n == 1) ? "" : "s"));

        Object[] o = principals.toArray(new SAMLPrincipal[0]);
        return (SAMLPrincipal[])o;
    }

    /**
     * A convenience method that simply calls the
     * {@link #getSecurityPrincipals()} method and casts the
     * result to an array of <code>SAMLPrincipal</code>.
     *
     * @return the SAML principals associated with this
     *         <code>SAMLSecurityContext</code> instance
     *
     * @since 0.4.3
     */
    public SAMLPrincipal[] getSAMLPrincipals() {

        return (SAMLPrincipal[])this.getSecurityPrincipals();
    }

    /**
     * Gets the SAML principal associated with the given
     * <code>SAMLIdentity</code> instance.  This method
     * returns null if the given <code>SAMLIdentity</code>
     * instance is untrusted or the <code>NameQualifier</code>
     * attribute of the corresponding SAML name identifier
     * is not null.
     *
     * @param identity a SAML identity
     *
     * @return the (possibly null) SAML principal associated
     *         with the given <code>SAMLIdentity</code> instance
     *
     * @since 0.5.4
     */
    static SAMLPrincipal getSAMLPrincipal(SAMLIdentity identity) {

        logger.debug("Computing SAML principal for identity " +
                     identity.getFormat());

        if (!identity.isTrusted()) {
            String msg = "No SAML principal computed since this " +
                         "identity is not trusted";
            logger.debug(msg);
            return null;
        }

        if (identity.getNameQualifier() != null) {
            String msg = "No SAML principal computed since this " +
                         "identity is qualified: " +
                         identity.getNameQualifier();
            logger.debug(msg);
            return null;
        }

        SAMLPrincipal principal =
            new SAMLPrincipal(identity.getId(), identity.getIssuer(),
                              identity.getName(), identity.getFormat());
        logger.debug("SAML principal computed: " + principal.toString());

        return principal;
    }

    /**
     * Gets the SAML principals associated with the given
     * <code>BasicAttribute</code> instance.  This method
     * returns an empty list if the given <code>BasicAttribute</code>
     * instance is not trusted or is not an identity attribute.
     *
     * @param attribute a basic attribute
     *
     * @return a (possibly empty) list of <code>SAMLPrincipal</code>
     *         objects associated with this
     *         <code>BasicAttribute</code> instance
     *
     * @since 0.5.4
     */
    static List getSAMLPrincipals(BasicAttribute attribute) {

        logger.debug("Computing SAML principals for attribute " +
                     attribute.getName());

        if (!attribute.isTrusted()) {
            String msg = "No SAML principals computed since this " +
                         "attribute is not trusted";
            logger.debug(msg);
            return new ArrayList();
        }

        try {
            if (!attribute.isIdentityAttribute()) {
                String msg = "No SAML principals computed since " +
                             "this attribute is not an identity " +
                             "attribute: " + attribute.getName();
                logger.debug(msg);
                return new ArrayList();
            }
        } catch (LoadException e) {
            String msg = "Unable to reload identity attributes";
            logger.error(msg, e);
            return new ArrayList();
        }

        List principals = new ArrayList();

        String[] values = attribute.getValues();
        int n = values.length;
        logger.debug("Adding " + n + " SAML principal" +
                     ((values.length == 1) ? "" : "s"));
        for (int i = 0; i < n; i++) {
            SAMLPrincipal principal =
                new SAMLPrincipal(attribute.getId(), attribute.getIssuer(),
                                  values[i], attribute.getName());
            principals.add(principal);
            logger.debug("SAML principal computed: " +
                         principal.toString());
        }

        return principals;
    }

    /**
     * @return the SAML authentication contexts associated
     * with this <code>SAMLSecurityContext</code> instance
     */
    public SAMLAuthnContext[] getSAMLAuthnContexts() {
        logger.debug("Found " + this.authnContexts.size() +
                     " authn context" +
                     ((this.authnContexts.size() == 1) ? "" : "s"));
        Object[] o = this.authnContexts.toArray(new SAMLAuthnContext[0]);
        return (SAMLAuthnContext[])o;
    }

    /**
     * @return the SAML attributes associated with this
     * <code>SAMLSecurityContext</code> instance
     */
    public BasicAttribute[] getAttributes() {
        logger.debug("Found " + this.attributes.size() +
                     " attribute" +
                     ((this.attributes.size() == 1) ? "" : "s"));
        Object[] o = this.attributes.toArray(new BasicAttribute[0]);
        return (BasicAttribute[])o;
    }

    /**
     * @return true if this security context changed as a result of the call
     */
    public boolean removeSAMLToken(SAMLToken token) {
        return this.tokens.remove(token);
    }

    /**
     * @return true if this security context changed as a result of the call
     */
    public boolean removeSAMLIdentity(SAMLIdentity identity) {
        return this.identities.remove(identity);
    }

    /**
     * @return true if this security context changed as a result of the call
     */
    public boolean removeSAMLAuthnContext(SAMLAuthnContext authnContext) {
        return this.authnContexts.remove(authnContext);
    }

    /**
     * @return true if this security context changed as a result of the call
     */
    public boolean removeAttribute(BasicAttribute attribute) {
        return this.attributes.remove(attribute);
    }

    /**
     * Adds the security information in the given SAML assertion
     * to this security context.
     * A parsed SAML assertion can not be "unparsed," that is,
     * a parsed SAML assertion can not be removed from the
     * security context.
     *
     * @return true if this security context changed as a result of the call
     *
     * @since 0.3.0
     */
    public boolean parseSAMLAssertion(SAMLSubjectAssertion assertion) {

        assert (assertion != null);

        logger.info("Adding SAML SubjectAssertion to security context");
        this.assertions.add(assertion);
        logger.debug(assertion.toString());

        logger.info("Adding SAMLToken to security context");
        SAMLToken token = new SAMLToken(assertion);
        this.tokens.add(token);
        logger.debug(token.toString());

        logger.info("Adding SAML Subject to security context");
        logger.debug(assertion.getSubject().toString());
        String id = assertion.getId();
        String issuer = assertion.getIssuer();
        addSAMLSubject(id, issuer, assertion.getSubject());

        // process SAML statements:
        Iterator statements = assertion.getStatements();
        while (statements.hasNext()) {
            SAMLStatement statement = (SAMLStatement)statements.next();
            if (statement instanceof SAMLAuthenticationStatement) {
                logger.info("Adding SAML AuthenticationStatement " +
                            "to security context");
                SAMLAuthenticationStatement authnStatement =
                    (SAMLAuthenticationStatement)statement;
                logger.debug(authnStatement.toString());
                addSAMLAuthnStatement(id, issuer, authnStatement);
            } else if (statement instanceof SAMLAttributeStatement) {
                logger.info("Adding SAML AttributeStatement " +
                            "to security context");
                SAMLAttributeStatement attrStatement =
                    (SAMLAttributeStatement)statement;
                logger.debug(attrStatement.toString());
                addSAMLAttributeStatement(id, issuer, attrStatement);
            } else if (statement instanceof SAMLAuthorizationDecisionStatement) {
                logger.warn("Unsupported statement type");
                logger.info("Skipping statement: " + statement.toString());
            } else if (statement instanceof SubjectStatement) {
                logger.info("Skipping empty SubjectStatement: " +
                            statement.toString());
            } else {
                logger.warn("Unknown statement type");
                logger.info("Skipping statement: " + statement.toString());
            }
        }

        return true;
    }

    /**
     * @return true if this security context changed as a result of the call
     *
     * @since 0.3.0
     */
    protected boolean addSAMLSubject(String id,
                                     String issuer,
                                     SAMLSubject subject) {

        assert (issuer != null && subject != null);

        SAMLNameIdentifier nameid = subject.getNameIdentifier();
        SAMLIdentity identity =
            new SAMLIdentity(id, issuer, nameid.getName(),
                                         nameid.getNameQualifier(),
                                         nameid.getFormat());
        return this.identities.add(identity);
    }

    /**
     * @return true if this security context changed as a result of the call
     *
     * @since 0.3.0
     */
    protected boolean addSAMLAuthnStatement(String id, String issuer,
                               SAMLAuthenticationStatement statement) {

        assert (issuer != null && statement != null);

        /* A schema-valid SAML V1.1 assertion is guaranteed
         * to have a non-null AuthenticationMethod attribute.
         * Moreover, this attribute MUST be a URI (which the
         * parser checks).  Yet the OpenSAML API stores this
         * attribute as a String (rather than a URI), so we
         * have to jump through hoops.
         */
        URI authnMethod = null;
        try {
            authnMethod = new URI(statement.getAuthMethod());
        } catch (URISyntaxException e) {
            String msg = "AuthenticationStatement is invalid, " +
                         "AuthenticationMethod must be a URI";
            logger.warn(msg);
            return false;
        }

        return this.authnContexts.add(
            new SAMLAuthnContext(id, issuer, authnMethod,
                                 statement.getAuthInstant(),
                                 statement.getSubjectIP(),
                                 statement.getSubjectDNS()));
    }

    /**
     * @return true if this security context changed as a result of the call
     *
     * @since 0.3.0
     */
    protected boolean addSAMLAttributeStatement(String id, String issuer,
                                   SAMLAttributeStatement statement) {

        assert (issuer != null && statement != null);

        Iterator attributes = statement.getAttributes();
        return addSAMLAttributes(id, issuer, attributes);
    }

    /**
     * @return true if this security context changed as a result of the call
     *
     * @since 0.3.0
     */
    protected boolean addSAMLAttributes(String id, String issuer,
                                        Iterator attributes) {

        assert (issuer != null && attributes != null);

        boolean result = false;
        while (attributes.hasNext()) {
            SAMLAttribute attribute = (SAMLAttribute)attributes.next();
            if (addSAMLAttribute(id, issuer, attribute)) { result = true; }
        }
        return result;
    }

    /**
     * @return true if this security context changed as a result of the call
     *
     * @since 0.3.0
     */
    protected boolean addSAMLAttribute(String id, String issuer,
                                       SAMLAttribute attribute) {

        assert (issuer != null && attribute != null);

        BasicAttribute a = new BasicAttribute(id, issuer,
                                              attribute.getName(),
                                              attribute.getNamespace());
        Iterator values = attribute.getValues();
        while (values.hasNext()) {
            a.addValue((String)values.next());
        }
        return this.attributes.add(a);
    }

    /**
     * Converts this <code>SAMLSecurityContext</code> to
     * a string representation.  This method overrides the
     * corresponding method in the superclass, but prepends
     * the string representation of the superclass to this
     * string representation.
     * <p>
     * Calling this method is equivalent to calling
     * <code>toString(false)</code>.
     */
    public String toString() {

        return this.toString(false);
    }

    /**
     * Converts this <code>SAMLSecurityContext</code> to
     * a string representation.
     *
     * @param verbose if true, the returned string will
     *        include string representations of <strong>all</strong>
     *        security items, including string representations of
     *        all X.509 certificates in the certificate chain and
     *        raw, unparsed SAML assertions
     *
     * @since 0.3.0
     */
    public String toString(boolean verbose) {

        StringBuffer buf = new StringBuffer();

        if (verbose) {

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
                buf.append("'\n  type='unknown");
                buf.append("'\n}");
                buf.append("\n");
            }
        }

        // buffer SAML principals:
        SAMLPrincipal[] samlPrincipals = this.getSAMLPrincipals();
        assert (samlPrincipals != null);
        for (int i = 0; i < samlPrincipals.length; i++) {
            buf.append(samlPrincipals[i].toString());
            buf.append("\n");
        }

        // buffer SAML tokens:
        SAMLToken[] tokens = this.getSAMLTokens();
        assert (tokens != null);
        for (int i = 0; i < tokens.length; i++) {
            buf.append(tokens[i].toString(verbose));
            buf.append("\n");
        }

        // buffer SAML identities:
        SAMLIdentity[] identities = this.getSAMLIdentities();
        assert (identities != null);
        for (int i = 0; i < identities.length; i++) {
            buf.append(identities[i].toString());
            buf.append("\n");
        }

        // buffer SAML authn contexts:
        SAMLAuthnContext[] authnContexts = this.getSAMLAuthnContexts();
        assert (authnContexts != null);
        for (int i = 0; i < authnContexts.length; i++) {
            buf.append(authnContexts[i].toString());
            buf.append("\n");
        }

        // buffer basic attributes:
        BasicAttribute[] attributes = this.getAttributes();
        assert (attributes != null);
        for (int i = 0; i < attributes.length; i++) {
            buf.append(attributes[i].toString());
            buf.append("\n");
        }

        return buf.toString();
    }

    /**
     * @since 0.5.4
     */
    public SecurityContextLogger getSecurityContextLogger() {
        return new SAMLSecurityContextLogger();
    }
}
