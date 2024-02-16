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

package org.globus.gridshib.security.saml;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.security.util.GSIUtil;
import org.globus.gsi.X509Credential;
import org.globus.gsi.CredentialException;
import org.globus.opensaml11.saml.SAMLAssertion;
import org.globus.opensaml11.saml.SAMLAttributeStatement;
import org.globus.opensaml11.saml.SAMLAuthenticationStatement;
import org.globus.opensaml11.saml.SAMLConfig;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLNameIdentifier;
import org.globus.opensaml11.saml.SAMLResponse;
import org.globus.opensaml11.saml.SAMLSubject;
import org.globus.opensaml11.saml.SAMLSubjectAssertion;
import org.globus.util.Util;

/**
 * A <em>self-issued assertion</em> is an X.509-bound
 * SAML assertion where the assertion issuer and
 * the X.509 issuer are one and the same entity.
 * <p>
 * The assertion issuer is identified by an URI called
 * an <em>entityID</em> while the X.509 issuer is
 * denoted by an X.500 Distinguished Name (DN).
 * Thus the relying party must be able to map the
 * assertion issuer (URI) to the X.509 issuer (DN).
 * Usually, this is accomplished by using SAML metadata,
 * so this SAML assertion issuer should supply SAML
 * metadata to the appropriate relying parties.
 */
public class SelfIssuedAssertion extends SAMLSubjectAssertion {

    private static Log logger =
        LogFactory.getLog(SelfIssuedAssertion.class.getName());

    /**
     * Creates an empty <code>SelfIssuedAssertion</code>
     * instance, that is, an assertion with no content.
     * Such an assertion contains a SAML identity wrapped
     * in an otherwise empty SAML <code>SubjectStatement</code>
     * of type <b>samlsap:SubjectStatementType</b>, but other
     * than that, the assertion is empty.  In particular,
     * this assertion does <em>not</em> contain a SAML
     * <code>AuthenticationStatement</code> nor does it
     * contain a SAML <code>AttributeStatement</code>.
     * <p>
     * This <code>SelfIssuedAssertion</code> instance has
     * no <code>SubjectConfirmation</code> element and so
     * the subject confirmation method is inherited from
     * the containing certificate.  That is, this assertion
     * has implicit <code>holder-of-key</code> subject
     * confirmation.  Thus this assertion is used in the
     * case where the presenter is the subject.
     *
     * @param  issueInstant  Time of issuance
     * @param  issuer        EntityID of SAML issuer
     * @param  lifetime      Assertion lifetime (may be null)
     * @param  name          Subject name
     * @param  qualifier     Subject name qualifier
     * @param  format        Subject name format (must be a URI)
     *
     * @exception  org.globus.opensaml11.saml.SAMLException
     *             Thrown if an assertion cannot be constructed
     *             from the given information
     */
    public SelfIssuedAssertion(
            Date issueInstant,
            String issuer,
            int lifetime,
            String name,
            String qualifier,
            String format) throws SAMLException {

        this(issueInstant, issuer, lifetime, name, qualifier, format, false);
    }

    /**
     * Creates an empty <code>SelfIssuedAssertion</code>
     * instance, that is, an assertion with no content.
     * Such an assertion contains a SAML identity wrapped
     * in an otherwise empty SAML <code>SubjectStatement</code>
     * of type <b>samlsap:SubjectStatementType</b>, but other
     * than that, the assertion is empty.  In particular,
     * this assertion does <em>not</em> contain a SAML
     * <code>AuthenticationStatement</code> nor does it
     * contain a SAML <code>AttributeStatement</code>.
     * <p>
     * This <code>SelfIssuedAssertion</code> instance has
     * an explicit <code>SubjectConfirmation</code> element
     * with method <code>sender-vouches</code>.  Thus this
     * assertion is suitable in those cases where the
     * presenter is acting on behalf of the subject.
     *
     * @param  issueInstant  Time of issuance
     * @param  issuer        EntityID of SAML issuer
     * @param  lifetime      Assertion lifetime (may be null)
     * @param  name          Subject name
     * @param  qualifier     Subject name qualifier
     * @param  format        Subject name format (must be a URI)
     *
     * @exception  org.globus.opensaml11.saml.SAMLException
     *             Thrown if an assertion cannot be constructed
     *             from the given information
     *
     * @since 0.3.0
     */
    public SelfIssuedAssertion(
            Date issueInstant,
            String issuer,
            int lifetime,
            String name,
            String qualifier,
            String format,
            boolean wantSenderVouches) throws SAMLException {

        this(
            SAMLConfig.instance().getDefaultIDProvider().getIdentifier(),
            issueInstant,
            issuer,
            computeNotBefore(issueInstant, lifetime),
            computeNotOnOrAfter(issueInstant, lifetime),
            null,  // conditions
            null,  // advice
            null   // statements
            );

        // at this point, this assertion has no statements:
        assert (!getStatements().hasNext());

        // add an empty statement:
        SAMLSubject subject = new Subject(name, qualifier, format);
        if (wantSenderVouches) {
            subject.addConfirmationMethod(SAMLSubject.CONF_SENDER_VOUCHES);
        }
        this.addSubjectStatement(subject);
        assert (this.isEmpty());
    }

    /**
     * Creates a <code>SelfIssuedAssertion</code> instance
     * from its component parts.
     *
     * @param  assertionId   Globally unique identifier
     * @param  issueInstant  Time of issuance
     * @param  issuer        EntityID of SAML issuer
     * @param  notBefore     Start time of assertion validity
     * @param  notOnOrAfter  End time of assertion validity
     * @param  conditions    Conditions on assertion validity
     * @param  advice        Advice content
     * @param  statements    SAML statements to place in assertion
     *
     * @exception  org.globus.opensaml11.saml.SAMLException
     *             Thrown if an assertion cannot be constructed
     *             from the given information
     */
    public SelfIssuedAssertion(
            String assertionId,
            Date issueInstant,
            String issuer,
            Date notBefore,
            Date notOnOrAfter,
            Collection conditions,
            Collection advice,
            Collection statements) throws SAMLException {

        super(
            assertionId,
            issueInstant,
            issuer,
            notBefore,
            notOnOrAfter,
            conditions,
            advice,
            statements
            );
    }

    /**
     * Adds a SAML <code>AuthenticationStatement</code>
     * to this <code>SelfIssuedAssertion</code>.
     * If either of <code>authnMethod</code> and
     * <code>authnInstant</code> are null, this
     * method does nothing.
     *
     * @param  authnMethod   Authentication method (must be a URI)
     * @param  authnInstant  Time of authentication
     * @param  subjectIP     IP address of authenticated subject
     *
     * @exception  org.globus.opensaml11.saml.SAMLException
     *             Thrown if the statement can not be added
     */
    public void addAuthnStatement(String authnMethod,
                                  Date authnInstant,
                                  String subjectIP) throws SAMLException {

        if (authnMethod != null && authnInstant != null) {
            logger.debug("Adding AuthnStatement (" + authnMethod + ", " +
                         authnInstant.toString() + ", " + subjectIP + ")");
            this.addStatement(new AuthnStatement(this.getSubject(),
                                                 authnMethod,
                                                 authnInstant,
                                                 subjectIP));
            assert (!this.isEmpty());
        }
    }

    /**
     * Adds a SAML <code>AttributeStatement</code>
     * to this <code>SelfIssuedAssertion</code>.
     * If no attribute are provided, this method
     * does nothing.
     *
     * @param  attributes    Collection of SAML attributes
     *
     * @exception  org.globus.opensaml11.saml.SAMLException
     *             Thrown if the statement can not be added
     */
    public void addAttributeStatement(Collection attributes)
                               throws SAMLException {

        // temporary debugging:
        if (attributes == null) {
            logger.debug("Null argument (attributes)");
        } else if (attributes.size() == 0) {
            logger.debug("Empty collection of attributes");
        }

        if (attributes != null && attributes.size() > 0) {
            int n = attributes.size();
            logger.debug("Adding AttributeStatement with " + n +
                         " attribute" + ((n == 1) ? "" : "s"));
            this.addStatement(new SAMLAttributeStatement(this.getSubject(),
                                                         attributes));
            assert (!this.isEmpty());
        }
    }

    /**
     * Bind this <code>SelfIssuedAssertion</code> instance to
     * an X.509 proxy certificate.  The given credential is
     * used to sign the issued credential.
     *
     * @param credential the issuing credential
     * @param lifetime the lifetime of the issued credential
     *
     * @return a Globus proxy credential
     *
     * @exception  org.globus.gsi.CredentialException
     *             Thrown if this <code>SelfIssuedAssertion</code>
     *             instance can not be bound to a proxy or if the
     *             proxy can not otherwise be issued
     */
    public X509Credential bindToX509Proxy(X509Credential credential,
                                            int lifetime)
                                     throws CredentialException {

        return GSIUtil.bindAssertion(credential, this, lifetime);
    }

    /**
     * Bind this <code>SelfIssuedAssertion</code> instance to
     * an X.509 proxy certificate.  The given credential is
     * used to sign the issued credential.  The lifetime of
     * the latter defaults to some reasonable value (consult
     * org.globus.gridshib.security.util.GSIUtil#getDefaultLifetime()
     * for the actual value).
     *
     * @param credential the issuing credential
     *
     * @return a Globus proxy credential
     *
     * @exception  org.globus.gsi.GlobusCredentialException
     *             Thrown if this <code>SelfIssuedAssertion</code>
     *             instance can not be bound to a proxy or if the
     *             proxy can not otherwise be issued
     */
    public X509Credential bindToX509Proxy(X509Credential credential)
                                     throws CredentialException {

        return GSIUtil.bindAssertion(credential, this);
    }

    /**
     * Write this <code>SelfIssuedAssertion</code> instance
     * to a file.
     *
     * @param  outputFilename  a system-dependent file name
     *
     * @return true if and only if the file permissions were set
     *         (this is pretty much guaranteed to be false on Windows)
     *
     * @exception java.lang.SecurityException
     * @exception java.io.IOException
     * @exception java.io.FileNotFoundException
     */
    public boolean writeToFile(String outputFilename)
                        throws SecurityException,
                               IOException,
                               FileNotFoundException {

        if (outputFilename == null) {
            String msg = "Null argument (outputFilename)";
            throw new IllegalArgumentException(msg);
        }

        return writeToFile(Util.createFile(outputFilename));
    }

    /**
     * Write this <code>SelfIssuedAssertion</code> instance
     * to a file.
     *
     * @param  outputFile  a system-independent <code>File</code> object
     *
     * @return true if and only if the file permissions were set
     *         (this is pretty much guaranteed to be false on Windows)
     *
     * @exception java.lang.SecurityException
     * @exception java.io.IOException
     * @exception java.io.FileNotFoundException
     */
    public boolean writeToFile(File outputFile)
                        throws SecurityException,
                               IOException,
                               FileNotFoundException {

        if (outputFile == null) {
            String msg = "Null argument (outputFile)";
            throw new IllegalArgumentException(msg);
        }

        String path = outputFile.getPath();
        boolean result = Util.setOwnerAccessOnly(path);
        if (!result) {
            String str = "Unable to set file permissions: " + path;
            logger.warn(str);
        }

        FileOutputStream out = null;
        try {
            out = new FileOutputStream(outputFile);
            out.write(this.toString().getBytes());
            out.flush();
        } finally {
            if (out != null) {
                try { out.close(); } catch (IOException e) { }
            }
        }

        return result;
    }

    /**
     * Add SSO assertions to the <code>Advice</code> element
     * of this <code>SelfIssuedAssertion</code> instance.
     * The assertions in the SAML response are extracted
     * and added to the <code>Advice</code> element.
     *
     * @param response a SAML response
     *
     * @exception  org.globus.opensaml11.saml.SAMLException
     *             Thrown if any of the SSO assertions in
     *             the SAML response can not be added to
     *             the <code>Advice</code> element
     */
    public void nestSSOAssertions(SAMLResponse response)
                           throws SAMLException {

        if (response == null) { return; }

        // extract and nest SSO assertions
        SAMLAssertion assertion = null;
        for (Iterator i = response.getAssertions(); i.hasNext();) {
            // add assertion to Advice element:
            assertion = (SAMLAssertion)i.next();
            try {
                addAdvice((SAMLAssertion)assertion.clone());
            } catch (CloneNotSupportedException e) {
                String msg = "Unable to clone assertion";
                throw new SAMLException(msg, e);
            }
        }
    }

    /**
     * Computes NotBefore attribute.  Returns null if issueInstant
     * is null or lifetime is less than or equal to zero.
     */
    private static Date computeNotBefore(Date issueInstant, int lifetime) {
        Date notBefore = null;
        if (issueInstant == null) {
            logger.warn("Null issueInstant");
        } else if (lifetime > 0) {
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(issueInstant);
            calendar.add(Calendar.SECOND, -Math.min(lifetime, 60*5));
            notBefore = calendar.getTime();
            logger.debug("Computed NotBefore attribute: " + notBefore);
        } else {
            logger.warn("Non-positive lifetime: " + lifetime);
        }
        return notBefore;
    }

    /**
     * Computes NotOnOrAfter attribute.  Returns null if issueInstant
     * is null or lifetime is less than or equal to zero.
     */
    private static Date computeNotOnOrAfter(Date issueInstant, int lifetime) {
        Date notOnOrAfter = null;
        if (issueInstant == null) {
            logger.warn("Null issueInstant");
        } else if (lifetime > 0) {
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(issueInstant);
            calendar.add(Calendar.SECOND, lifetime);
            notOnOrAfter = calendar.getTime();
            logger.debug("Computed NotOnOrAfter attribute: " + notOnOrAfter);
        } else {
            logger.warn("Non-positive lifetime: " + lifetime);
        }
        return notOnOrAfter;
    }

    /**
     * A wrapper class.
     *
     * @see org.globus.opensaml11.saml.SAMLSubject
     */
    /* private */ static class Subject extends SAMLSubject {

        public Subject(String name,
                       String nameQualifier,
                       String format)
                throws SAMLException {

            super(new SAMLNameIdentifier(name, nameQualifier, format),
                  null,  // confirmationMethods
                  null,  // confirmationData
                  null   // keyInfo
                  );
        }
    }

    /**
     * A wrapper class.
     *
     * @see org.globus.opensaml11.saml.SAMLAuthenticationStatement
     */
    /* private */ static class AuthnStatement extends SAMLAuthenticationStatement {

        public AuthnStatement(SAMLSubject subject,
                              String authnMethod,
                              Date authnInstant,
                              String subjectIP)
                       throws SAMLException {

            super(subject,
                  authnMethod,
                  authnInstant,
                  subjectIP,
                  null,  // subjectDNS
                  null   // bindings
                  );
        }
    }
}


