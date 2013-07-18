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

package org.globus.opensaml11.saml;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;
import java.util.Collection;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.w3c.dom.*;

/**
 * Represents a SAML Assertion that conforms to the
 * <em>SAML&nbsp;V1.1 Subject-based Assertion Profile</em>.
 * <p>
 * A <code>SAMLSubjectAssertion</code> may or may not
 * contain an empty <code>SubjectStatement</code>.
 * In any case, a <code>SAMLSubjectAssertion</code>
 * does <em>not</em> contain a <em>redundant</em>
 * <code>SubjectStatement</code>.  This characteristic
 * is invariant throughout the lifetime of the assertion.
 *
 * @author     Tom Scavo
 */
public class SAMLSubjectAssertion extends SAMLAssertion implements Cloneable {

    private static Logger log =
        Logger.getLogger(SAMLSubjectAssertion.class.getName());

    /**
     * Default constructor
     */
    public SAMLSubjectAssertion() {}

    /**
     * Builds an assertion out of its component parts
     *
     * @param  issuer             Name of SAML authority issuing assertion
     * @param  notBefore          Optional start of validity
     * @param  notOnOrAfter       Optional end of validity
     * @param  conditions         Set of conditions on validity
     * @param  advice             Optional advice content
     * @param  statements         Set of SAML statements to place in assertion
     * @exception  org.globus.opensaml11.saml.SAMLException
     *             Raised if an assertion cannot be constructed
     *             from the supplied information
     */
    public SAMLSubjectAssertion(
            String issuer,
            Date notBefore,
            Date notOnOrAfter,
            Collection conditions,
            Collection advice,
            Collection statements
            ) throws SAMLException {

        this(
            SAMLConfig.instance().getDefaultIDProvider().getIdentifier(),
            new Date(),
            issuer,
            notBefore,
            notOnOrAfter,
            conditions,
            advice,
            statements
            );
    }

    /**
     * Builds an assertion out of its component parts
     * @param  assertionId        Unique identifier for assertion
     * @param  issueInstant       Time of issuance
     * @param  issuer             Name of SAML authority issuing assertion
     * @param  notBefore          Optional start of validity
     * @param  notOnOrAfter       Optional end of validity
     * @param  conditions         Set of conditions on validity
     * @param  advice             Optional advice content
     * @param  statements         Set of SAML statements to place in assertion
     * @exception  org.globus.opensaml11.saml.SAMLException
     *             Raised if an assertion cannot be constructed
     *             from the supplied information
     */
    public SAMLSubjectAssertion(
            String assertionId,
            Date issueInstant,
            String issuer,
            Date notBefore,
            Date notOnOrAfter,
            Collection conditions,
            Collection advice,
            Collection statements
            ) throws SAMLException {

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
     * Constructs a subject-based assertion from an
     * ordinary assertion object.
     *
     * @param  assertion          A SAML assertion
     * @exception  org.globus.opensaml11.saml.SAMLException
     *             Thrown if the object cannot be constructed
     */
    public SAMLSubjectAssertion(SAMLAssertion assertion) throws SAMLException {
        this(new ByteArrayInputStream(assertion.toString().getBytes()));
    }

    /**
     * Reconstructs a subject-based assertion from a DOM tree
     *
     * @param  e                  The root of a DOM tree
     * @exception  org.globus.opensaml11.saml.SAMLException
     *             Thrown if the object cannot be constructed
     */
    public SAMLSubjectAssertion(Element e) throws SAMLException {
        fromDOM(e);
    }

    /**
     * Reconstructs a subject-based assertion from a stream
     *
     * @param  in                 A stream containing XML
     * @exception  org.globus.opensaml11.saml.SAMLException
     *             Raised if an exception occurs while constructing
     *             the object.
     */
    public SAMLSubjectAssertion(InputStream in) throws SAMLException {
        fromDOM(fromStream(in));
    }

    /**
     * Reconstructs a subject-based assertion of a particular
     * minor version from a stream
     *
     * @param  in                 A stream containing XML
     * @param  minor              The minor version of the incoming assertion
     * @exception  org.globus.opensaml11.saml.SAMLException
     *             Raised if an exception occurs while constructing
     *             the object.
     */
    public SAMLSubjectAssertion(InputStream in, int minor) throws SAMLException {
        fromDOM(fromStream(in,minor));
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLAssertion#fromDOM(org.w3c.dom.Element)
     */
    public void fromDOM(Element e) throws SAMLException {
        super.fromDOM(e);
        if (hasRedundantSubjectStatement()) {
            removeSubjectStatements();
        }
        assert (!hasRedundantSubjectStatement());
        checkValidity();
    }

    /**
     * Gets the statement subject. All statements contained
     * in this SAMLSubjectAssertion have subjects that
     * "very strongly match" this subject, by definition.
     *
     * @return    The statement subject
     */
    public SAMLSubject getSubject() {

        if (statements.size() > 0) {
            // all the subjects are the same, so return the first one:
            SAMLSubject subject =
                ((SAMLSubjectStatement)statements.get(0)).getSubject();
            try {
                return (SAMLSubject)subject.clone();
            } catch (CloneNotSupportedException e) {
                log.warn("Clone not supported, returning null", e);
            }
        }
        return null;
    }

    /**
     * Sets the statements to include in the assertion
     *
     * @param statements    The statements to include in the assertion
     * @exception   org.globus.opensaml11.saml.SAMLException
     *              Raised if unable to construct new statement objects
     */
    public void setStatements(Collection statements) throws SAMLException {
        this.statements.clear();
        setDirty(true);
        addStatements(statements);
    }

    /**
     * Adds a collection of statements to the assertion
     *
     * @param statements    The statements to add to the assertion
     * @exception   org.globus.opensaml11.saml.SAMLException
     *              Raised if unable to construct new statement objects
     */
    private void addStatements(Collection statements) throws SAMLException {
        if (statements != null) {
            for (Iterator i = statements.iterator(); i.hasNext(); ) {
                addStatement((SAMLSubjectStatement) i.next());
            }
        }
    }

    /**
     * Adds a statement to this <code>SAMLSubjectAssertion</code>.
     * If the statement is a <code>SubjectStatement</code>, and
     * the assertion already contains a statement (of any type),
     * this method does nothing.  If the statement is something
     * other than a <code>SubjectStatement</code>, this method
     * removes any <code>SubjectStatement</code> before adding
     * the statement.
     *
     * @param s     The statement to add
     *
     * @exception   org.globus.opensaml11.saml.SAMLException
     *              Raised if an error occurs while adding the statement
     */
    public void addStatement(SAMLStatement s) throws SAMLException {
        assert (!hasRedundantSubjectStatement());
        if (s != null) {
            if (s instanceof SubjectStatement) {
                if (this.statements.size() > 0) { return; }
            }
            this.removeSubjectStatements();
            this.statements.add(checkStatement(s).setParent(this));
            setDirty(true);
            assert (!hasRedundantSubjectStatement());
        } else {
            String msg = "Statement argument cannot be null";
            throw new IllegalArgumentException(msg);
        }
    }

    /**
     * Adds a <code>SubjectStatement</code> to this
     * <code>SAMLSubjectAssertion</code> instance.
     * If the assertion already contains a statement (of any
     * type), this method does nothing.
     *
     * @param subject     The subject of the statement to add
     *
     * @exception   org.globus.opensaml11.saml.SAMLException
     *              Raised if an error occurs while adding the statement
     */
    public void addSubjectStatement(SAMLSubject subject) throws SAMLException {
        if (this.statements.size() > 0) { return; }
        if (subject == null) {
            String msg = "Subject argument cannot be null";
            throw new IllegalArgumentException(msg);
        }
        this.addStatement(new SubjectStatement(subject));
    }

    /**
     * Removes all <code>SubjectStatement</code>s from this
     * <code>SAMLSubjectAssertion</code> instance (if any
     * exist).
     */
    public void removeSubjectStatements() {
        for (int i = 0; i < this.statements.size(); i++) {
            SAMLStatement statement = (SAMLStatement)this.statements.get(i);
            if (statement instanceof SubjectStatement) {
                this.statements.remove(i);
                removeSubjectStatements();  // recurse
            }
        }
    }

    /**
     * Determines if this <code>SAMLSubjectAssertion</code>
     * instance contains a redundant <code>SubjectStatement</code>.
     * A <code>SubjectStatement</code> is redundant if this
     * <code>SAMLSubjectAssertion</code> contains more than
     * one statement (of any type).
     *
     * @return true if and only if this <code>SAMLSubjectAssertion</code>
     *         instance contains a redundant <code>SubjectStatement</code>
     */
    protected boolean hasRedundantSubjectStatement() {
        if (this.statements.size() < 2) { return false; }
        Iterator statements = this.getStatements();
        while (statements.hasNext()) {
            SAMLStatement statement = (SAMLStatement)statements.next();
            if (statement instanceof SubjectStatement) {
                return true;
            }
        }
        return false;
    }

    /**
     * Determines if this <code>SAMLSubjectAssertion</code>
     * is empty, that is, if it either contains no statements
     * or only a single <code>SubjectStatement</code>.  Thus,
     * an empty assertion contains a SAML Subject but no
     * content.
     *
     * @return true if and only if this
     *         <code>SAMLSubjectAssertion</code> is empty
     */
    public boolean isEmpty() {
        assert (!hasRedundantSubjectStatement());
        if (this.statements.size() == 0) { return true; }
        if (this.statements.size() == 1) {
            SAMLStatement statement = (SAMLStatement)this.statements.get(1);
            if (statement instanceof SubjectStatement) {
                return true;
            }
        }
        return false;
    }

    /**
     * Since a SAMLSubjectAssertion is an extension of SAMLAssertion,
     * it must already have both an issuer and at least one statement.
     *
     * @see org.globus.opensaml11.saml.SAMLAssertion#checkValidity()
     */
    public void checkValidity() throws SAMLException {
        super.checkValidity();
        log.debug("Checking validity of SAMLSubjectAssertion...");
        // assume issuer is non-empty:
        if (this.issuer.length() > 1024) {
            log.warn("Issuer longer than 1024 chars");
        }
        try {
            new URI(this.issuer);
        } catch (URISyntaxException e) {
            log.warn("Issuer is not an URI");
        }
        checkStatements();
        // internal validity check:
        if (getSubject() == null) {
            String msg = "SAMLSubjectAssertion has no subject";
            log.error(msg);
            throw new MalformedException(msg);
        }
        SAMLNameIdentifier nameid = getSubject().getNameIdentifier();
        if (nameid == null) {
            String msg = "Subject must have NameIdentifier";
            log.error(msg);
            throw new MalformedException(msg);
        }
        String qualifier = nameid.getNameQualifier();
        if (!XML.isEmpty(qualifier)) {
            String msg = "NameQualifier should be omitted (";
            msg += qualifier + ")";
            log.warn(msg);
        }
        log.debug("SAMLSubjectAssertion is valid");
    }

    private void checkStatements() throws SAMLException {
        for (int i = 0; i < this.statements.size(); i++) {
            checkStatement((SAMLStatement)this.statements.get(i));
        }
    }

    /**
     * Checks the given statement.  In particular, checks the
     * Subject of the given statement against this Subject,
     * that is, the Subject of a representative statement
     * contained in this SAMLSubjectAssertion object (all of
     * which have Subjects that "very strongly match").
     * <p>
     * If the Subject of the given statement is null,
     * it is set to a cloned copy of this Subject.  Otherwise,
     * the two Subjects MUST very strongly match.
     * <p>
     * If the both Subjects are null, an exception is thrown.
     *
     * @param s The given statement (with or without a Subject)
     * @return A copy of the given statement with a Subject that
     *         very strongly matches this Subject
     * @exception org.globus.opensaml11.saml.SAMLException
     *            Thrown if both Subjects are null
     *            or if either can not be cloned
     */
    private SAMLSubjectStatement checkStatement(SAMLStatement statement)
                                         throws SAMLException {

        // check statement type:
        if (!(statement instanceof SAMLSubjectStatement)) {
            String msg = "Statement is wrong type";
            log.error(msg);
            throw new MalformedException(msg);
        }

        SAMLSubjectStatement s = (SAMLSubjectStatement) statement;
        if (s.getSubject() == null) {
            if (this.getSubject() == null) {
                String msg = "no subject available";
                throw new IllegalArgumentException(msg);
            } else {
                try {
                    s.setSubject((SAMLSubject) this.getSubject().clone());
                } catch (CloneNotSupportedException e) {
                    throw new SAMLException(e.getMessage());
                }
            }
        } else {
            if (this.getSubject() != null) {
                if (!veryStronglyMatches(this.getSubject(), s.getSubject())) {
                    String msg = "statement has non-matching subject";
                    throw new IllegalArgumentException(msg);
                }
            }
        }

        return s;

    }

    /**
     * Two subjects <strong>very strongly match</strong>
     * if each strongly matches the other.
     *
     * @return True if and only if the two subjects
     *         very strongly match
     */
    public static boolean veryStronglyMatches(SAMLSubject s1, SAMLSubject s2) {
        return s1.stronglyMatches(s2) && s2.stronglyMatches(s1);
    }

    /**
     * Copies a SAML object such that no dependencies exist between the original
     * and the copy
     *
     * @return      The new object
     * @see org.globus.opensaml11.saml.SAMLObject#clone()
     */
    public Object clone() throws CloneNotSupportedException {
        return (SAMLSubjectAssertion) super.clone();
    }

}
