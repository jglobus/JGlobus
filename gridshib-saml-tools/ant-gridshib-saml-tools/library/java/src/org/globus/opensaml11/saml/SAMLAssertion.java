/*
 *  Copyright 2001-2005 Internet2
 *  Copyright 2005-2009 University of Illinois
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.globus.opensaml11.saml;

import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.w3c.dom.*;

/**
 *  Represents a SAML Assertion
 *
 * @author     Scott Cantor (created March 18, 2002)
 * @author     Tom Scavo
 */
public class SAMLAssertion extends SAMLSignedObject implements Cloneable {

    private static Logger log =
        Logger.getLogger(SAMLAssertion.class.getName());

    protected int minor = config.getBooleanProperty("org.globus.opensaml11.saml.compatibility-mode") ? 0 : 1;
    protected String assertionId = null;
    protected String issuer = null;
    protected Date issueInstant = null;
    protected Date notBefore = null;
    protected Date notOnOrAfter = null;
    protected ArrayList conditions = new ArrayList();
    protected ArrayList advice = new ArrayList();
    protected ArrayList statements = new ArrayList();

    /**
     *  Places the signature into the object's DOM to prepare for signing<p>

     * @throws SAMLException    Thrown if an error occurs while placing the signature
     */
    protected void insertSignature() throws SAMLException {
        root.appendChild(getSignatureElement());
    }

    /**
     *  Default constructor
     */
    public SAMLAssertion() {
    }

    /**
     *  Builds an assertion out of its component parts
     *
     * @param  issuer             Name of SAML authority issuing assertion
     * @param  notBefore          Optional start of validity
     * @param  notOnOrAfter       Optional end of validity
     * @param  conditions         Set of conditions on validity
     * @param  advice             Optional advice content
     * @param  statements         Set of SAML statements to place in assertion
     * @exception  SAMLException  Raised if an assertion cannot be constructed
     *      from the supplied information
     */
    public SAMLAssertion(
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
     *  Builds an assertion out of its component parts
     * @param  assertionId        Unique identifier for assertion
     * @param  issueInstant       Time of issuance
     * @param  issuer             Name of SAML authority issuing assertion
     * @param  notBefore          Optional start of validity
     * @param  notOnOrAfter       Optional end of validity
     * @param  conditions         Set of conditions on validity
     * @param  advice             Optional advice content
     * @param  statements         Set of SAML statements to place in assertion
     * @exception  SAMLException  Raised if an assertion cannot be constructed
     *      from the supplied information
     */
    public SAMLAssertion(
            String assertionId,
            Date issueInstant,
            String issuer,
            Date notBefore,
            Date notOnOrAfter,
            Collection conditions,
            Collection advice,
            Collection statements
            ) throws SAMLException {

        // Copy pieces/parts to populate assertion.
        this.assertionId = XML.assign(assertionId);
        this.issueInstant = issueInstant;
        this.issuer = XML.assign(issuer);
        this.notBefore = notBefore;
        this.notOnOrAfter = notOnOrAfter;

        if (conditions != null) {
            for (Iterator i = conditions.iterator(); i.hasNext(); )
                this.conditions.add(((SAMLCondition)i.next()).setParent(this));
        }

        if (advice != null) {
            for (Iterator i = advice.iterator(); i.hasNext(); ) {
                Object obj=i.next();
                if (obj instanceof String && ((String)obj).length() > 0)
                    this.advice.add(obj);
                else if (obj instanceof SAMLAssertion)
                    this.advice.add(((SAMLAssertion)obj).setParent(this));
                else if (obj instanceof Element && ((Element)obj).getParentNode()==null &&
                            !((Element)obj).getNamespaceURI().equals(XML.SAML_NS))
                    this.advice.add(obj);
                else
                    throw new IllegalArgumentException("SAMLAssertion() can only process advice Strings, SAMLAssertions, or DOM elements from a non-saml namespace");
            }
        }

        if (statements != null) {
            for (Iterator i = statements.iterator(); i.hasNext(); )
                this.statements.add(((SAMLStatement)i.next()).setParent(this));
        }
    }

    /**
     *  Reconstructs an assertion from a DOM tree
     *
     * @param  e                  The root of a DOM tree
     * @exception  SAMLException  Thrown if the object cannot be constructed
     */
    public SAMLAssertion(Element e) throws SAMLException {
        fromDOM(e);
    }

    /**
     *  Reconstructs an assertion from a stream
     *
     * @param  in                   A stream containing XML
     * @exception  SAMLException  Raised if an exception occurs while constructing
     *                              the object.
     */
    public SAMLAssertion(InputStream in) throws SAMLException {
        fromDOM(fromStream(in));
    }

    /**
     *  Reconstructs an assertion of a particular minor version from a stream
     *
     * @param  in                   A stream containing XML
     * @param   minor               The minor version of the incoming assertion
     * @exception  SAMLException  Raised if an exception occurs while constructing
     *                              the object.
     */
    public SAMLAssertion(InputStream in, int minor) throws SAMLException {
        fromDOM(fromStream(in,minor));
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#fromDOM(org.w3c.dom.Element)
     */
    public void fromDOM(Element e) throws SAMLException {
        super.fromDOM(e);

        if (config.getBooleanProperty("org.globus.opensaml11.saml.strict-dom-checking") && !XML.isElementNamed(e,XML.SAML_NS,"Assertion"))
            throw new MalformedException(SAMLException.RESPONDER,"SAMLAssertion.fromDOM() requires saml:Assertion at root");

        if (Integer.parseInt(e.getAttributeNS(null, "MajorVersion")) != 1)
            throw new MalformedException(SAMLException.VERSION, "SAMLAssertion.fromDOM() detected incompatible assertion major version of " +
                e.getAttributeNS(null, "MajorVersion"));

        minor = Integer.parseInt(e.getAttributeNS(null, "MinorVersion"));
        issuer = XML.assign(e.getAttributeNS(null, "Issuer"));
        assertionId = XML.assign(e.getAttributeNS(null, "AssertionID"));
        if (minor>0)
            e.setIdAttributeNode(e.getAttributeNodeNS(null, "AssertionID"), true);

        try {
            SimpleDateFormat formatter = null;
            String dateTime = e.getAttributeNS(null, "IssueInstant");
            if (dateTime.indexOf('.') > 0) {
                formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
            }
            else {
                formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            }
            formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
            issueInstant = formatter.parse(dateTime);

            Element n = XML.getFirstChildElement(e);
            while (n != null) {
                // The top level children may be one of three different types.
                if (XML.isElementNamed(n, XML.SAML_NS, "Conditions")) {
                    // Check validity time attributes.
                    if (n.hasAttributeNS(null, "NotBefore"))
                        notBefore = formatter.parse(n.getAttributeNS(null, "NotBefore"));
                    if (n.hasAttributeNS(null, "NotOnOrAfter"))
                        notOnOrAfter = formatter.parse(n.getAttributeNS(null, "NotOnOrAfter"));

                    // Iterate over conditions.
                    Element cond = XML.getFirstChildElement(n);
                    while (cond != null) {
                        conditions.add(SAMLCondition.getInstance(cond).setParent(this));
                        cond = XML.getNextSiblingElement(cond);
                    }
                }
                else if (XML.isElementNamed(n, XML.SAML_NS, "Advice")) {
                    Element child = XML.getFirstChildElement(n);
                    while (child != null) {
                        if (XML.isElementNamed(child, XML.SAML_NS, "AssertionIDReference") && child.hasChildNodes()) {
                            advice.add(child.getFirstChild().getNodeValue());
                        }
                        else if (XML.isElementNamed(child, XML.SAML_NS, "Assertion")) {
                            advice.add(new SAMLAssertion(child).setParent(this));
                        }
                        else {
                            advice.add(child);
                        }
                        child = XML.getNextSiblingElement(child);
                    }
                }
                else if (!XML.isElementNamed(n, XML.XMLSIG_NS, "Signature"))
                    statements.add(SAMLStatement.getInstance(n).setParent(this));
                n = XML.getNextSiblingElement(n);
            }
        }
        catch (java.text.ParseException ex) {
            throw new MalformedException(SAMLException.RESPONDER, "SAMLAssertion.fromDOM() detected an invalid datetime while parsing assertion", ex);
        }
        checkValidity();
    }

    /**
     *  Gets the MinorVersion of the assertion.
     *
     * @return The minor version
     */
    public int getMinorVersion() {
        return minor;
    }

    /**
     *  Sets the MinorVersion of the assertion
     *
     * @param minor The minor version
     */
    public void setMinorVersion(int minor) {
        this.minor = minor;
        setDirty(true);
    }

    /**
     *  Gets the assertion ID from the assertion
     *
     * @return    The assertion ID
     */
    public String getId() {
        return assertionId;
    }

    /**
     *  Sets the assertion ID
     *
     *  <b>NOTE:</b> Use this method with caution. Assertions must contain unique identifiers
     *  and only specialized applications should need to explicitly assign an identifier.
     *
     * @param   id    The assertion ID
     */
    public void setId(String id) {
        if (XML.isEmpty(id))
            throw new IllegalArgumentException("id cannot be null");
        assertionId=id;
        setDirty(true);
    }

    /**
     *  Gets the issuer of the assertion
     *
     * @return    The issuer name
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     *  Sets the issuer name
     *
     * @param   issuer    The issuer name
     */
    public void setIssuer(String issuer) {
        if (XML.isEmpty(issuer))
            throw new IllegalArgumentException("issuer cannot be null");
        this.issuer = issuer;
        setDirty(true);
    }

    /**
     *  Gets the issue timestamp of the assertion
     *
     * @return    The issue timestamp
     */
    public Date getIssueInstant() {
        return issueInstant;
    }

    /**
     *  Sets the issue timestamp of the assertion
     *
     * @param   issueInstant    The issue timestamp
     */
    public void setIssueInstant(Date issueInstant) {
        if (issueInstant == null)
            throw new IllegalArgumentException("issueInstant cannot be null");
        this.issueInstant = issueInstant;
        setDirty(true);
    }

    /**
     *  Gets the start of the assertion's validity period
     *
     * @return    The starting validity date and time
     */
    public Date getNotBefore() {
        return notBefore;
    }

    /**
     *  Sets the start of the assertion's validity period
     *
     * @param   notBefore    The starting validity date and time
     */
    public void setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
        setDirty(true);
    }

    /**
     *  Gets the end of the assertion's validity period
     *
     * @return    The ending validity date and time
     */
    public Date getNotOnOrAfter() {
        return notOnOrAfter;
    }

    /**
     *  Sets the end of the assertion's validity period
     *
     * @param   notOnOrAfter    The ending validity date and time
     */
    public void setNotOnOrAfter(Date notOnOrAfter) {
        this.notOnOrAfter = notOnOrAfter;
        setDirty(true);
    }

    /**
     *  Gets the conditions included in the assertion
     *
     * @return    An iterator of SAML conditions
     */
    public Iterator getConditions() {
        return conditions.iterator();
    }

    /**
     *  Sets the conditions included in the assertion
     *
     * @param conditions    The conditions to include in the assertion
     * @throws SAMLException    Raised if any of the conditions are invalid
     */
    public void setConditions(Collection conditions) throws SAMLException {
        this.conditions.clear();
        if (conditions != null) {
            for (Iterator i = conditions.iterator(); i.hasNext(); )
                this.conditions.add(((SAMLCondition)i.next()).setParent(this));
        }
        setDirty(true);
    }

    /**
     *  Adds a condition to the assertion
     *
     * @param c     The condition to add
     * @exception   SAMLException   Raised if an error occurs while adding the condition
     */
    public void addCondition(SAMLCondition c) throws SAMLException {
        if (c != null) {
            conditions.add(c.setParent(this));
            setDirty(true);
        }
        else
            throw new IllegalArgumentException("c cannot be null");
    }

    /**
     *  Removes a condition by position (zero-based)
     *
     * @param   index   The position of the condition to remove
     */
    public void removeCondition(int index) throws IndexOutOfBoundsException {
        conditions.remove(index);
        setDirty(true);
    }

    /**
     *  Gets the optional Advice data included in the assertion
     *
     *  Advice can be Strings (assertion references), Assertions, or DOM Elements.
     *
     * @return    An iterator over the advice
     */
    public Iterator getAdvice() {
        return advice.iterator();
    }

    /**
     *  Sets the optional Advice data to include in the assertion
     *
     * @param advice    The Advice to include in the assertion
     * @exception   SAMLException   Raised if unable to construct new Advice objects
     */
    public void setAdvice(Collection advice) throws SAMLException {
        this.advice.clear();
        setDirty(true);
        if (advice != null) {
            for (Iterator i = advice.iterator(); i.hasNext(); )
                addAdvice(i.next());
        }
    }

    /**
     *  Adds an advice element
     *
     * @param   advice    a String, SAMLAssertion, or DOM Element
     * @exception SAMLException     Raised if object is invalid
     */
    public void addAdvice(Object advice) throws SAMLException {
        if (advice != null && (advice instanceof String || advice instanceof SAMLAssertion ||
                (advice instanceof Element && !((Element)advice).getNamespaceURI().equals(XML.SAML_NS)))) {
            if (advice instanceof SAMLAssertion)
                ((SAMLAssertion)advice).setParent(this);
            this.advice.add(advice);
            setDirty(true);
        }
        else
            throw new IllegalArgumentException("SAMLAssertion.addAdvice() can only process Strings, SAMLAssertions, or DOM elements from a non-saml namespace");
    }

    /**
     *  Removes an advice element by position (zero-based)
     *
     * @param   index   The position of the element to remove
     */
    public void removeAdvice(int index) throws IndexOutOfBoundsException {
        advice.remove(index);
        setDirty(true);
    }

    /**
     *  Gets the statements included in the assertion
     *
     * @return    An iterator of SAML statements
     */
    public Iterator getStatements() {
        return statements.iterator();
    }

    /**
     *  Sets the statements to include in the assertion
     *
     * @param statements    The statements to include in the assertion
     * @exception   SAMLException   Raised if unable to construct new statement objects
     */
    public void setStatements(Collection statements) throws SAMLException {
        this.statements.clear();
        setDirty(true);
        if (statements != null) {
            for (Iterator i = statements.iterator(); i.hasNext(); )
                this.statements.add(((SAMLStatement)i.next()).setParent(this));
        }
    }

    /**
     *  Adds a statement to the assertion
     *
     * @param s     The statement to add
     * @exception   SAMLException   Raised if an error occurs while adding the statement
     */
    public void addStatement(SAMLStatement s) throws SAMLException {
        if (s != null) {
            statements.add(s.setParent(this));
            setDirty(true);
        }
        else
            throw new IllegalArgumentException("s cannot be null");
    }

    /**
     *  Removes a statement by position (zero-based)
     *
     * @param   index   The position of the statement to remove
     */
    public void removeStatement(int index) throws IndexOutOfBoundsException {
        statements.remove(index);
        setDirty(true);
    }

    /**
     *  @see org.globus.opensaml11.saml.SAMLObject#buildRoot(org.w3c.dom.Document,boolean)
     */
    protected Element buildRoot(Document doc, boolean xmlns) {
        Element a = doc.createElementNS(XML.SAML_NS, "Assertion");
        a.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
        a.setAttributeNS(XML.XMLNS_NS, "xmlns:saml", XML.SAML_NS);
        a.setAttributeNS(XML.XMLNS_NS, "xmlns:samlp", XML.SAMLP_NS);
        if (xmlns) {
            a.setAttributeNS(XML.XMLNS_NS, "xmlns:xsd", XML.XSD_NS);
            a.setAttributeNS(XML.XMLNS_NS, "xmlns:xsi", XML.XSI_NS);
        }
        return a;
    }

    /**
     *  @see org.globus.opensaml11.saml.SAMLObject#toDOM(org.w3c.dom.Document,boolean)
     */
    public Node toDOM(Document doc, boolean xmlns) throws SAMLException {
        // Let the base build/verify the DOM root.
        super.toDOM(doc, xmlns);
        Element assertion = (Element)root;

        if (dirty) {
            if (assertionId == null)
                assertionId = config.getDefaultIDProvider().getIdentifier();

            if (issueInstant == null)
                issueInstant = new Date();

            assertion.setAttributeNS(null, "MajorVersion", "1");
            assertion.setAttributeNS(null, "MinorVersion", String.valueOf(minor));
            assertion.setAttributeNS(null, "AssertionID", assertionId);
            if (minor>0)
                assertion.setIdAttributeNS(null, "AssertionID", true);
            assertion.setAttributeNS(null, "Issuer", issuer);

            SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
            formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
            assertion.setAttributeNS(null, "IssueInstant", formatter.format(issueInstant));

            if (conditions.size() > 0 || notBefore != null || notOnOrAfter != null) {
                Element conds = doc.createElementNS(XML.SAML_NS, "Conditions");
                if (notBefore != null)
                    conds.setAttributeNS(null, "NotBefore", formatter.format(notBefore));
                if (notOnOrAfter != null)
                    conds.setAttributeNS(null, "NotOnOrAfter", formatter.format(notOnOrAfter));
                assertion.appendChild(conds);

                for (Iterator i = conditions.iterator(); i.hasNext(); )
                    conds.appendChild(((SAMLCondition)i.next()).toDOM(doc, false));
            }

            if (advice.size() > 0) {
                Element a = doc.createElementNS(XML.SAML_NS, "Advice");
                Iterator i = advice.iterator();
                while (i.hasNext()) {
                    Object obj = i.next();
                    if (obj instanceof String && !XML.isEmpty((String)obj)) {
                        Element ref = doc.createElementNS(XML.SAML_NS, "AssertionIDReference");
                        ref.appendChild(doc.createTextNode((String)obj));
                        a.appendChild(ref);
                    }
                    else if (obj instanceof SAMLAssertion) {
                        a.appendChild(((SAMLAssertion)obj).toDOM(doc, false));
                    }
                    else if (obj instanceof Element) {
                        a.appendChild(doc.adoptNode((Element)obj));
                    }
                }
                assertion.appendChild(a);
            }

            for (Iterator i = statements.iterator(); i.hasNext(); )
                assertion.appendChild(((SAMLStatement)i.next()).toDOM(doc, false));

            setDirty(false);
        }
        else if (xmlns) {
            assertion.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
            assertion.setAttributeNS(XML.XMLNS_NS, "xmlns:saml", XML.SAML_NS);
            assertion.setAttributeNS(XML.XMLNS_NS, "xmlns:samlp", XML.SAMLP_NS);
            assertion.setAttributeNS(XML.XMLNS_NS, "xmlns:xsd", XML.XSD_NS);
            assertion.setAttributeNS(XML.XMLNS_NS, "xmlns:xsi", XML.XSI_NS);
        }
        return root;
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#checkValidity()
     */
    public void checkValidity() throws SAMLException {
        if (XML.isEmpty(this.issuer)) {
            String msg = "Assertion must have issuer";
            log.error(msg);
            throw new MalformedException(msg);
        }
        log.info("Issuer is " + this.issuer);
        if (statements.size() == 0) {
            String msg = "Assertion has no statements";
            log.error(msg);
            throw new MalformedException(msg);
        }
    }

    /**
     *  Copies a SAML object such that no dependencies exist between the original
     *  and the copy
     *
     * @return      The new object
     * @see Object#clone()
     */
    public Object clone() throws CloneNotSupportedException {
        SAMLAssertion dup=(SAMLAssertion)super.clone();

        // Clone the embedded objects.
        try {
            dup.conditions = new ArrayList();
            for (Iterator i = conditions.iterator(); i.hasNext(); )
                dup.conditions.add(((SAMLCondition)((SAMLCondition)i.next()).clone()).setParent(dup));

            dup.advice = new ArrayList();
            for (Iterator i = advice.iterator(); i.hasNext(); ) {
                Object obj=i.next();
                if (obj instanceof String)
                    dup.advice.add(obj);
                else if (obj instanceof SAMLAssertion)
                    dup.advice.add(((SAMLAssertion)((SAMLAssertion)i.next()).clone()).setParent(dup));
                else
                    dup.advice.add(((Element)obj).cloneNode(true));
            }

            dup.statements = new ArrayList();
            for (Iterator i = statements.iterator(); i.hasNext(); )
                dup.statements.add(((SAMLStatement)((SAMLStatement)i.next()).clone()).setParent(dup));
        }
        catch (SAMLException e) {
            throw new CloneNotSupportedException(e.getMessage());
        }
        return dup;
    }
}
