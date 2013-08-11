/*
 *  Copyright 2001-2005 Internet2
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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.TimeZone;

import org.w3c.dom.*;

/**
 *  Represents a SAML protocol response
 *
 * @author     Scott Cantor (created March 18, 2002)
 */
public class SAMLResponse extends SAMLSignedObject
{
    protected int minor = config.getBooleanProperty("org.globus.opensaml11.saml.compatibility-mode") ? 0 : 1;
    protected String responseId = null;
    protected String inResponseTo = null;
    protected Date issueInstant = new Date();
    protected String recipient = null;
    protected ArrayList assertions = new ArrayList();
    protected SAMLException e = null;

    /**
     *  Places the signature into the object's DOM to prepare for signing<p>

     * @throws org.globus.opensaml11.saml.SAMLException    Thrown if an error occurs while placing the signature
     */
    protected void insertSignature() throws SAMLException {
        root.insertBefore(getSignatureElement(),root.getFirstChild());
    }

    /**
     *  Default constructor
     */
    public SAMLResponse() {
    }

    /**
     *  Builds a SAML response out of its component parts<P>
     *
     * @param  inResponseTo       The request ID that prompted the response, if any
     * @param  recipient          The URL of the intended recipient of the response
     * @param  assertions         The SAML assertion(s) to return in the response, if any
     * @param  e                  The SAML error status information to return in the response, if any
     * @exception  org.globus.opensaml11.saml.SAMLException  Raised if a response cannot be constructed
     *      from the supplied information
     */
    public SAMLResponse(String inResponseTo, String recipient, Collection assertions, SAMLException e) throws SAMLException {
        this(SAMLConfig.instance().getDefaultIDProvider().getIdentifier(),new Date(),inResponseTo,recipient,assertions,e);
    }
    /**
     *  Builds a SAML response out of its component parts<P>
     *
     * @param  responseId        Unique identifier for response
     * @param  issueInstant       Time of issuance
     * @param  inResponseTo       The request ID that prompted the response, if any
     * @param  recipient          The URL of the intended recipient of the response
     * @param  assertions         The SAML assertion(s) to return in the response, if any
     * @param  e                  The SAML error status information to return in the response, if any
     * @exception  org.globus.opensaml11.saml.SAMLException  Raised if a response cannot be constructed
     *      from the supplied information
     */
    public SAMLResponse(
            String responseId,
            Date issueInstant,
            String inResponseTo,
            String recipient,
            Collection assertions,
            SAMLException e
            ) throws SAMLException {
        this.responseId = XML.assign(responseId);
        this.issueInstant = issueInstant;
        this.inResponseTo = XML.assign(inResponseTo);
        this.recipient = XML.assign(recipient);
        if (e != null)
            this.e = e.setParent(this);

        if (assertions != null) {
            for (Iterator i = assertions.iterator(); i.hasNext(); )
                this.assertions.add(((SAMLAssertion)i.next()).setParent(this));
        }
    }

    /**
     *  Reconstructs a response from a DOM tree
     *
     * @param  e                  The root of a DOM tree
     * @exception  org.globus.opensaml11.saml.SAMLException  Thrown if the object cannot be constructed
     */
    public SAMLResponse(Element e) throws SAMLException {
        fromDOM(e);
    }

    /**
     *  Reconstructs a response from a stream
     *
     * @param  in                   A stream containing XML
     * @exception  org.globus.opensaml11.saml.SAMLException  Raised if an exception occurs while constructing
     *                              the object.
     */
    public SAMLResponse(InputStream in) throws SAMLException {
        fromDOM(fromStream(in));
    }

    /**
     *  Reconstructs a response of a particular minor version from a stream
     *
     * @param  in                   A stream containing XML
     * @param   minor               The minor version of the incoming response
     * @exception  org.globus.opensaml11.saml.SAMLException  Raised if an exception occurs while constructing
     *                              the object.
     */
    public SAMLResponse(InputStream in, int minor) throws SAMLException {
        fromDOM(fromStream(in,minor));
    }

    /**
     * @see SAMLObject#fromDOM(org.w3c.dom.Element)
     */
    public void fromDOM(Element e) throws SAMLException {
        super.fromDOM(e);

        if (config.getBooleanProperty("org.globus.opensaml11.saml.strict-dom-checking") && !XML.isElementNamed(e,XML.SAMLP_NS,"Response"))
            throw new MalformedException(SAMLException.RESPONDER,"SAMLResponse.fromDOM() requires samlp:Response at root");

        if (Integer.parseInt(e.getAttributeNS(null, "MajorVersion")) != 1)
            throw new MalformedException(SAMLException.VERSION,
                "SAMLResponse() detected incompatible response major version of " + e.getAttributeNS(null, "MajorVersion"));

        minor = Integer.parseInt(e.getAttributeNS(null, "MinorVersion"));
        responseId = XML.assign(e.getAttributeNS(null, "ResponseID"));
        if (minor>0)
            e.setIdAttributeNode(e.getAttributeNodeNS(null, "ResponseID"), true);
        inResponseTo = XML.assign(e.getAttributeNS(null, "InResponseTo"));
        recipient = XML.assign(e.getAttributeNS(null, "Recipient"));

        try {
            SimpleDateFormat formatter = null;
            String dateTime = XML.assign(e.getAttributeNS(null, "IssueInstant"));
            int dot = dateTime.indexOf('.');
            if (dot > 0) {
                formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
            }
            else {
                formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            }
            formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
            issueInstant = formatter.parse(dateTime);
        }
        catch (java.text.ParseException ex) {
            throw new MalformedException(SAMLException.RESPONDER, "SAMLResponse() detected an invalid datetime while parsing response", ex);
        }

        Element n = XML.getFirstChildElement(e, XML.SAMLP_NS, "Status");

        // Process status, and toss out any errors.
        this.e = SAMLException.getInstance(n);
        Iterator it=this.e.getCodes();
        if (it.hasNext())
            if (!it.next().equals(SAMLException.SUCCESS))
                throw this.e;

        n = XML.getNextSiblingElement(n, XML.SAML_NS, "Assertion");
        while (n != null) {
            assertions.add(new SAMLAssertion(n).setParent(this));
            n = XML.getNextSiblingElement(n, XML.SAML_NS, "Assertion");
        }

        checkValidity();
    }

    /**
     *  Gets the MinorVersion of the response.
     *
     * @return The minor version
     */
    public int getMinorVersion() {
        return minor;
    }

    /**
     *  Sets the MinorVersion of the response
     *
     * @param minor The minor version
     */
    public void setMinorVersion(int minor) {
        this.minor = minor;
        setDirty(true);
    }

    /**
     *  Gets the response ID
     *
     * @return    The response ID
     */
    public String getId() {
        return responseId;
    }

    /**
     *  Sets the response ID
     *
     *  <b>NOTE:</b> Use this method with caution. Responses must contain unique identifiers
     *  and only specialized applications should need to explicitly assign an identifier.
     *
     * @param   id    The response ID
     */
    public void setId(String id) {
        if (XML.isEmpty(id))
            throw new IllegalArgumentException("id cannot be null");
        responseId = XML.assign(id);
        setDirty(true);
    }

    /**
     *  Gets the InResponseTo attribute
     *
     * @return    The InResponseTo value
     */
    public String getInResponseTo() {
        return inResponseTo;
    }

    /**
     *  Sets the InResponseTo attribute
     *
     * @param   inResponseTo    The InResponseTo value
     */
    public void setInResponseTo(String inResponseTo) {
        this.inResponseTo = XML.assign(inResponseTo);
        setDirty(true);
    }

    /**
     *  Gets the issue timestamp of the SAML response
     *
     * @return    The issue timestamp
     */
    public Date getIssueInstant() {
        return issueInstant;
    }

    /**
     *  Sets the issue timestamp of the response
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
     *  Gets the Recipient attribute of the SAML response
     *
     * @return    The Recipient value
     */
    public String getRecipient() {
        return recipient;
    }

    /**
     *  Sets the Recipient attribute
     *
     * @param   recipient    The Recipient value
     */
    public void setRecipient(String recipient) {
        this.recipient = XML.assign(recipient);
        setDirty(true);
    }

    /**
     *  Gets the SAML assertions contained in the response, if any
     *
     * @return    The assertions in the response
     */
    public Iterator getAssertions() {
        return assertions.iterator();
    }

    /**
     *  Sets the SAML assertions to include in the response
     *
     * @param assertions   The assertions to include
     * @exception org.globus.opensaml11.saml.SAMLException     Raised if the assertions are invalid
     */
    public void setAssertions(Collection assertions) throws SAMLException {
        this.assertions.clear();
        if (assertions != null) {
            for (Iterator i = assertions.iterator(); i.hasNext(); )
                this.assertions.add(((SAMLAssertion)i.next()).setParent(this));
        }
        setDirty(true);
    }

    /**
     *  Adds an assertion to the response
     *
     * @param   assertion   The assertion to add
     * @exception   org.globus.opensaml11.saml.SAMLException   Raised if the assertion is invalid
     */
    public void addAssertion(SAMLAssertion assertion) throws SAMLException {
        if (assertion != null) {
            assertions.add(assertion.setParent(this));
            setDirty(true);
        }
        else
            throw new IllegalArgumentException("assertion cannot be null");
    }

    /**
     *  Removes assertion by position (zero-based)
     *
     * @param   index   The position of the assertion to remove
     */
    public void removeAssertion(int index) throws IndexOutOfBoundsException {
        assertions.remove(index);
        setDirty(true);
    }

    /**
     *  Gets the SAML Status contained in the response, if any (a SAMLException object is
     *  used to express the information, even in a successful case)
     *
     * @return    The status information in the response
     */
    public SAMLException getStatus() {
        return e;
    }

    /**
     *  Sets the SAML status to include in the response
     *
     * @param e   The status to include
     * @exception org.globus.opensaml11.saml.SAMLException     Raised if the status cannot be set or is invalid
     */
    public void setStatus(SAMLException e) throws SAMLException {
        this.e = e.setParent(this);
        setDirty(true);
    }

    /**
     *  @see SAMLObject#buildRoot(org.w3c.dom.Document,boolean)
     */
    protected Element buildRoot(Document doc, boolean xmlns) {
        Element r = doc.createElementNS(XML.SAMLP_NS, "Response");
        if (xmlns) {
            r.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAMLP_NS);
            r.setAttributeNS(XML.XMLNS_NS, "xmlns:saml", XML.SAML_NS);
            r.setAttributeNS(XML.XMLNS_NS, "xmlns:samlp", XML.SAMLP_NS);
            r.setAttributeNS(XML.XMLNS_NS, "xmlns:xsi", XML.XSI_NS);
            r.setAttributeNS(XML.XMLNS_NS, "xmlns:xsd", XML.XSD_NS);
        }
        return r;
    }

    /**
     *  @see SAMLObject#toDOM(org.w3c.dom.Document,boolean)
     */
    public Node toDOM(Document doc, boolean xmlns) throws SAMLException {
        // Let the base build/verify the DOM root.
        super.toDOM(doc, xmlns);
        Element r = (Element)root;

        if (dirty) {
            if (responseId == null)
                responseId = config.getDefaultIDProvider().getIdentifier();

            if (issueInstant == null)
                issueInstant = new Date();

            r.setAttributeNS(null, "MajorVersion", "1");
            r.setAttributeNS(null, "MinorVersion", String.valueOf(minor));
            r.setAttributeNS(null, "ResponseID", responseId);
            if (minor > 0)
                r.setIdAttributeNS(null, "ResponseID", true);
            if (!XML.isEmpty(inResponseTo))
                r.setAttributeNS(null, "InResponseTo", inResponseTo);
            if (!XML.isEmpty(recipient))
                r.setAttributeNS(null, "Recipient", recipient);

            SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
            formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
            r.setAttributeNS(null, "IssueInstant", formatter.format(issueInstant));

            // Fill in a status.
            if (e!=null)
                r.appendChild(e.toDOM(doc, false));
            else {
                Element status = doc.createElementNS(XML.SAMLP_NS, "Status");
                Element code = doc.createElementNS(XML.SAMLP_NS, "StatusCode");
                code.setAttributeNS(null, "Value", "samlp:" + SAMLException.SUCCESS.getLocalPart());
                status.appendChild(code);
                r.appendChild(status);
            }

            // Embed the assertions.
            Iterator i = assertions.iterator();
            while (i.hasNext())
                r.appendChild(((SAMLAssertion)i.next()).toDOM(doc));

            setDirty(false);
        }
        else if (xmlns) {
            r.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAMLP_NS);
            r.setAttributeNS(XML.XMLNS_NS, "xmlns:saml", XML.SAML_NS);
            r.setAttributeNS(XML.XMLNS_NS, "xmlns:samlp", XML.SAMLP_NS);
            r.setAttributeNS(XML.XMLNS_NS, "xmlns:xsi", XML.XSI_NS);
            r.setAttributeNS(XML.XMLNS_NS, "xmlns:xsd", XML.XSD_NS);
        }
        return root;
    }

    /**
     * @see SAMLObject#checkValidity()
     */
    public void checkValidity() throws SAMLException {
        if (responseId == null)
            throw new MalformedException("Response is invalid, must have an ID");
    }

    /**
     *  Copies a SAML object such that no dependencies exist between the original
     *  and the copy
     *
     * @return      The new object
     * @see Object#clone()
     */
    public Object clone() throws CloneNotSupportedException {
        SAMLResponse dup=(SAMLResponse)super.clone();

        // Clone the embedded objects.
        try {
            if (e != null)
                dup.e = (SAMLException)((SAMLException)e.clone()).setParent(dup);
            dup.assertions = new ArrayList();
            for (Iterator i = assertions.iterator(); i.hasNext(); )
                dup.assertions.add(((SAMLAssertion)((SAMLAssertion)i.next()).clone()).setParent(dup));
        }
        catch (SAMLException e) {
            throw new CloneNotSupportedException(e.getMessage());
        }

        return dup;
    }
}

