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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.w3c.dom.*;

/**
 * Represents a SAML Subject
 *
 * @author     Scott Cantor (created March 25, 2002)
 * @author     Tom Scavo
 */
public class SAMLSubject extends SAMLObject implements Cloneable {

    protected SAMLNameIdentifier nameId = null;
    protected ArrayList confirmationMethods = new ArrayList();
    protected Element confirmationData = null;
    protected KeyInfo keyInfo = null;

    /**  Artifact Confirmation Method Identifier */
    public final static String CONF_ARTIFACT =
        "urn:oasis:names:tc:SAML:1.0:cm:artifact";

    /**
     * Artifact Confirmation Method Identifier
     * @deprecated
     */
    public final static String CONF_ARTIFACT01 =
        "urn:oasis:names:tc:SAML:1.0:cm:artifact-01";

    /**  Bearer Confirmation Method Identifier */
    public final static String CONF_BEARER =
        "urn:oasis:names:tc:SAML:1.0:cm:bearer";

    /**  Holder of Key Confirmation Method Identifier */
    public final static String CONF_HOLDER_KEY =
        "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key";

    /**  Sender Vouches Confirmation Method Identifier */
    public final static String CONF_SENDER_VOUCHES =
        "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches";

    /**
     *  Default constructor
     */
    public SAMLSubject() {
    }

    /**
     *  Builds a subject out of its component parts
     *
     * @param  nameId       Name of subject (optional)
     * @param  confirmationMethods  Confirmation method(s) that bind the subject
     *      to an enclosing assertion (optional)
     * @param  confirmationData     Arbitrary confirmation data DOM (optional)
     * @param  keyInfo              A ds:KeyInfo, either from an xmlsig library or a DOM element (optional)
     * @exception  org.globus.opensaml11.saml.SAMLException    Raised if a subject cannot be constructed
     *      from the supplied information
     */
    public SAMLSubject(SAMLNameIdentifier nameId, Collection confirmationMethods, Element confirmationData, Object keyInfo)
        throws SAMLException {

        if (nameId != null)
            this.nameId = (SAMLNameIdentifier)nameId.setParent(this);
        if (confirmationData != null && (!XML.isElementNamed(confirmationData, XML.SAML_NS, "SubjectConfirmationData")))
            throw new IllegalArgumentException("confirmationData must be a saml:SubjectConfirmationData element");
        else
            this.confirmationData = confirmationData;

        if (confirmationMethods != null)
            this.confirmationMethods.addAll(confirmationMethods);

        if (keyInfo != null) {
            try {
                if (keyInfo instanceof KeyInfo && ((KeyInfo)keyInfo).getElement().getParentNode() == null)
                    this.keyInfo = (KeyInfo)keyInfo;
                else if (keyInfo instanceof Element && ((Element)keyInfo).getParentNode() == null)
                    this.keyInfo = new KeyInfo((Element)keyInfo, null);
                else
                    throw new IllegalArgumentException("SAMLSubject() unable to process the provided keyInfo object/element");
            }
            catch (XMLSecurityException e) {
                throw new MalformedException("SAMLSubject() caught an XML security exception", e);
            }
        }
    }

    /**
     *  Reconstructs a subject from a DOM tree
     *
     * @param  e                  The root of a DOM tree
     * @exception  org.globus.opensaml11.saml.SAMLException  Thrown if the object cannot be constructed
     */
    public SAMLSubject(Element e) throws SAMLException {
        fromDOM(e);
    }

    /**
     *  Reconstructs a subject from a stream
     *
     * @param  in                   A stream containing XML
     * @exception  org.globus.opensaml11.saml.SAMLException  Raised if an exception occurs while constructing
     *                              the object.
     */
    public SAMLSubject(InputStream in) throws SAMLException {
        fromDOM(fromStream(in));
    }

    /**
     * @see SAMLObject#fromDOM(org.w3c.dom.Element)
     */
    public void fromDOM(Element e) throws SAMLException {
        super.fromDOM(e);

        if (config.getBooleanProperty("org.globus.opensaml11.saml.strict-dom-checking") && !XML.isElementNamed(e,XML.SAML_NS,"Subject"))
            throw new MalformedException("SAMLSubject.fromDOM() requires saml:Subject at root");

        // Look for NameIdentifier.
        Element n = XML.getFirstChildElement(e, XML.SAML_NS, "NameIdentifier");
        if (n != null) {
            nameId = (SAMLNameIdentifier)SAMLNameIdentifier.getInstance(n).setParent(this);
            //n = XML.getNextSiblingElement(n);
        }

        // Look for SubjectConfirmation.
        n = XML.getFirstChildElement(e, XML.SAML_NS, "SubjectConfirmation");
        if (n != null) {
            // Iterate over ConfirmationMethods.
            Element n2 = XML.getFirstChildElement(n);
            while (n2 != null && XML.isElementNamed(n2, XML.SAML_NS, "ConfirmationMethod") && n2.hasChildNodes()) {
                confirmationMethods.add(n2.getFirstChild().getNodeValue());
                n2 = XML.getNextSiblingElement(n2);
            }

            // Extract optional SubjectConfirmationData.
            if (n2 != null && XML.isElementNamed(n2, XML.SAML_NS, "SubjectConfirmationData")) {
                confirmationData = n2;
                n2 = XML.getNextSiblingElement(n2);
            }

            // Extract optional ds:KeyInfo.
            if (n2 != null && XML.isElementNamed(n2, XML.XMLSIG_NS, "KeyInfo")) {
                try {
                    keyInfo = new KeyInfo(n2, null);
                }
                catch (XMLSecurityException ex) {
                    throw new MalformedException("SAMLSubject.fromDOM() caught an XML security exception", ex);
                }
            }
        }

        checkValidity();
    }

    /**
     *  Gets the name identifier of the Subject
     *
     * @return    The name identifier
     */
    public SAMLNameIdentifier getNameIdentifier() {
        return nameId;
    }

    /**
     *  Sets the name identifier of the Subject
     *
     * @param   nameId    The name identifier
     * @exception org.globus.opensaml11.saml.SAMLException     Raised if the object is invalid
     */
    public void setNameIdentifier(SAMLNameIdentifier nameId) throws SAMLException {
        if (nameId != null)
            this.nameId = (SAMLNameIdentifier)nameId.setParent(this);
        else
            this.nameId = null;
        setDirty(true);
    }

    /**
     *  Gets the confirmation methods of the Subject
     *
     * @return    An iterator of Subject confirmation method URIs
     */
    public Iterator getConfirmationMethods() {
        return confirmationMethods.iterator();
    }

    /**
     *  Sets the confirmation methods of the Subject
     *
     * @param   confirmationMethods     The confirmation methods
     */
    public void setConfirmationMethods(Collection confirmationMethods) {
        this.confirmationMethods.clear();
        if (confirmationMethods != null) {
            for (Iterator i = confirmationMethods.iterator(); i.hasNext(); )
                addConfirmationMethod((String)i.next());
        }
        setDirty(true);
    }

    /**
     *  Adds a confirmation method to the Subject
     *
     * @param   confirmationMethod  The method URI to add
     */
    public void addConfirmationMethod(String confirmationMethod) {
        if (!XML.isEmpty(confirmationMethod)) {
            confirmationMethods.add(confirmationMethod);
            setDirty(true);
        }
        else
            throw new IllegalArgumentException("confirmationMethod cannot be null or empty");
    }

    /**
     *  Removes a confirmation method by position (zero-based)
     *
     * @param   index   The position of the method to remove
     */
    public void removeConfirmationMethod(int index) throws IndexOutOfBoundsException {
        confirmationMethods.remove(index);
        setDirty(true);
    }

    /**
     *  Gets the optional confirmation data of the Subject
     *
     * @return    The saml:SubjectConfirmationData element
     */
    public Element getConfirmationData() {
        return confirmationData;
    }

    /**
     *  Sets the optional confirmation data of the Subject
     *
     * @param   confirmationData    The saml:SubjectConfirmationData element
     */
    public void setConfirmationData(Element confirmationData) {
        if (confirmationData != null && (!XML.isElementNamed(confirmationData, XML.SAML_NS, "SubjectConfirmationData")))
            throw new IllegalArgumentException("confirmationData must be a saml:SubjectConfirmationData element");
        this.confirmationData = confirmationData;
        setDirty(true);
    }

    /**
     *  Gets the ds:KeyInfo DOM that is included in the subject, if any
     *
     * @return  Root of the ds:KeyInfo DOM
     */
    public Element getKeyInfo() {
        return (keyInfo != null) ? keyInfo.getElement() : null;
    }

    /**
     *  Gets the native library object for the ds:KeyInfo that is included in the subject, if any
     *
     * @return  The native library object containing the ds:KeyInfo
     */
    public Object getNativeKeyInfo() {
        return keyInfo;
    }

    /**
     *  Sets the ds:KeyInfo of the Subject
     *
     * @param   keyInfo    The ds:KeyInfo DOM or native library object
     * @exception   org.globus.opensaml11.saml.SAMLException   Raised if the object is invalid
     */
    public void setKeyInfo(Object keyInfo) throws SAMLException {
        if (keyInfo != null && !(keyInfo instanceof KeyInfo || keyInfo instanceof Element))
            throw new IllegalArgumentException("keyInfo must be a ds:KeyInfo element or a native library object");

        //Try and build a native object.
        KeyInfo nativeki = null;
        try {
            if (keyInfo instanceof Element)
                nativeki = new KeyInfo((Element)keyInfo, null);
            else
                nativeki = (KeyInfo)keyInfo;
        }
        catch (XMLSecurityException ex) {
            throw new SAMLException("setKeyInfo() caught an XML security exception", ex);
        }

        this.keyInfo = nativeki;
        setDirty(true);
    }

    /**
     *  @see SAMLObject#buildRoot(org.w3c.dom.Document,boolean)
     */
    protected Element buildRoot(Document doc, boolean xmlns) {
        Element s = doc.createElementNS(XML.SAML_NS, "Subject");
        if (xmlns)
            s.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
        return s;
    }

    /**
     *  @see SAMLObject#toDOM(org.w3c.dom.Document,boolean)
     */
    public Node toDOM(Document doc, boolean xmlns) throws SAMLException {
        // Let the base build/verify the DOM root.
        super.toDOM(doc, xmlns);
        Element s = (Element)root;

        if (dirty) {
            if (nameId != null)
                s.appendChild(nameId.toDOM(doc, false));

            if (confirmationMethods.size() > 0) {
                Element conf = doc.createElementNS(XML.SAML_NS, "SubjectConfirmation");
                Iterator i=confirmationMethods.iterator();
                while (i.hasNext())
                    conf.appendChild(doc.createElementNS(XML.SAML_NS, "ConfirmationMethod")).appendChild(doc.createTextNode((String)i.next()));
                if (confirmationData != null) {
                    if (confirmationData.getOwnerDocument() == doc)
                        conf.appendChild(confirmationData);
                    else
                        conf.appendChild(doc.adoptNode(confirmationData));
                }
                if (keyInfo != null) {
                    if (keyInfo.getElement().getOwnerDocument() == doc)
                        conf.appendChild(keyInfo.getElement());
                    else
                        conf.appendChild(doc.adoptNode(keyInfo.getElement()));
                }
                s.appendChild(conf);
            }

            setDirty(false);
        }
        else if (xmlns) {
            s.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
        }

        return root;
    }

    /**
     * @see SAMLObject#checkValidity()
     */
    public void checkValidity() throws SAMLException {
        if (nameId == null &&
            (confirmationMethods == null || confirmationMethods.size() == 0)) {
            String msg = "Subject is invalid: ";
            msg += "NameIdentifier and/or SubjectConfirmation with ConfirmationMethod required";
            throw new MalformedException(msg);
        }
        Iterator i = this.getConfirmationMethods();
        while (i.hasNext()) {
            if (CONF_HOLDER_KEY.equals((String) i.next())) {
                if (keyInfo == null) {
                    String msg = "Subject is invalid: ";
                    msg += "Holder-of-key subject confirmation requires KeyInfo";
                    throw new MalformedException(msg);
                }
                break;
            }
        }
        // internal sanity check:
        if (confirmationData != null &&
            !XML.isElementNamed(confirmationData, XML.SAML_NS, "SubjectConfirmationData")) {
            String msg = "Subject is invalid: ";
            msg += "SubjectConfirmationData expected";
            throw new MalformedException(msg);
        }
    }

    /**
     * This method implements a modified form of the following
     * definition (section&nbsp;3.4.4 of SAMLCore):
     * <blockquote>
     *   A <code>&lt;saml:Subject&gt;</code> element S1
     *   <strong>strongly matches</strong> S2 if and only if
     *   the following two conditions both apply:
     *   <ul>
     *     <li> If S2 includes a <code>&lt;saml:NameIdentifier&gt;</code>
     *     element, then S1 must include an identical
     *     <code>&lt;saml:NameIdentifier&gt;</code> element.</li>
     *
     *     <li> If S2 includes a <code>&lt;saml:SubjectConfirmation&gt;</code>
     *     element, then S1 must include an identical
     *     <code>&lt;saml:SubjectConfirmation&gt;</code> element.</li>
     *   </ul>
     * </blockquote>
     * The latter condition implies that the two
     * <code>&lt;saml:SubjectConfirmation&gt;</code> elements have
     * the same "deep structure," which is too restrictive.
     * Instead, this method relaxes this restriction as follows: If S2
     * includes a <code>&lt;saml:SubjectConfirmation&gt;</code> element,
     * then S1 must also include a
     * <code>&lt;saml:SubjectConfirmation&gt;</code> element
     * such that every <code>&lt;saml:ConfirmationMethod&gt;</code>
     * contained by S2 is also contained by S1.  In practice, since
     * a <code>&lt;saml:SubjectConfirmation&gt;</code> element usually
     * contains a single <code>&lt;saml:ConfirmationMethod&gt;</code>
     * element, this reduces to equivalent confirmation methods.
     * <p>
     * Note that this operation is not symmetric, that is, one can
     * easily construct an example where S1 strongly matches S2 but
     * S2 does not strongly match S1.
     *
     * @param s the given (non-null) Subject to match against
     * @return true if and only if this Subject
     *              strongly matches the given Subject
     */
    public boolean stronglyMatches(SAMLSubject s) {
        if (s == null) {return false;}
        ArrayList cm = this.confirmationMethods;
        if (cm != null) {
            Iterator i = s.getConfirmationMethods();
            while (i.hasNext()) {
                if (!cm.contains((String) i.next())) {
                    return false;
                }
            }
        }
        return s.getNameIdentifier().equals(this.getNameIdentifier());
    }

    /**
     *  Copies a SAML object such that no dependencies exist between the original
     *  and the copy
     *
     * @return      The new object
     * @see Object#clone()
     */
    public Object clone() throws CloneNotSupportedException {
        SAMLSubject dup=(SAMLSubject)super.clone();

        try {
            if (nameId != null)
                dup.nameId = (SAMLNameIdentifier)((SAMLNameIdentifier)nameId.clone()).setParent(dup);

            dup.confirmationMethods = (ArrayList)confirmationMethods.clone();

            if (confirmationData != null)
                dup.confirmationData = (Element)confirmationData.cloneNode(true);

            if (keyInfo != null) {
                dup.keyInfo = new KeyInfo((Element)keyInfo.getElement().cloneNode(true), null);
            }
        }
        catch (SAMLException e) {
            throw new CloneNotSupportedException(e.getMessage());
        }
        catch (XMLSecurityException e) {
            throw new CloneNotSupportedException(e.getMessage());
        }

        return dup;
    }
}
