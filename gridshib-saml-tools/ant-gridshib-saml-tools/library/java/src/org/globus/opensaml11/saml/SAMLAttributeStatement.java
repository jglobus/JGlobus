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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import javax.xml.namespace.QName;

import org.w3c.dom.*;

/**
 *  Represents a SAML Attribute Statement
 *
 * @author     Scott Cantor (created March 25, 2002)
 */
public class SAMLAttributeStatement extends SAMLSubjectStatement implements Cloneable
{
    protected ArrayList attrs = new ArrayList();

    /**
     *  Default constructor
     */
    public SAMLAttributeStatement() {
    }

    /**
     *  Builds a statement out of its component parts
     *
     * @param  subject            Subject of statement
     * @param  attrs              Collection of attributes
     * @exception  SAMLException  Raised if a statement cannot be constructed
     *      from the supplied information
     */
    public SAMLAttributeStatement(SAMLSubject subject, Collection attrs) throws SAMLException {
        super(subject);

        for (Iterator i=attrs.iterator(); i.hasNext(); )
            this.attrs.add(((SAMLAttribute)i.next()).setParent(this));
    }

    /**
     *  Reconstructs an attribute statement from a DOM tree
     *
     * @param  e                  The root of a DOM tree
     * @exception  SAMLException  Thrown if the object cannot be constructed
     */
    public SAMLAttributeStatement(Element e) throws SAMLException {
        fromDOM(e);
    }

    /**
     *  Reconstructs an attribute statement from a stream
     *
     * @param  in                   A stream containing XML
     * @exception  SAMLException  Raised if an exception occurs while constructing
     *                              the object.
     */
    public SAMLAttributeStatement(InputStream in) throws SAMLException {
        fromDOM(fromStream(in));
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#fromDOM(org.w3c.dom.Element)
     */
    public void fromDOM(Element e) throws SAMLException {
        super.fromDOM(e);

        if (config.getBooleanProperty("org.globus.opensaml11.saml.strict-dom-checking") && !XML.isElementNamed(e,XML.SAML_NS,"AttributeStatement"))
        {
            QName q = XML.getQNameAttribute(e, XML.XSI_NS, "type");
            if (!(XML.isElementNamed(e,XML.SAML_NS,"Statement") || XML.isElementNamed(e,XML.SAML_NS,"SubjectStatement")) || q == null || !XML.SAML_NS.equals(q.getNamespaceURI()) || !"AttributeStatementType".equals(q.getLocalPart()))
                throw new MalformedException(SAMLException.REQUESTER, "SAMLAttributeStatement() requires saml:AttributeStatement at root");
        }

        // Extract attributes.
        Element n = XML.getFirstChildElement(root, XML.SAML_NS, "Attribute");
        while (n != null) {
            try {
                attrs.add(SAMLAttribute.getInstance(n).setParent(this));
            }
            catch (SAMLException ex) {
                log.warn("exception while instantiating a SAMLAttribute: " + ex.getMessage());
            }
            n = XML.getNextSiblingElement(n, XML.SAML_NS, "Attribute");
        }

        checkValidity();
    }

    /**
     *  Gets attributes from the statement, if any
     *
     * @return    An array of attributes
     */
    public Iterator getAttributes() {
        return attrs.iterator();
    }

    /**
     *  Sets the attributes inside the statement
     *
     * @param attributes    The attributes to include
     * @exception   SAMLException   Raised if the attributes are invalid
     */
    public void setAttributes(Collection attributes) throws SAMLException {
        attrs.clear();
        if (attributes != null) {
            for (Iterator i = attributes.iterator(); i.hasNext(); )
                attrs.add(((SAMLAttribute)i.next()).setParent(this));
        }
        setDirty(true);
    }

    /**
     *  Adds an attribute to the statement
     *
     * @param attribute    The attribute to add
     * @exception SAMLException     Raised if the subject is invalid
     */
    public void addAttribute(SAMLAttribute attribute) throws SAMLException {
        if (attribute != null) {
            attrs.add(attribute.setParent(this));
            setDirty(true);
        }
        else
            throw new IllegalArgumentException("attribute cannot be null");
    }

    /**
     *  Removes an attribute by position (zero-based)
     *
     * @param   index   The position of the attribute to remove
     */
    public void removeAttribute(int index) {
        attrs.remove(index);
        setDirty(true);
    }

    /**
     *  @see org.globus.opensaml11.saml.SAMLObject#buildRoot(org.w3c.dom.Document,boolean)
     */
    protected Element buildRoot(Document doc, boolean xmlns) {
        Element s = doc.createElementNS(XML.SAML_NS, "AttributeStatement");
        if (xmlns) {
            s.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
            s.setAttributeNS(XML.XMLNS_NS, "xmlns:xsd", XML.XSD_NS);
            s.setAttributeNS(XML.XMLNS_NS, "xmlns:xsi", XML.XSI_NS);
        }
        return s;
    }

    /**
     *  @see org.globus.opensaml11.saml.SAMLObject#toDOM(org.w3c.dom.Document,boolean)
     */
    public Node toDOM(Document doc, boolean xmlns) throws SAMLException {
        // Let the base build/verify the DOM root.
        super.toDOM(doc, xmlns);
        Element statement = (Element)root;

        if (dirty) {
            for (Iterator i=attrs.iterator(); i.hasNext();)
                statement.appendChild(((SAMLAttribute)i.next()).toDOM(doc, false));
            setDirty(false);
        }
        else if (xmlns) {
            statement.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
            statement.setAttributeNS(XML.XMLNS_NS, "xmlns:xsd", XML.XSD_NS);
            statement.setAttributeNS(XML.XMLNS_NS, "xmlns:xsi", XML.XSI_NS);
        }

        return root;
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#checkValidity()
     */
    public void checkValidity() throws SAMLException {
        super.checkValidity();
        if (attrs == null || attrs.size() == 0)
            throw new MalformedException("AttributeStatement is invalid, requires at least one attribute");
    }

    /**
     *  Copies a SAML object such that no dependencies exist between the original
     *  and the copy
     *
     * @return      The new object
     * @see Object#clone()
     */
    public Object clone() throws CloneNotSupportedException {
        SAMLAttributeStatement dup=(SAMLAttributeStatement)super.clone();

        try {
            // Clone the embedded objects.
            dup.attrs = new ArrayList();
            for (Iterator i=attrs.iterator(); i.hasNext(); )
                dup.attrs.add(((SAMLAttribute)((SAMLAttribute)i.next()).clone()).setParent(dup));
        }
        catch (SAMLException e) {
            throw new CloneNotSupportedException(e.getMessage());
        }

        return dup;
    }
}

