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

import javax.xml.namespace.QName;

import org.w3c.dom.*;

/**
 *  Wraps a SAML Authority Binding
 *
 * @author     Scott Cantor (created March 25, 2002)
 */
public class SAMLAuthorityBinding extends SAMLObject implements Cloneable
{
    protected String binding = null;
    protected String location = null;
    protected QName authorityKind = null;

    /**
     *  Default constructor
     */
    public SAMLAuthorityBinding() {
    }

    /**
     *  Constructor builds a SAML AuthorityBinding out of its component parts
     *
     * @param  binding            The SAML binding protocol to use
     * @param  location           The AA address (URI, format dependent on the protocol)
     * @param  authorityKind      The QName of the Query element that the authority knows
     *      how to process
     * @exception  SAMLException  Thrown if any parameters are invalid
     */
    public SAMLAuthorityBinding(String binding, String location, QName authorityKind) throws SAMLException {
        this.binding = XML.assign(binding);
        this.location = XML.assign(location);
        this.authorityKind = authorityKind;
    }

    /**
     *  Reconstructs a binding from a DOM tree
     *
     * @param  e                  The root of a DOM tree
     * @exception  SAMLException  Thrown if the object cannot be constructed
     */
    public SAMLAuthorityBinding(Element e) throws SAMLException {
        fromDOM(e);
    }

    /**
     *  Reconstructs a binding from a stream
     *
     * @param  in                   A stream containing XML
     * @exception  SAMLException  Raised if an exception occurs while constructing
     *                              the object.
     */
    public SAMLAuthorityBinding(InputStream in) throws SAMLException {
        fromDOM(fromStream(in));
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#fromDOM(org.w3c.dom.Element)
     */
    public void fromDOM(Element e) throws SAMLException {
        super.fromDOM(e);

        if (config.getBooleanProperty("org.globus.opensaml11.saml.strict-dom-checking") && !XML.isElementNamed(e,XML.SAML_NS,"AuthorityBinding"))
            throw new MalformedException(SAMLException.RESPONDER, "SAMLAuthorityBinding() requires saml:AuthorityBinding at root");

        binding = XML.assign(e.getAttributeNS(null,"Binding"));
        location = XML.assign(e.getAttributeNS(null,"Location"));
        authorityKind = XML.getQNameAttribute(e,null,"AuthorityKind");

        checkValidity();
    }

    /**
     *  Gets the protocol binding attribute of the authority binding
     *
     * @return    The binding protocol value
     */
    public String getBinding() {
        return binding;
    }

    /**
     *  Sets the protocol binding attribute of the authority binding
     *
     * @param   binding    The binding protocol value
     */
    public void setBinding(String binding) {
        if (XML.isEmpty(binding))
            throw new IllegalArgumentException("binding cannot be null or empty");
        this.binding = binding;
        setDirty(true);
    }

    /**
     *  Gets the location attribute of the authority binding
     *
     * @return    The location value
     */
    public String getLocation() {
        return location;
    }

    /**
     *  Sets the location attribute of the authority binding
     *
     * @param   location    The location value
     */
    public void setLocation(String location) {
        if (XML.isEmpty(location))
            throw new IllegalArgumentException("location cannot be null or empty");
        this.location = location;
        setDirty(true);
    }

    /**
     *  Gets the QName of the query element processable by the authority
     *
     * @return    The query element QName
     */
    public QName getAuthorityKind() {
        return authorityKind;
    }

    /**
     *  Sets the QName of the query element processable by the authority
     *
     * @param   authorityKind    The query element QName
     */
    public void setAuthorityKind(QName authorityKind) {
        if (authorityKind == null)
            throw new IllegalArgumentException("authorityKind cannot be null");
        this.authorityKind = authorityKind;
        setDirty(true);
    }

    /**
     *  @see org.globus.opensaml11.saml.SAMLObject#buildRoot(org.w3c.dom.Document,boolean)
     */
    protected Element buildRoot(Document doc, boolean xmlns) {
        Element ab = doc.createElementNS(XML.SAML_NS, "AuthorityBinding");
        if (xmlns)
            ab.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
        return ab;
    }

    /**
     *  @see org.globus.opensaml11.saml.SAMLObject#toDOM(org.w3c.dom.Document,boolean)
     */
    public Node toDOM(Document doc, boolean xmlns) throws SAMLException {
        // Let the base build/verify the DOM root.
        super.toDOM(doc, xmlns);
        Element ab = (Element)root;

        if (dirty) {
            ab.setAttributeNS(null, "Binding", binding);
            ab.setAttributeNS(null, "Location", location);
            if (!XML.SAMLP_NS.equals(authorityKind.getNamespaceURI())) {
                ab.setAttributeNS(XML.XMLNS_NS, "xmlns:kind", authorityKind.getNamespaceURI());
                ab.setAttributeNS(null, "AuthorityKind","kind:" + authorityKind.getLocalPart());
            }
            else
                ab.setAttributeNS(null, "AuthorityKind","samlp:" + authorityKind.getLocalPart());
            setDirty(false);
        }
        else if (xmlns) {
            ab.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
        }

        return root;
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#checkValidity()
     */
    public void checkValidity() throws SAMLException {
        if (XML.isEmpty(binding) || XML.isEmpty(location) || authorityKind == null)
            throw new MalformedException("AuthorityBinding is invalid, must have Binding, Location, and AuthorityKind");
    }

    /**
     *  Copies a SAML object such that no dependencies exist between the original
     *  and the copy
     *
     * @return      The new object
     * @see Object#clone()
     */
    public Object clone() throws CloneNotSupportedException {
        return super.clone();
    }
}

