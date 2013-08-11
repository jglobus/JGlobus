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

import org.w3c.dom.*;

/**
 *  SAML Attribute Designator implementation
 *
 * @author     Scott Cantor (created Nov 22, 2003)
 */
public class SAMLAttributeDesignator extends SAMLObject implements Cloneable
{
    /**  Name of attribute */
    protected String name = null;

    /**  Namespace/qualifier of attribute */
    protected String namespace = null;

    /**
     *  Default constructor
     */
    public SAMLAttributeDesignator() {
    }

    /**
     *  Builds an AttributeDesignator out of its component parts
     *
     * @param  name               Name of attribute
     * @param  namespace          Namespace/qualifier of attribute
     * @exception  SAMLException  Thrown if attribute cannot be built from the
     *      supplied information
     */
    public SAMLAttributeDesignator(String name, String namespace) throws SAMLException {
        this.name = XML.assign(name);
        this.namespace = XML.assign(namespace);
    }

    /**
     *  Reconstructs an AttributeDesignator from a DOM tree
     *
     * @param  e                  The root of a DOM tree
     * @exception  SAMLException  Thrown if the object cannot be constructed
     */
    public SAMLAttributeDesignator(Element e) throws SAMLException {
        fromDOM(e);
    }

    /**
     *  Reconstructs an AttributeDesignator from a stream
     *
     * @param  in                   A stream containing XML
     * @exception  SAMLException  Raised if an exception occurs while constructing
     *                              the object.
     */
    public SAMLAttributeDesignator(InputStream in) throws SAMLException {
        fromDOM(fromStream(in));
    }

    /**
     *  Initialization of AttributeDesignator from a DOM element.<P>
     *
     * @param  e                   Root element of a DOM tree
     * @exception  SAMLException   Raised if an exception occurs while constructing the object.
     */
    public void fromDOM(Element e) throws SAMLException {
        super.fromDOM(e);

        if (config.getBooleanProperty("org.globus.opensaml11.saml.strict-dom-checking") && !XML.isElementNamed(e,XML.SAML_NS,"AttributeDesignator"))
            throw new MalformedException("SAMLAttributeDesignator.fromDOM() requires saml:AttributeDesignator at root");

        name = XML.assign(e.getAttributeNS(null, "AttributeName"));
        namespace = XML.assign(e.getAttributeNS(null, "AttributeNamespace"));
        checkValidity();
    }

    /**
     *  Gets the AttributeName attribute of the SAML AttributeDesignator
     *
     * @return    The name value
     */
    public String getName() {
        return name;
    }

    /**
     *  Sets the AttributeName attribute of the SAML AttributeDesignator
     *
     * @param   name    The name value
     */
    public void setName(String name) {
        if (XML.isEmpty(name))
            throw new IllegalArgumentException("name cannot be null");
        this.name = name;
        setDirty(true);
    }

    /**
     *  Gets the AttributeNamespace attribute of the SAML AttributeDesignator
     *
     * @return    The namespace value
     */
    public String getNamespace() {
        return namespace;
    }

    /**
     *  Sets the AttributeNamespace attribute of the SAML AttributeDesignator
     *
     * @param   namespace    The name value
     */
    public void setNamespace(String namespace) {
        if (XML.isEmpty(namespace))
            throw new IllegalArgumentException("namespace cannot be null");
        this.namespace = namespace;
        setDirty(true);
    }

    /**
     *  @see org.globus.opensaml11.saml.SAMLObject#buildRoot(org.w3c.dom.Document,boolean)
     */
    protected Element buildRoot(Document doc, boolean xmlns) {
        Element a = doc.createElementNS(XML.SAML_NS, "AttributeDesignator");
        if (xmlns)
            a.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
        return a;
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#toDOM(org.w3c.dom.Document,boolean)
     */
    public Node toDOM(Document doc, boolean xmlns) throws SAMLException {
        // Let the base build/verify the DOM root.
        super.toDOM(doc, xmlns);
        Element a = (Element)root;

        if (dirty) {
            a.setAttributeNS(null, "AttributeName", name);
            a.setAttributeNS(null, "AttributeNamespace", namespace);
            setDirty(false);
        }
        else if (xmlns) {
            a.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
        }
        return root;
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#checkValidity()
     */
    public void checkValidity() throws SAMLException {
        if (XML.isEmpty(name) || XML.isEmpty(namespace))
            throw new MalformedException(SAMLException.RESPONDER, "AttributeDesignator invalid, requires name and namespace");
    }

    /**
     *  Copies a SAML object such that no dependencies exist between the original
     *  and the copy. Does not clone values.
     *
     * @return      The new object
     * @see Object#clone()
     */
    public Object clone() throws CloneNotSupportedException {
        return (SAMLAttributeDesignator)super.clone();
    }
}
