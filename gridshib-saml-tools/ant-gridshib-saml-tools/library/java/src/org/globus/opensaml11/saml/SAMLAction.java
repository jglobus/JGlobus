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

import org.w3c.dom.Element;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

/**
 *  Represents a SAML Action
 *
 * @author     Helen Rehn (created October 4, 2002)
 */
public class SAMLAction extends SAMLObject implements Cloneable
{
    /** SAML Action Namespace URI values */

    public static final String SAML_ACTION_NAMESPACE_RWEDC = "urn:oasis:names:tc:SAML:1.0:action:rwedc";

    public static final String SAML_ACTION_NAMESPACE_RWEDC_NEG = "urn:oasis:names:tc:SAML:1.0:action:rwedc-negation";

    public static final String SAML_ACTION_NAMESPACE_GHPP = "urn:oasis:names:tc:SAML:1.0:action:ghpp";

    public static final String SAML_ACTION_NAMESPACE_UNIX = "urn:oasis:names:tc:SAML:1.0:action:unix";

    private String namespace = null;
    private String data = null;

    /**
     *  Default constructor
     */
    public SAMLAction() {
    }

    /**
     *  Builds an action out of its component parts
     *
     * @param  namespace  a URI reference representing the namespace in
     *                    which the name of the specified action is to be
     *                    interpreted
     * @param  data       an action sought to be performed on the specified
     *                    resource
     * @exception  SAMLException  Raised if an action cannot be constructed
     *      from the supplied information
     */
    public SAMLAction(String namespace, String data) throws SAMLException {
        this.namespace = XML.assign(namespace);
        this.data = XML.assign(data);
    }

    /**
     *  Reconstructs an action from a DOM tree
     *
     * @param  e                  The root of a DOM tree
     * @exception  SAMLException  Thrown if the object cannot be constructed
     */
    public SAMLAction(Element e) throws SAMLException {
        fromDOM(e);
    }

    /**
     *  Reconstructs an action from a stream
     *
     * @param  in                   A stream containing XML
     * @exception  SAMLException  Raised if an exception occurs while constructing
     *                              the object.
     */
    public SAMLAction(InputStream in) throws SAMLException {
        fromDOM(fromStream(in));
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#fromDOM(org.w3c.dom.Element)
     */
    public void fromDOM(Element e) throws SAMLException {
        super.fromDOM(e);

        if (config.getBooleanProperty("org.globus.opensaml11.saml.strict-dom-checking") && !XML.isElementNamed(e,XML.SAML_NS,"Action"))
            throw new MalformedException(SAMLException.RESPONDER, "SAMLAction() requires saml:Action at root");

        namespace = XML.assign(e.getAttributeNS(null,"Namespace"));
        if (e.hasChildNodes())
            data = XML.assign(e.getFirstChild().getNodeValue());

        checkValidity();
    }

    /**
     *  Gets the namespace from the action
     *
     * @return    the namespace
     */
    public String getNamespace() {
       return namespace;
    }

    /**
     *  Gets the data from the action
     *
     * @return    the data
     */
    public String getData() {
        return data;
    }

    /**
     *  Sets the namespace of the action
     *
     * @param namespace    the namespace
     */
    public void setNamespace(String namespace) {
        this.namespace = XML.assign(namespace);
        setDirty(true);
    }

    /**
     *  Sets the data of the action
     *
     * @param data    the data
     */
    public void setData(String data) {
        if (XML.isEmpty(data))
            throw new IllegalArgumentException("data cannot be null or empty");
        this.data = data;
        setDirty(true);
    }

    /**
     *  @see org.globus.opensaml11.saml.SAMLObject#buildRoot(org.w3c.dom.Document,boolean)
     */
    protected Element buildRoot(Document doc, boolean xmlns) {
        Element a = doc.createElementNS(XML.SAML_NS, "Action");
        if (xmlns)
            a.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
        return a;
    }

    /**
     *  @see org.globus.opensaml11.saml.SAMLObject#toDOM(org.w3c.dom.Document,boolean)
     */
    public Node toDOM(Document doc, boolean xmlns) throws SAMLException {
        // Let the base build/verify the DOM root.
        super.toDOM(doc, xmlns);
        if (dirty) {
            // Dirty bit is set, so we need to rebuild.
            Element a = (Element)root;
            if (!XML.isEmpty(namespace))
                a.setAttributeNS(null, "Namespace", namespace);
            a.appendChild(doc.createTextNode(data));
            setDirty(false);
        }
        else if (xmlns) {
            ((Element)root).setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
        }
        return root;
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#checkValidity()
     */
    public void checkValidity() throws SAMLException {
        if (XML.isEmpty(data))
            throw new MalformedException("Action is invalid, data must have a value");
    }

    /**
     *  Copies a SAML object such that no dependencies exist between the original and the copy
     *
     * @return      The new object
     * @see Object#clone()
     */
    public Object clone() throws CloneNotSupportedException {
        return super.clone();
    }
}

