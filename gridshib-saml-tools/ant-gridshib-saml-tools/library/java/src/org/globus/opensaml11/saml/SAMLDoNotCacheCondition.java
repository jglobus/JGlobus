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
 *  Represents a SAML DoNotCacheCondition
 *
 * @author     Scott Cantor (created March 30, 2002)
 */
public class SAMLDoNotCacheCondition extends SAMLCondition implements Cloneable
{
    /**
     *  Default constructor
     */
    public SAMLDoNotCacheCondition() {
    }

    /**
     *  Reconstructs a condition from a DOM tree
     *
     * @param  e                  The root of a DOM tree
     * @exception  SAMLException  Thrown if the object cannot be constructed
     */
    public SAMLDoNotCacheCondition(Element e) throws SAMLException {
        fromDOM(e);
    }

    /**
     *  Reconstructs a condition from a stream
     *
     * @param  in                   A stream containing XML
     * @exception  SAMLException  Raised if an exception occurs while constructing
     *                              the object.
     */
    public SAMLDoNotCacheCondition(InputStream in) throws SAMLException {
        fromDOM(fromStream(in));
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#fromDOM(org.w3c.dom.Element)
     */
    public void fromDOM(Element e) throws SAMLException {
        super.fromDOM(e);

        if (config.getBooleanProperty("org.globus.opensaml11.saml.strict-dom-checking")) {
            if (!XML.isElementNamed(e,XML.SAML_NS,"DoNotCacheCondition")) {
                QName q = XML.getQNameAttribute(e, XML.XSI_NS, "type");
                if (!XML.isElementNamed(e,XML.SAML_NS,"Condition") || q == null ||
                    !XML.SAML_NS.equals(q.getNamespaceURI()) || !"DoNotCacheConditionType".equals(q.getLocalPart()))
                    throw new MalformedException(SAMLException.RESPONDER, "SAMLDoNotCacheCondition() requires saml:DoNotCacheCondition at root");
            }
        }
    }

    /**
     *  @see org.globus.opensaml11.saml.SAMLObject#buildRoot(org.w3c.dom.Document,boolean)
     */
    protected Element buildRoot(Document doc, boolean xmlns) {
        Element c = doc.createElementNS(XML.SAML_NS, "DoNotCacheCondition");
        if (xmlns)
            c.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
        return c;
    }

    /**
     *  @see org.globus.opensaml11.saml.SAMLObject#toDOM(org.w3c.dom.Document,boolean)
     */
    public Node toDOM(Document doc, boolean xmlns) throws SAMLException {
        super.toDOM(doc, xmlns);
        if (dirty)
            setDirty(false);
        else if (xmlns)
            ((Element)root).setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
        return root;
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#checkValidity()
     */
    public void checkValidity() throws SAMLException {
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

