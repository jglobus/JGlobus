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
 *  Represents a SAML Authentication Query object
 *
 * @author     Scott Cantor (created March 25, 2002)
 */
public class SAMLAuthenticationQuery extends SAMLSubjectQuery implements Cloneable
{
    protected String authMethod = null;

    /**
     *  Default constructor
     */
    public SAMLAuthenticationQuery() {
    }

    /**
     *  Builds an authentication query out of its component parts
     *
     * @param  subject            Subject of query
     * @param  authMethod         Authentication method in query
     * @exception  SAMLException  Raised if the query cannot be constructed from
     *      the supplied information
     */
    public SAMLAuthenticationQuery(SAMLSubject subject, String authMethod) throws SAMLException {
        super(subject);
        this.authMethod = XML.assign(authMethod);
    }

    /**
     *  Reconstructs an authentication query from a DOM tree
     *
     * @param  e                  The root of a DOM tree
     * @exception  SAMLException  Thrown if the object cannot be constructed
     */
    public SAMLAuthenticationQuery(Element e) throws SAMLException {
        fromDOM(e);
    }

    /**
     *  Reconstructs an authentication query from a stream
     *
     * @param  in                   A stream containing XML
     * @exception  SAMLException  Raised if an exception occurs while constructing
     *                              the object.
     */
    public SAMLAuthenticationQuery(InputStream in) throws SAMLException {
        fromDOM(fromStream(in));
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#fromDOM(org.w3c.dom.Element)
     */
    public void fromDOM(Element e) throws SAMLException {
        super.fromDOM(e);

        if (config.getBooleanProperty("org.globus.opensaml11.saml.strict-dom-checking") && !XML.isElementNamed(e,XML.SAMLP_NS,"AuthenticationQuery"))
        {
            QName q = XML.getQNameAttribute(e, XML.XSI_NS, "type");
            if (!(XML.isElementNamed(e,XML.SAMLP_NS,"Query") || XML.isElementNamed(e,XML.SAMLP_NS,"SubjectQuery")) || q == null || !XML.SAMLP_NS.equals(q.getNamespaceURI()) || !"AuthenticationQueryType".equals(q.getLocalPart()))
                throw new MalformedException(SAMLException.REQUESTER, "SAMLAuthenticationQuery.fromDOM() requires samlp:AuthenticationQuery at root");
        }

        authMethod = XML.assign(e.getAttributeNS(null, "AuthenticationMethod"));
        checkValidity();
    }

    /**
     *  Gets the authentication method inside the query
     *
     * @return    The authentication method URI
     */
    public String getAuthMethod() {
        return authMethod;
    }

    /**
     *  Sets the authentication method inside the query
     *
     * @param   authMethod    The authentication method URI
     */
    public void setAuthMethod(String authMethod) {
        if (XML.isEmpty(authMethod))
            throw new IllegalArgumentException("authMethod cannot be null or empty");
        this.authMethod = authMethod;
        setDirty(true);
    }

    /**
     *  @see org.globus.opensaml11.saml.SAMLObject#buildRoot(org.w3c.dom.Document,boolean)
     */
    protected Element buildRoot(Document doc, boolean xmlns) {
        Element q = doc.createElementNS(XML.SAMLP_NS, "AuthenticationQuery");
        if (xmlns)
            q.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAMLP_NS);
        return q;
    }

    /**
     *  @see org.globus.opensaml11.saml.SAMLObject#toDOM(org.w3c.dom.Document,boolean)
     */
    public Node toDOM(Document doc, boolean xmlns) throws SAMLException {
        // Let the base build/verify the DOM root.
        super.toDOM(doc, xmlns);
        Element q = (Element)root;

        if (dirty) {
            if (!XML.isEmpty(authMethod))
                q.setAttributeNS(null, "AuthenticationMethod", authMethod);
            setDirty(false);
        }
        else if (xmlns) {
            q.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAMLP_NS);
        }

        return root;
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

