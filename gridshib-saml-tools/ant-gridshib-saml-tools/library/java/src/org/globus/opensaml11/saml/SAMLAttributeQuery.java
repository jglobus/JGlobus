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
 *  Represents a SAML Attribute Query object
 *
 * @author     Scott Cantor (created March 25, 2002)
 */
public class SAMLAttributeQuery extends SAMLSubjectQuery implements Cloneable
{
    protected String resource = null;
    protected ArrayList designators = new ArrayList();

    /**
     *  Default constructor
     */
    public SAMLAttributeQuery() {
    }

    /**
     *  Builds an attribute query out of its component parts
     *
     * @param  subject            Subject of query
     * @param  resource           URI of resource being accessed at time of
     *      query
     * @param  designators        Indicates specific attributes to query for
     * @exception  SAMLException  Raised if the query cannot be constructed from
     *      the supplied information
     */
    public SAMLAttributeQuery(SAMLSubject subject, String resource, Collection designators) throws SAMLException {
        super(subject);

        this.resource = XML.assign(resource);
        if (designators != null) {
            for (Iterator i=designators.iterator(); i.hasNext();)
                this.designators.add(((SAMLAttributeDesignator)i.next()).setParent(this));
        }
    }

    /**
     *  Reconstructs an attribute query from a DOM tree
     *
     * @param  e                  The root of a DOM tree
     * @exception  SAMLException  Thrown if the object cannot be constructed
     */
    public SAMLAttributeQuery(Element e) throws SAMLException {
        fromDOM(e);
    }

    /**
     *  Reconstructs an attribute query from a stream
     *
     * @param  in                   A stream containing XML
     * @exception  SAMLException  Raised if an exception occurs while constructing
     *                              the object.
     */
    public SAMLAttributeQuery(InputStream in) throws SAMLException {
        fromDOM(fromStream(in));
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#fromDOM(org.w3c.dom.Element)
     */
    public void fromDOM(Element e) throws SAMLException {
        super.fromDOM(e);

        if (config.getBooleanProperty("org.globus.opensaml11.saml.strict-dom-checking") && !XML.isElementNamed(e,XML.SAMLP_NS,"AttributeQuery")) {
            QName q = XML.getQNameAttribute(e, XML.XSI_NS, "type");
            if (!(XML.isElementNamed(e,XML.SAMLP_NS,"Query") || XML.isElementNamed(e,XML.SAMLP_NS,"SubjectQuery")) || q == null || !XML.SAMLP_NS.equals(q.getNamespaceURI()) || !"AttributeQueryType".equals(q.getLocalPart()))
                throw new MalformedException(SAMLException.REQUESTER, "SAMLAttributeQuery() requires samlp:AttributeQuery at root");
        }

        if (e.hasAttributeNS(null, "Resource"))
            resource = XML.assign(e.getAttributeNS(null, "Resource"));

        // Extract attribute designators, if any.
        Element n = XML.getFirstChildElement(root, XML.SAML_NS, "AttributeDesignator");
        while (n != null) {
            designators.add(new SAMLAttributeDesignator(n).setParent(this));
            n = XML.getNextSiblingElement(n, XML.SAML_NS, "AttributeDesignator");
        }

        checkValidity();
    }

    /**
     *  Gets the resource URI inside the query
     *
     * @return    The resource URI
     */
    public String getResource()
    {
        return resource;
    }

    /**
     *  Sets the resource URI inside the query
     *
     * @param   resource    The resource URI
     */
    public void setResource(String resource) {
        this.resource = XML.assign(resource);
        setDirty(true);
    }

    /**
     *  Gets the attribute designators inside the query
     *
     * @return    An iterator of attribute designators
     */
    public Iterator getDesignators() {
        return designators.iterator();
    }

    /**
     *  Sets the attribute designators inside the query
     *
     * @param designators    The designators to include
     * @exception   SAMLException   Raised if the designators are invalid
     */
    public void setDesignators(Collection designators) throws SAMLException {
        this.designators.clear();
        if (designators != null) {
            for (Iterator i = designators.iterator(); i.hasNext(); )
                this.designators.add(((SAMLAttributeDesignator)i.next()).setParent(this));
        }
        setDirty(true);
    }

    /**
     *  Adds an attribute designator to the query
     *
     * @param designator    The designator to add
     * @exception   SAMLException   Raised if the designator is invalid
     */
    public void addDesignator(SAMLAttributeDesignator designator) throws SAMLException {
        if (designator != null) {
            designators.add(designator.setParent(this));
            setDirty(true);
        }
        else
            throw new IllegalArgumentException("designator cannot be null");
    }

    /**
     *  Removes a designator by position (zero-based)
     *
     * @param   index   The position of the designator to remove
     */
    public void removeDesignator(int index) {
        designators.remove(index);
        setDirty(true);
    }

    /**
     *  @see org.globus.opensaml11.saml.SAMLObject#buildRoot(org.w3c.dom.Document,boolean)
     */
    protected Element buildRoot(Document doc, boolean xmlns) {
        Element q = doc.createElementNS(XML.SAMLP_NS, "AttributeQuery");
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
            if (!XML.isEmpty(resource))
                q.setAttributeNS(null, "Resource", resource);

            for (Iterator i=designators.iterator(); i.hasNext(); )
                q.appendChild(((SAMLAttributeDesignator)i.next()).toDOM(doc));

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
        SAMLAttributeQuery dup=(SAMLAttributeQuery)super.clone();

        try {
            // Clone the embedded objects.
            dup.designators = new ArrayList();
            for (Iterator i=designators.iterator(); i.hasNext(); )
                dup.designators.add(((SAMLAttributeDesignator)((SAMLAttributeDesignator)i.next()).clone()).setParent(dup));
        }
        catch (SAMLException e) {
            throw new CloneNotSupportedException(e.getMessage());
        }

        return dup;
    }
}

