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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 *  Represents a SAML AuthorizationDecisionQuery
 *
 * @author     Helen Rehn (created October 4, 2002)
 * @author     Scott Cantor
 */

public class SAMLAuthorizationDecisionQuery extends SAMLSubjectQuery implements Cloneable
{
    protected String resource = null;
    protected ArrayList actions = new ArrayList();
    protected ArrayList evidence = new ArrayList();

    /**
     *  Default constructor
     */
    public SAMLAuthorizationDecisionQuery() {
    }

    /**
     *  Builds an AuthorizationDecisionQuery out of its component parts
     *
     * @param  subject     subject of the query
     * @param  resource    URI of the resource being accessed at the time of
     *                           the query
     * @param  actions     specific actions being queried for, must contain SAMLAction objects
     * @param  evidence    evidence which may be considered, must contain String or SAMLAssertion objects
     * @exception  SAMLException  Raised if an AuthorizationDecisionQuery
     *             cannot be constructed from the supplied information
     */
    public SAMLAuthorizationDecisionQuery(
            SAMLSubject subject, String resource, Collection actions, Collection evidence
            ) throws SAMLException {
        super(subject);

        this.resource = XML.assign(resource);

        if (actions != null) {
            for (Iterator i=actions.iterator(); i.hasNext(); )
                this.actions.add(((SAMLAction)i.next()).setParent(this));
        }

        if (evidence != null) {
            for (Iterator i=evidence.iterator(); i.hasNext(); ) {
                Object o = i.next();
                if (o instanceof SAMLAssertion)
                    this.evidence.add(((SAMLAssertion)o).setParent(this));
                else if (o instanceof String && ((String)o).length() > 0)
                    this.evidence.add(o);
            }
        }
    }

    /**
     *  Reconstructs a query from a DOM tree
     *
     * @param  e                  The root of a DOM tree
     * @exception  SAMLException  Thrown if the object cannot be constructed
     */
    public SAMLAuthorizationDecisionQuery(Element e) throws SAMLException {
        fromDOM(e);
    }

    /**
     *  Reconstructs a query from a stream
     *
     * @param  in                   A stream containing XML
     * @exception  SAMLException  Raised if an exception occurs while constructing
     *                              the object.
     */
    public SAMLAuthorizationDecisionQuery(InputStream in) throws SAMLException {
        fromDOM(fromStream(in));
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#fromDOM(org.w3c.dom.Element)
     */
    public void fromDOM(Element e) throws SAMLException {
        super.fromDOM(e);

        if (config.getBooleanProperty("org.globus.opensaml11.saml.strict-dom-checking") && !XML.isElementNamed(e,XML.SAMLP_NS,"AuthorizationDecisionQuery"))
        {
            QName q = XML.getQNameAttribute(e, XML.XSI_NS, "type");
            if (!(XML.isElementNamed(e,XML.SAMLP_NS,"Query") || XML.isElementNamed(e,XML.SAMLP_NS,"SubjectQuery")) || q == null || !XML.SAMLP_NS.equals(q.getNamespaceURI()) || !"AuthorizationDecisionQueryType".equals(q.getLocalPart()))
                throw new MalformedException(SAMLException.REQUESTER, "SAMLAuthorizationDecisionQuery.fromDOM() requires samlp:AuthorizationDecisionQuery at root");
        }

        resource = XML.assign(e.getAttributeNS(null, "Resource"));

        Element n = XML.getFirstChildElement(e, XML.SAML_NS, "Action");
        while (n != null) {
            actions.add(new SAMLAction(n).setParent(this));
            n = XML.getNextSiblingElement(n, XML.SAML_NS, "Action");
        }

        n = XML.getFirstChildElement(e, XML.SAML_NS, "Evidence");
        if (n != null) {
            Element n2 = XML.getFirstChildElement(n);
            while (n2 != null) {
                if (XML.isElementNamed(n2, XML.SAML_NS, "Assertion"))
                    evidence.add(new SAMLAssertion(n2).setParent(this));
                else if (XML.isElementNamed(n2, XML.SAML_NS, "AssertionIDReference")) {
                    if (n2.hasChildNodes())
                        evidence.add(n2.getFirstChild().getNodeValue());
                }
                n2 = XML.getNextSiblingElement(n2);
            }
        }

        checkValidity();
    }

    /**
     *  Gets the resource URI inside the query
     *
     * @return    The resource URI
     */
    public String getResource() {
        return resource;
    }

    /**
     *  Sets the resource URI inside the query
     *
     * @param   resource    The resource URI
     */
    public void setResource(String resource) {
        if (XML.isEmpty(resource))
            throw new IllegalArgumentException("resource cannot be null");
        this.resource = resource;
        setDirty(true);
    }

    /**
     * Gets the actions inside the query
     *
     * @return    An iterator over the actions
     */
    public Iterator getActions() {
        return actions.iterator();
    }

    /**
     *  Sets the actions to include in the query
     *
     * @param   actions  The actions to include
     * @exception SAMLException     Raised if the actions are invalid
     */
    public void setActions(Collection actions) throws SAMLException {
        this.actions.clear();
        if (actions != null) {
            for (Iterator i = actions.iterator(); i.hasNext(); )
                this.actions.add(((SAMLAction)i.next()).setParent(this));
        }
        setDirty(true);
    }

    /**
     *  Adds an action to the query
     * @param   action  The action to add
     * @exception SAMLException     Raised if the action if invalid
     */
    public void addAction(SAMLAction action) throws SAMLException {
        if (action != null) {
            actions.add(action.setParent(this));
            setDirty(true);
        }
        else
            throw new IllegalArgumentException("action cannot be null");
    }

    /**
     *  Removes an action by position (zero-based)
     *
     * @param   index   The position of the action to remove
     */
    public void removeAction(int index) {
        actions.remove(index);
        setDirty(true);
    }

    /**
     *  Gets the evidence inside the query
     *
     * @return     An iterator over the evidence
     */
    public Iterator getEvidence() {
        return evidence.iterator();
    }

    /**
     *  Sets the evidence to include in the query
     *
     * @param   evidence  The evidence to include
     * @exception SAMLException     Raised if the evidence is invalid
     */
    public void setEvidence(Collection evidence) throws SAMLException {
        this.evidence.clear();
        if (evidence != null) {
            for (Iterator i = evidence.iterator(); i.hasNext(); )
                addEvidence(i.next());
        }
        setDirty(true);
    }

    /**
     *  Adds an evidence element
     *
     * @param   evidence    a String or SAMLAssertion
     * @exception SAMLException     Raised if an invalid kind of object is provided
     */
    public void addEvidence(Object evidence) throws SAMLException {
        if (evidence != null && (evidence instanceof String || evidence instanceof SAMLAssertion)) {
            if (evidence instanceof SAMLAssertion)
                this.evidence.add(((SAMLAssertion)evidence).setParent(this));
            else if (((String)evidence).length() > 0)
                this.evidence.add(evidence);
            setDirty(true);
        }
        else
            throw new IllegalArgumentException("can only add Strings or SAMLAssertions");
    }

    /**
     *  Removes an evidence element by position (zero-based)
     *
     * @param   index   The position of the element to remove
     */
    public void removeEvidence(int index) throws IndexOutOfBoundsException {
        evidence.remove(index);
        setDirty(true);
    }

    /**
     *  @see org.globus.opensaml11.saml.SAMLObject#buildRoot(org.w3c.dom.Document,boolean)
     */
    protected Element buildRoot(Document doc, boolean xmlns) {
        Element q = doc.createElementNS(XML.SAMLP_NS, "AuthorizationDecisionQuery");
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
            q.setAttributeNS(null, "Resource", resource);

            Iterator i = actions.iterator();
            while (i.hasNext())
                q.appendChild(((SAMLAction)i.next()).toDOM(doc));

            if (evidence.size()>0) {
                Element ev = doc.createElementNS(XML.SAML_NS, "Evidence");
                ev.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
                i = evidence.iterator();
                while (i.hasNext()) {
                    Object o = i.next();
                    if (o instanceof SAMLAssertion)
                        ev.appendChild(((SAMLAssertion)o).toDOM(doc, false));
                    else if (o instanceof String && !XML.isEmpty((String)o))
                        ev.appendChild(doc.createElementNS(XML.SAML_NS,"AssertionIDReference")).appendChild(doc.createTextNode((String)o));
                }
                q.appendChild(ev);
            }

            setDirty(false);
        }
        else if (xmlns) {
            q.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAMLP_NS);
        }

        return root;
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#checkValidity()
     */
    public void checkValidity() throws SAMLException {
        super.checkValidity();
        if (XML.isEmpty(resource) || actions.size() == 0)
            throw new MalformedException("AuthorizationDecisionQuery is invalid, must have Resource and at least one Action");
    }

    /**
     *  Copies a SAML object such that no dependencies exist between the original
     *  and the copy
     *
     * @return      The new object
     * @see Object#clone()
     */
    public Object clone() throws CloneNotSupportedException {
        SAMLAuthorizationDecisionQuery dup=(SAMLAuthorizationDecisionQuery)super.clone();

        // Clone the embedded objects.
        try {
            dup.actions = new ArrayList();
            for (Iterator i=actions.iterator(); i.hasNext(); )
                dup.actions.add(((SAMLAction)((SAMLAction)i.next()).clone()).setParent(dup));

            dup.evidence = new ArrayList();
            for (Iterator i=evidence.iterator(); i.hasNext(); ) {
                Object o = i.next();
                if (o instanceof SAMLAssertion)
                    dup.evidence.add(((SAMLAssertion)((SAMLAssertion)o).clone()).setParent(dup));
                else if (o instanceof String)
                    dup.evidence.add(o);
            }
        }
        catch (SAMLException e) {
            throw new CloneNotSupportedException(e.getMessage());
        }

        return dup;
    }
}
