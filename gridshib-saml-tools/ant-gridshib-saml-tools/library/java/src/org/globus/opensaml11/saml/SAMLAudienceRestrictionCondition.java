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
 *  Represents a SAML AudienceRestrictionCondition
 *
 * @author     Scott Cantor (created March 30, 2002)
 */
public class SAMLAudienceRestrictionCondition extends SAMLCondition implements Cloneable
{
    protected ArrayList audiences = new ArrayList();

    /**
     *  Default constructor
     */
    public SAMLAudienceRestrictionCondition() {
    }

    /**
     *  Builds a condition out of its component parts
     *
     * @param  audiences          Array of audiences to embed in condition
     * @exception  SAMLException  Raised if a condition cannot be constructed
     *      from the supplied information
     */
    public SAMLAudienceRestrictionCondition(Collection audiences) throws SAMLException {
        if (audiences != null)
            this.audiences.addAll(audiences);
    }

    /**
     *  Reconstructs a condition from a DOM tree
     *
     * @param  e                  The root of a DOM tree
     * @exception  SAMLException  Thrown if the object cannot be constructed
     */
    public SAMLAudienceRestrictionCondition(Element e) throws SAMLException {
        fromDOM(e);
    }

    /**
     *  Reconstructs a condition from a stream
     *
     * @param  in                   A stream containing XML
     * @exception  SAMLException  Raised if an exception occurs while constructing
     *                              the object.
     */
    public SAMLAudienceRestrictionCondition(InputStream in) throws SAMLException {
        fromDOM(fromStream(in));
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#fromDOM(org.w3c.dom.Element)
     */
    public void fromDOM(Element e) throws SAMLException {
        super.fromDOM(e);

        if (config.getBooleanProperty("org.globus.opensaml11.saml.strict-dom-checking")) {
            if (!XML.isElementNamed(e,XML.SAML_NS,"AudienceRestrictionCondition")) {
                QName q = XML.getQNameAttribute(e, XML.XSI_NS, "type");
                if (!XML.isElementNamed(e,XML.SAML_NS,"Condition") || q == null ||
                    !XML.SAML_NS.equals(q.getNamespaceURI()) || !"AudienceRestrictionConditionType".equals(q.getLocalPart()))
                    throw new MalformedException(SAMLException.RESPONDER, "SAMLAudienceRestrictionCondition() requires saml:AudienceRestrictionCondition at root");
            }
        }

        // Extract audiences.
        Element aud = XML.getFirstChildElement(e);
        while (aud != null) {
            if (aud.hasChildNodes())
                audiences.add(aud.getFirstChild().getNodeValue());
            aud = XML.getNextSiblingElement(aud);
        }
        checkValidity();
    }

    /**
     *  Gets the audiences included in the condition
     *
     * @return The audiences in the condition
     */
    public Iterator getAudiences() {
        return audiences.iterator();
    }

    /**
     *  Sets the audiences to include in the condition
     *
     * @param   audiences   The audiences to include
     */
    public void setAudiences(Collection audiences) {
        this.audiences.clear();
        if (audiences != null)
            this.audiences.addAll(audiences);
        setDirty(true);
    }

    /**
     *  Adds an audience to the condition
     *
     * @param audience  The audience to add
     */
    public void addAudience(String audience) {
        if (!XML.isEmpty(audience)) {
            audiences.add(audience);
            setDirty(true);
        }
        else
            throw new IllegalArgumentException("audience cannot be null or empty");
    }

    /**
     *  Removes an audience by position (zero-based)
     *
     * @param   index   The position of the audience to remove
     */
    public void removeAudience(int index) {
        audiences.remove(index);
        setDirty(true);
    }

    /**
     *  @see org.globus.opensaml11.saml.SAMLObject#buildRoot(org.w3c.dom.Document,boolean)
     */
    protected Element buildRoot(Document doc, boolean xmlns) {
        Element c = doc.createElementNS(XML.SAML_NS, "AudienceRestrictionCondition");
        if (xmlns)
            c.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
        return c;
    }

    /**
     *  @see org.globus.opensaml11.saml.SAMLObject#toDOM(org.w3c.dom.Document,boolean)
     */
    public Node toDOM(Document doc, boolean xmlns) throws SAMLException {
        // Let the base build/verify the DOM root.
        super.toDOM(doc, xmlns);
        Element condition = (Element)root;

        if (dirty) {
            Iterator i=audiences.iterator();
            while (i.hasNext()) {
                String s = (String)i.next();
                if (!XML.isEmpty(s))
                    condition.appendChild(doc.createElementNS(XML.SAML_NS,"Audience")).appendChild(doc.createTextNode(s));
            }
            setDirty(false);
        }
        else if (xmlns) {
            condition.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
        }

        return root;
    }

    /**
     *  Evaluates the condition
     *
     * @param  audiences  A collection of audiences deemed acceptable by the evaluator
     * @return            Returns true iff the condition's audiences intersect
     *      with those of the evaluator
     */
    public boolean eval(Collection audiences) {
        if (audiences == null || audiences.size() == 0)
            return false;

        for (Iterator i=audiences.iterator(); i.hasNext();)
            if (this.audiences.contains(i.next()))
                return true;
        return false;
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#checkValidity()
     */
    public void checkValidity() throws SAMLException {
        if (audiences == null || audiences.size() == 0)
            throw new MalformedException(SAMLException.RESPONDER, "AudienceRestrictionCondition is invalid, requires at least one audience");

    }

    /**
     *  Copies a SAML object such that no dependencies exist between the original
     *  and the copy
     *
     * @return      The new object
     * @see Object#clone()
     */
    public Object clone() throws CloneNotSupportedException {
        SAMLAudienceRestrictionCondition dup=(SAMLAudienceRestrictionCondition)super.clone();
        dup.audiences=(ArrayList)audiences.clone();
        return dup;
    }
}

