/*
 * Copyright 2006-2009 University of Illinois
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.globus.opensaml11.saml;

import java.io.InputStream;

import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.w3c.dom.*;

/**
 * A concrete implementation of <code>SAMLSubjectStatement</code>
 * with no content.
 *
 * @author     Tom Scavo
 */
public class SubjectStatement extends SAMLSubjectStatement
                           implements Cloneable {

    private static Logger log =
        Logger.getLogger(SubjectStatement.class.getName());

    public final static String XSI_TYPE =
        XML.SAMLSAP_NS_PREFIX + ":" + XML.SAMLSAP_TYPE_NAME;

    /**
     * Default constructor
     */
    public SubjectStatement() {}

    /**
     * Builds a subject statement out of its component parts
     * (i.e., a subject).
     *
     * @param  subject            Subject of statement
     * @exception  org.globus.opensaml11.saml.SAMLException
     *             Thrown if a statement cannot be
     *             constructed from the supplied information
     */
    public SubjectStatement(SAMLSubject subject) throws SAMLException {
        super(subject);
    }

    /**
     * Reconstructs a subject statement from a DOM tree
     *
     * @param  e                  The root of a DOM tree
     * @exception  org.globus.opensaml11.saml.SAMLException
     *             Thrown if a statement cannot be constructed
     */
    public SubjectStatement(Element e) throws SAMLException {
        fromDOM(e);
    }

    /**
     * Reconstructs a subject statement from a stream
     *
     * @param  in                 A stream containing XML
     * @exception  org.globus.opensaml11.saml.SAMLException
     *             Thrown if a statement cannot be constructed
     */
    public SubjectStatement(InputStream in) throws SAMLException {
        fromDOM(fromStream(in));
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#fromDOM(org.w3c.dom.Element)
     */
    public void fromDOM(Element e) throws SAMLException {
        super.fromDOM(e);

        String propName = "org.globus.opensaml11.saml.strict-dom-checking";
        if (config.getBooleanProperty(propName) &&
            !XML.isElementNamed(e,XML.SAML_NS,"SubjectStatement")) {
            QName q = XML.getQNameAttribute(e, XML.XSI_NS, "type");
            if (!(XML.isElementNamed(e,XML.SAML_NS,"Statement") ||
                XML.isElementNamed(e,XML.SAML_NS,"SubjectStatement")) ||
                q == null || !XML.SAMLSAP_NS.equals(q.getNamespaceURI()) ||
                !XML.SAMLSAP_TYPE_NAME.equals(q.getLocalPart())) {
                String msg = "SubjectStatement() requires saml:SubjectStatement at root";
                throw new MalformedException(SAMLException.REQUESTER, msg);
            }
        }

        checkValidity();
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#buildRoot(org.w3c.dom.Document,boolean)
     */
    protected Element buildRoot(Document doc, boolean xmlns) {

        Element s = doc.createElementNS(XML.SAML_NS, "SubjectStatement");
        if (xmlns) {
            s.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
            s.setAttributeNS(XML.XMLNS_NS, "xmlns:xsd", XML.XSD_NS);
            s.setAttributeNS(XML.XMLNS_NS, "xmlns:xsi", XML.XSI_NS);
        }
        s.setAttributeNS(XML.XMLNS_NS, "xmlns:" + XML.SAMLSAP_NS_PREFIX, XML.SAMLSAP_NS);
        s.setAttributeNS(XML.XSI_NS, "xsi:type", XSI_TYPE);
        return s;
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#toDOM(org.w3c.dom.Document,boolean)
     */
    public Node toDOM(Document doc, boolean xmlns) throws SAMLException {
        // Let the base build/verify the DOM root.
        super.toDOM(doc, xmlns);

        Element s = (Element) root;
        if (dirty) {
            setDirty(false);
        } else if (xmlns) {
            s.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
            s.setAttributeNS(XML.XMLNS_NS, "xmlns:xsd", XML.XSD_NS);
            s.setAttributeNS(XML.XMLNS_NS, "xmlns:xsi", XML.XSI_NS);
        }

        return root;
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#checkValidity()
     */
    public void checkValidity() throws SAMLException {
        super.checkValidity();
    }

    /**
     * Copies a SAML object such that no dependencies exist between
     * the original and the copy
     *
     * @return      The new object
     * @see org.globus.opensaml11.saml.SAMLObject#clone()
     */
    public Object clone() throws CloneNotSupportedException {
        return (SubjectStatement) super.clone();
    }

}