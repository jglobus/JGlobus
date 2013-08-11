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
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.TimeZone;

import javax.xml.namespace.QName;

import org.globus.opensaml11.saml.artifact.Artifact;
import org.globus.opensaml11.saml.artifact.ArtifactParseException;
import org.globus.opensaml11.saml.artifact.ArtifactParserException;
import org.globus.opensaml11.saml.artifact.SAMLArtifact;
import org.w3c.dom.*;

/**
 *  Represents a SAML protocol request
 *
 * @author     Scott Cantor (created March 30, 2002)
 */
public class SAMLRequest extends SAMLSignedObject implements Cloneable
{
    protected int minor = config.getBooleanProperty("org.globus.opensaml11.saml.compatibility-mode") ? 0 : 1;
    protected String requestId = null;
    protected Date issueInstant = new Date();
    protected ArrayList respondWiths = new ArrayList();
    protected SAMLQuery query = null;
    protected ArrayList assertionIdRefs = new ArrayList();
    protected ArrayList artifacts = new ArrayList();

    /**
     *  Places the signature into the object's DOM to prepare for signing<p>

     * @throws org.globus.opensaml11.saml.SAMLException    Thrown if an error occurs while placing the signature
     */
    protected void insertSignature() throws SAMLException {
        // Goes after any RespondWith elements.
        Element n=XML.getFirstChildElement(root);
        while (n != null && XML.isElementNamed(n, XML.SAMLP_NS, "RespondWith"))
            n = XML.getNextSiblingElement(n);
        root.insertBefore(getSignatureElement(),n);
    }

    /**
     *  Default constructor
     */
    public SAMLRequest() {
    }

    /**
     *  Builds a SAML request using a query
     *
     * @param  query                A query to place in the request
     * @exception  org.globus.opensaml11.saml.SAMLException    Thrown if a request cannot be constructed from
     *      the supplied information
     */
    public SAMLRequest(SAMLQuery query)
        throws SAMLException {
        this(query,SAMLConfig.instance().getDefaultIDProvider().getIdentifier(),new Date());
    }

    /**
     *  Builds a SAML request using a query
     *
     * @param  query                A query to place in the request
     * @param  requestId        Unique identifier for request
     * @param  issueInstant       Time of issuance
     * @exception  org.globus.opensaml11.saml.SAMLException    Thrown if a request cannot be constructed from
     *      the supplied information
     */
    public SAMLRequest(SAMLQuery query, String requestId, Date issueInstant)
        throws SAMLException {
        this.requestId = XML.assign(requestId);
        this.issueInstant = issueInstant;
        if (query != null)
            this.query = (SAMLQuery)query.setParent(this);
    }

    /**
     *  Builds a SAML request using artifacts or assertion references
     *
     * @param  artifactsOrIdRefs      A collection of Artifacts or Strings (but not both)
     * @exception  org.globus.opensaml11.saml.SAMLException    Thrown if a request cannot be constructed from
     *      the supplied information
     */
    public SAMLRequest(Collection artifactsOrIdRefs)
        throws SAMLException {
        this(artifactsOrIdRefs,SAMLConfig.instance().getDefaultIDProvider().getIdentifier(),new Date());
    }

    /**
     *  Builds a SAML request using artifacts or assertion references
     *
     * @param  artifactsOrIdRefs      A collection of Artifacts or Strings (but not both)
     * @param  requestId        Unique identifier for request
     * @param  issueInstant       Time of issuance
     * @exception  org.globus.opensaml11.saml.SAMLException    Thrown if a request cannot be constructed from
     *      the supplied information
     */
    public SAMLRequest(Collection artifactsOrIdRefs, String requestId, Date issueInstant)
        throws SAMLException {
        this.requestId = XML.assign(requestId);
        this.issueInstant = issueInstant;
        if (artifactsOrIdRefs != null && !artifactsOrIdRefs.isEmpty()) {
            Iterator i = artifactsOrIdRefs.iterator();
            Object first = i.next();
            if (first instanceof Artifact) {
                artifacts.add(first);
                while (i.hasNext())
                    artifacts.add((Artifact)i.next());
            }
            else if (first instanceof String) {
                assertionIdRefs.add(first);
                while (i.hasNext())
                    assertionIdRefs.add((String)i.next());
            }
            else
                throw new MalformedException("SAMLRequest() collection parameter must contain Artifacts or Strings");
        }
    }

    /**
     *  Reconstructs a request from a DOM tree
     *
     * @param  e                  The root of a DOM tree
     * @exception  org.globus.opensaml11.saml.SAMLException  Thrown if the object cannot be constructed
     */
    public SAMLRequest(Element e) throws SAMLException {
        fromDOM(e);
    }

    /**
     *  Reconstructs a request from a stream
     *
     * @param  in                   A stream containing XML
     * @exception  org.globus.opensaml11.saml.SAMLException  Raised if an exception occurs while constructing
     *                              the object.
     */
    public SAMLRequest(InputStream in) throws SAMLException {
        fromDOM(fromStream(in));
    }

    /**
     *  Reconstructs a request of a particular minor version from a stream
     *
     * @param  in                   A stream containing XML
     * @param   minor               The minor version of the incoming request
     * @exception  org.globus.opensaml11.saml.SAMLException  Raised if an exception occurs while constructing
     *                              the object.
     */
    public SAMLRequest(InputStream in, int minor) throws SAMLException {
        fromDOM(fromStream(in,minor));
    }

    /**
     * @see SAMLObject#fromDOM(org.w3c.dom.Element)
     */
    public void fromDOM(Element e) throws SAMLException {
        super.fromDOM(e);

        if (config.getBooleanProperty("org.globus.opensaml11.saml.strict-dom-checking") && !XML.isElementNamed(e,XML.SAMLP_NS,"Request"))
            throw new MalformedException(SAMLException.RESPONDER,"SAMLRequest.fromDOM() requires samlp:Request at root");

        if (Integer.parseInt(e.getAttributeNS(null, "MajorVersion")) != 1)
            throw new MalformedException(SAMLException.VERSION, "SAMLRequest.fromDOM() detected incompatible request major version of " +
                e.getAttributeNS(null, "MajorVersion"));

        minor = Integer.parseInt(e.getAttributeNS(null, "MinorVersion"));
        requestId = XML.assign(e.getAttributeNS(null, "RequestID"));
        if (minor>0)
            e.setIdAttributeNode(e.getAttributeNodeNS(null, "RequestID"), true);

        try {
            SimpleDateFormat formatter = null;
            String dateTime = XML.assign(e.getAttributeNS(null, "IssueInstant"));
            int dot = dateTime.indexOf('.');
            if (dot > 0) {
                formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
            }
            else {
                formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            }
            formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
            issueInstant = formatter.parse(dateTime);
        }
        catch (java.text.ParseException ex) {
            throw new MalformedException(SAMLException.REQUESTER, "SAMLRequest.fromDOM() detected an invalid datetime while parsing request", ex);
        }

        // Process RespondWith elements.
        Element n = XML.getFirstChildElement(e);
        while (n != null && XML.isElementNamed(n, XML.SAMLP_NS, "RespondWith")) {
            respondWiths.add(XML.getQNameTextNode((Text)n.getFirstChild()));
            n = XML.getNextSiblingElement(n);
        }

        // Skip signature.
        if (XML.isElementNamed(n, XML.XMLSIG_NS, "Signature"))
            n = XML.getNextSiblingElement(n);

        // We're pointed at one of the request content options...
        if (XML.isElementNamed(n, XML.SAML_NS, "AssertionIDReference")) {
            while (n != null && n.hasChildNodes()) {
                assertionIdRefs.add(n.getFirstChild().getNodeValue());
                n = XML.getNextSiblingElement(n, XML.SAML_NS, "AssertionIDReference");
            }
        }
        else if (XML.isElementNamed(n, XML.SAMLP_NS, "AssertionArtifact")) {
            while (n != null && n.hasChildNodes()) {
                try {
                    artifacts.add(
                        SAMLArtifact.getTypeCode(n.getFirstChild().getNodeValue()).getParser().parse(
                            n.getFirstChild().getNodeValue()
                            )
                        );
                }
                catch (ArtifactParseException ex) {
                    throw new MalformedException(SAMLException.REQUESTER, "SAMLRequest.fromDOM() unable to parse artifact", ex);
                }
                catch (ArtifactParserException ex) {
                    throw new MalformedException(SAMLException.REQUESTER, "SAMLRequest.fromDOM() unable to parse artifact", ex);
                }
                n = XML.getNextSiblingElement(n, XML.SAMLP_NS, "AssertionArtifact");
            }
        }
        else {
            query = (SAMLQuery)SAMLQuery.getInstance(n).setParent(this);
        }

        checkValidity();
    }

    /**
     *  Gets the MinorVersion of the request.
     *
     * @return The minor version
     */
    public int getMinorVersion() {
        return minor;
    }

    /**
     *  Sets the MinorVersion of the request
     *
     * @param minor The minor version
     */
    public void setMinorVersion(int minor) {
        this.minor = minor;
        setDirty(true);
    }

    /**
     *  Gets the request ID
     *
     * @return    The request ID
     */
    public String getId() {
        return requestId;
    }

    /**
     *  Sets the request ID
     *
     *  <b>NOTE:</b> Use this method with caution. Requests must contain unique identifiers
     *  and only specialized applications should need to explicitly assign an identifier.
     *
     * @param   id    The request ID
     */
    public void setId(String id) {
        if (XML.isEmpty(id))
            throw new IllegalArgumentException("id cannot be null");
        requestId = XML.assign(id);
        setDirty(true);
    }

    /**
     *  Gets the issue timestamp of the request
     *
     * @return    The issue timestamp
     */
    public Date getIssueInstant() {
        return issueInstant;
    }

    /**
     *  Sets the issue timestamp of the request
     *
     * @param   issueInstant    The issue timestamp
     */
    public void setIssueInstant(Date issueInstant) {
        if (issueInstant == null)
            throw new IllegalArgumentException("issueInstant cannot be null");
        this.issueInstant = issueInstant;
        setDirty(true);
    }

    /**
     *  Gets the types of statements the requester is prepared to accept
     *
     * @return    An iterator of QNames representing statement types
     */
    public Iterator getRespondWiths() {
        return respondWiths.iterator();
    }

    /**
     *  Sets the types of statements the requester is prepared to accept
     *
     * @param   respondWiths    An iterator of QNames representing statement types
     */
    public void setRespondWiths(Collection respondWiths) {
        this.respondWiths.clear();
        if (respondWiths != null) {
            for (Iterator i = respondWiths.iterator(); i.hasNext(); )
                addRespondWith((QName)i.next());
        }
        setDirty(true);
    }

    /**
     *  Adds a statement type to the request
     *
     * @param respondWith     The type to add
     */
    public void addRespondWith(QName respondWith) {
        if (respondWith != null) {
            respondWiths.add(respondWith);
            setDirty(true);
        }
        else
            throw new IllegalArgumentException("respondWith cannot be null");
    }

    /**
     *  Removes a statement type by position (zero-based)
     *
     * @param   index   The position of the statement type to remove
     */
    public void removeRespondWith(int index) throws IndexOutOfBoundsException {
        respondWiths.remove(index);
        setDirty(true);
    }

    /**
     *  Gets the query contained within the request
     *
     * @return    The query in the request
     */
    public SAMLQuery getQuery() {
        return query;
    }

    /**
     *  Sets the query contained within the request
     *
     * @param query    The query for the request
     * @exception   org.globus.opensaml11.saml.SAMLException   Raised if the query is invalid
     */
    public void setQuery(SAMLQuery query) throws SAMLException {
        if (query != null) {
            query.setParent(this);
            setAssertionIdRefs(null);
            setArtifacts(null);
        }
        this.query = query;
        setDirty(true);
    }

    /**
     * Gets the assertion ID references contained within the request
     *
     * @return An iterator over the references
     */
    public Iterator getAssertionIdRefs() {
        return assertionIdRefs.iterator();
    }

    /**
     *  Adds an assertion ID reference to the request
     *
     * @param   ref     The reference to add
     */
    public void addAssertionIdRef(String ref) {
        if (XML.isEmpty(ref))
            throw new IllegalArgumentException("ref cannot be null or empty");
        try {
            setQuery(null);
        }
        catch (SAMLException e) {
        }
        setArtifacts(null);
        assertionIdRefs.add(ref);
    }

    /**
     *  Sets the assertion ID references contained within the request
     *
     * @param   refs    The references to include
     */
    public void setAssertionIdRefs(Collection refs) {
        this.assertionIdRefs.clear();
        if (refs != null) {
            for (Iterator i = refs.iterator(); i.hasNext(); )
                addAssertionIdRef((String)i.next());
        }
    }

    /**
     *  Removes an assertion reference by position (zero-based)
     *
     * @param   index   The position of the reference to remove
     */
    public void removeAssertionIdRef(int index) throws IndexOutOfBoundsException {
        assertionIdRefs.remove(index);
        setDirty(true);
    }

    /**
     * Gets the artifacts contained within the request
     *
     * @return An iterator over the artifacts
     */
    public Iterator getArtifacts() {
        return artifacts.iterator();
    }

    /**
     *  Sets the artifacts contained within the request
     *
     * @param   artifacts    The artifacts to include
     */
    public void setArtifacts(Collection artifacts) {
        this.artifacts.clear();
        if (artifacts != null) {
            for (Iterator i = artifacts.iterator(); i.hasNext(); )
                addArtifact((Artifact)i.next());
        }
    }

    /**
     *  Adds an artifact to the request
     *
     * @param   artifact     The artifact to add
     */
    public void addArtifact(Artifact artifact) {
        if (artifact == null)
            throw new IllegalArgumentException("artifact cannot be null or empty");
        try {
            setQuery(null);
        }
        catch (SAMLException e) {
        }
        setAssertionIdRefs(null);
        artifacts.add(artifact);
    }

    /**
     *  Removes an artifact by position (zero-based)
     *
     * @param   index   The position of the artifact to remove
     */
    public void removeArtifact(int index) throws IndexOutOfBoundsException {
        artifacts.remove(index);
        setDirty(true);
    }

    /**
     *  @see SAMLObject#buildRoot(org.w3c.dom.Document,boolean)
     */
    protected Element buildRoot(Document doc, boolean xmlns) {
        Element r = doc.createElementNS(XML.SAMLP_NS, "Request");
        if (xmlns) {
            r.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAMLP_NS);
            r.setAttributeNS(XML.XMLNS_NS, "xmlns:saml", XML.SAML_NS);
            r.setAttributeNS(XML.XMLNS_NS, "xmlns:samlp", XML.SAMLP_NS);
            r.setAttributeNS(XML.XMLNS_NS, "xmlns:xsi", XML.XSI_NS);
            r.setAttributeNS(XML.XMLNS_NS, "xmlns:xsd", XML.XSD_NS);
        }
        return r;
    }

    /**
     *  @see SAMLObject#toDOM(org.w3c.dom.Document,boolean)
     */
    public Node toDOM(Document doc, boolean xmlns) throws SAMLException {
        // Let the base build/verify the DOM root.
        super.toDOM(doc, xmlns);
        Element r = (Element)root;

        if (dirty) {
            if (requestId == null)
                requestId = config.getDefaultIDProvider().getIdentifier();

            if (issueInstant == null)
                issueInstant = new Date();

            r.setAttributeNS(null, "MajorVersion", "1");
            r.setAttributeNS(null, "MinorVersion", String.valueOf(minor));
            r.setAttributeNS(null, "RequestID", requestId);
            if (minor > 0)
                r.setIdAttributeNS(null, "RequestID", true);

            SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
            formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
            r.setAttributeNS(null, "IssueInstant", formatter.format(issueInstant));

            Iterator i=respondWiths.iterator();
            while (i.hasNext()) {
                QName qn=(QName)i.next();
                Element rw = doc.createElementNS(XML.SAMLP_NS, "RespondWith");
                String rwns = qn.getNamespaceURI();
                if (rwns==null)
                    rwns="";
                if (!XML.SAML_NS.equals(rwns)) {
                    rw.setAttributeNS(XML.XMLNS_NS, "xmlns:rw", rwns);
                    rwns="rw:";
                }
                else
                    rwns="saml:";
                rw.appendChild(doc.createTextNode(rwns + qn.getLocalPart()));
                r.appendChild(rw);
            }

            if (query != null)
                r.appendChild(query.toDOM(doc, false));
            else if (assertionIdRefs.size() > 0) {
                i=assertionIdRefs.iterator();
                while (i.hasNext())
                    r.appendChild(doc.createElementNS(XML.SAML_NS,"saml:AssertionIDReference")).appendChild(doc.createTextNode((String)i.next()));
            }
            else {
                i=artifacts.iterator();
                while (i.hasNext()) {
                    r.appendChild(
                        doc.createElementNS(XML.SAMLP_NS,"AssertionArtifact")).appendChild(doc.createTextNode(((Artifact)i.next()).encode())
                        );
                }
            }

            setDirty(false);
        }
        else if (xmlns) {
            ((Element)root).setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAMLP_NS);
            ((Element)root).setAttributeNS(XML.XMLNS_NS, "xmlns:saml", XML.SAML_NS);
            ((Element)root).setAttributeNS(XML.XMLNS_NS, "xmlns:samlp", XML.SAMLP_NS);
            ((Element)root).setAttributeNS(XML.XMLNS_NS, "xmlns:xsi", XML.XSI_NS);
            ((Element)root).setAttributeNS(XML.XMLNS_NS, "xmlns:xsd", XML.XSD_NS);
        }

        return root;
    }

    /**
     * @see SAMLObject#checkValidity()
     */
    public void checkValidity() throws SAMLException {
        if (requestId == null || (query == null && assertionIdRefs.size() == 0 && artifacts.size() == 0))
            throw new MalformedException("Request is invalid, must have an ID and query, assertion references, or artifacts");
    }

    /**
     *  Copies a SAML object such that no dependencies exist between the original
     *  and the copy
     *
     * @return      The new object
     * @see Object#clone()
     */
    public Object clone() throws CloneNotSupportedException {
        SAMLRequest dup=(SAMLRequest)super.clone();

        try {
            dup.respondWiths = (ArrayList)respondWiths.clone();
            dup.query = (SAMLQuery)((SAMLQuery)query.clone()).setParent(dup);
            dup.assertionIdRefs = (ArrayList)assertionIdRefs.clone();
            dup.artifacts = new ArrayList();
            for (Iterator i=artifacts.iterator(); i.hasNext();) {
                String a = ((Artifact)i.next()).encode();;
                try {
                    dup.artifacts.add(SAMLArtifact.getTypeCode(a).getParser().parse(a));
                }
                catch (ArtifactParseException e) {
                    throw new RuntimeException("Unable to clone artifact");
                }
                catch (ArtifactParserException e) {
                    throw new RuntimeException("Unable to clone artifact");
                }
            }
        }
        catch (SAMLException e) {
            throw new CloneNotSupportedException(e.getMessage());
        }

        return dup;
    }
}

