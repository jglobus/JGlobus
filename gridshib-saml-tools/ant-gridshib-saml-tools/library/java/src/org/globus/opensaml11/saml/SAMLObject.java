/*
 *  Copyright 2001-2005 Internet2
 *  Copyright 2005-2009 University of Illinois
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

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.apache.log4j.NDC;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

/**
 *  Abstract base class for all SAML constructs
 *
 * @author     Scott Cantor (created November 17, 2001)
 * @author     Tom Scavo
 */
public abstract class SAMLObject extends ObjectEquiv implements Cloneable
{
    /** OpenSAML configuration */
    protected SAMLConfig config = SAMLConfig.instance();

    /**  Root node of a DOM tree capturing the object */
    protected Node root = null;

    /** Class-specific logging object */
    protected Logger log = Logger.getLogger(this.getClass());

    /** Back pointer to SAML "parent" to allow back-walking and prevent double-containment */
    protected SAMLObject parentObject = null;

    /** Dirty bit triggers recreation of DOM */
    protected boolean dirty = true;

    /**
     *  Sets or clears the object's dirty bit. When set, serialization will flush
     *  an existing DOM. All parent objects will also be flagged.
     *
     * @param flag  The new value of the dirty bit
     */
    protected void setDirty(boolean flag) {
        dirty = flag;
        if (flag && parentObject != null)
            parentObject.setDirty(flag);
    }

    /**
     *  Allows parsing of objects from a stream of XML
     *
     * @param  in                   A stream containing XML
     * @return                      The root of the XML document instance
     * @exception  org.globus.opensaml11.saml.SAMLException  Raised if an exception occurs while constructing
     *                              the object
     */
    static protected Element fromStream(InputStream in) throws SAMLException {
        try
        {
            Document doc = XML.parserPool.parse(in);
            return doc.getDocumentElement();
        }
        catch (Exception e)
        {
            NDC.push("fromStream");
            Logger.getLogger(SAMLObject.class.getName()).error("caught an exception while parsing a stream:\n" + e.getMessage());
            NDC.pop();
            throw new MalformedException("SAMLObject.fromStream() caught exception while parsing a stream",e);
        }
    }

    /**
     *  Allows parsing of objects of a particular minor version from a stream of XML
     *
     * @param  in                   A stream containing XML
     * @param  minor                The minor version of the incoming object
     * @return                      The root of the XML document instance
     * @exception  org.globus.opensaml11.saml.SAMLException  Raised if an exception occurs while constructing
     *                              the object
     */
    static protected Element fromStream(InputStream in, int minor) throws SAMLException {
        try
        {
            Document doc = XML.parserPool.parse(
                new InputSource(in),
                (minor==1) ? XML.parserPool.getSchemaSAML11() : XML.parserPool.getSchemaSAML10()
                );
            return doc.getDocumentElement();
        }
        catch (Exception e)
        {
            NDC.push("fromStream");
            Logger.getLogger(SAMLObject.class.getName()).error("caught an exception while parsing a stream:\n" + e.getMessage());
            NDC.pop();
            throw new MalformedException("SAMLObject.fromStream() caught exception while parsing a stream",e);
        }
    }

    /**
     *  Installs the root node of this DOM as the document element
     *
     * @return    The root node so planted
     */
    protected Node plantRoot() {
        if (root!=null) {
            Node domroot=root;
            while (domroot.getParentNode()!=null && domroot.getParentNode().getNodeType() != Node.DOCUMENT_NODE)
                domroot=domroot.getParentNode();
            Element e=root.getOwnerDocument().getDocumentElement();
            if (e!=null && e!=domroot)
                root.getOwnerDocument().replaceChild(domroot,e);
            else if (e==null)
                root.getOwnerDocument().appendChild(domroot);
        }
        return root;
    }

    /**
     *  Delegates the process of building the root element of an object and
     *  inserting appropriate namespaces.
     *
     * @param doc       The document context to use
     * @param xmlns     Include namespace(s) on root element?
     * @return  A new root element for the object
     */
    protected abstract Element buildRoot(Document doc, boolean xmlns);

    /**
     *  Evaluates the object's content to see if it is currently valid if serialized.
     *  Does not evaluate embedded objects except on the basis of whether they exist.
     *  For example, an Assertion must have a Statement, but if an invalid statement
     *  is added, SAMLAssertion.checkValidity() would succeed, while SAMLStatement.checkValidity
     *  would raise an exception.
     *
     * @exception   org.globus.opensaml11.saml.SAMLException      Raised if the serialized object would be invalid SAML,
     *      excluding any embedded objects
     */
    public abstract void checkValidity() throws SAMLException;

    /**
     *  Informs the object that it is being inserted into a composite structure, allowing
     *  it to check for existing containment and throw an exception, preventing unexplained
     *  errors due to multiple object containment.
     *
     * @param parent    The object into which this object is being inserted
     * @return          A reference to the object being inserted (allows for cleaner insertion)
     * @throws org.globus.opensaml11.saml.SAMLException    Raised if this object already has a parent
     */
    public SAMLObject setParent(SAMLObject parent) throws SAMLException {
        if (parentObject != null)
            throw new SAMLException("SAMLObject.setParent() called on an already-contained object");
        if (parent == null)
            throw new IllegalArgumentException("SAMLObject.setParent() called with null parameter");
        parentObject = parent;
        return this;
    }

    /**
     *  Returns the containing object, if any. Multiple containment of a single object
     *  is prohibited! You must clone() to add an owned object to another parent.
     *
     * @return  The parent SAML object, or null if stand-alone
     */
    public SAMLObject getParent() {
        return parentObject;
    }

    /**
     *  Initialization of an object from a DOM element
     *
     * @param  e                   Root element of a DOM tree
     * @exception  org.globus.opensaml11.saml.SAMLException   Raised if an exception occurs while constructing
     *                              the object
     */
    public void fromDOM(Element e) throws SAMLException {
        if (e==null)
            throw new MalformedException("SAMLObject.fromDOM() given an empty DOM");
        root = e;
        setDirty(false);    // we have to be clean if we're starting from existing XML
    }

    /**
     *  Serializes the XML representation of the SAML object to a stream
     *
     * @param  out                      Stream to use for output
     * @exception  java.io.IOException  Raised if an I/O problem is detected
     * @exception  org.globus.opensaml11.saml.SAMLException Raised if the object is incompletely defined
     */
    public void toStream(OutputStream out) throws java.io.IOException, SAMLException {
        try
        {
            toDOM();
            plantRoot();
            Canonicalizer c = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            out.write(c.canonicalizeSubtree(root, config.getProperty("org.globus.opensaml11.saml.inclusive-namespace-prefixes")));
        }
        catch (InvalidCanonicalizerException e)
        {
            throw new java.io.IOException(e.getMessage());
        }
        catch (CanonicalizationException e)
        {
            throw new java.io.IOException(e.getMessage());
        }
    }

    /**
     *  Returns a base64-encoded XML representation of the SAML object
     *
     * @return                          A byte array containing the encoded data
     * @exception  java.io.IOException  Raised if an I/O problem is detected
     * @exception  org.globus.opensaml11.saml.SAMLException Raised if the object is incompletely defined
     */
    public byte[] toBase64() throws java.io.IOException, SAMLException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        toStream(out);
        return Base64.encodeBase64Chunked(out.toByteArray());
    }

    /**
     *  Transforms the object into a DOM tree using an existing document context
     *
     * @param  doc               A Document object to use in manufacturing the tree
     * @param  xmlns             Include namespace(s) on root element?
     * @return                   Root element node of the DOM tree capturing the object
     * @exception  org.globus.opensaml11.saml.SAMLException Raised if the object is incompletely defined
     */
    public Node toDOM(Document doc, boolean xmlns) throws SAMLException {
        checkValidity();
        if (root != null) {
            if (!dirty) {
                // If the DOM tree is already generated, compare the Documents.
                if (root.getOwnerDocument() != doc) {
                    // We already built a tree. Just adopt it into the new document.
                    return root = doc.adoptNode(root);
                }
                return root;
            }
            // Dirty, so we need a new root element.
            log.debug("toDOM() detected object changes, rebuilding tree");
        }
        return root = buildRoot(doc,xmlns);
    }

    /**
     *  Transforms the object into a DOM tree without an existing document context
     *
     * @param  xmlns             Include namespace(s) on root element?
     * @return                   Root element node of the DOM tree capturing the object
     * @exception  org.globus.opensaml11.saml.SAMLException Raised if the object is incompletely defined
     */
    public Node toDOM(boolean xmlns) throws SAMLException {
        // Reuse document if possible.
        if (root != null)
            return toDOM(root.getOwnerDocument(), xmlns);

        // No existing document object, so we have to create one.
        return toDOM(XML.parserPool.newDocument(), xmlns);
    }

    /**
     *  Transforms the object into a DOM tree using an existing document context,
     *  including namespace declarations
     *
     * @param  doc               A Document object to use in manufacturing the tree
     * @return                   Root element node of the DOM tree capturing the object
     * @exception  org.globus.opensaml11.saml.SAMLException Raised if the object is incompletely defined
     */
    public Node toDOM(Document doc) throws SAMLException {
        return toDOM(doc, true);
    }

    /**
     *  Transforms the object into a DOM tree without an existing document context,
     *  including namespace declarations
     *
     * @return                   Root element node of the DOM tree capturing the object
     * @exception  org.globus.opensaml11.saml.SAMLException Raised if the object is incompletely defined
     */
    public Node toDOM() throws SAMLException {
        return toDOM(true);
    }

    /**
     *  Copies a SAML object such that no dependencies exist between the original
     *  and the copy.
     *
     * @return      The new object
     * @see java.lang.Object#clone()
     */
    protected Object clone() throws CloneNotSupportedException {
        SAMLObject dup=(SAMLObject)super.clone();

        // Clear the DOM and parent before returning the copy.
        dup.root = null;
        dup.parentObject = null;
        dup.dirty = true;

        return dup;
    }

    /**
     *  Serializes a SAML object to a string in exclusive canonical form.
     *
     * @return      The canonicalized output
     * @see java.lang.Object#toString()
     */
    public String toString() {
        try
        {
            // We already support serialization to streams, but note that c14n XML is always in UTF-8.
            ByteArrayOutputStream os= new ByteArrayOutputStream();
            toStream(os);
            return os.toString("UTF8");
        }
        catch (java.io.IOException e)
        {
            NDC.push("toString");
            log.error("caught an I/O exception while serializing XML: " + e);
            NDC.pop();
            return "";
        }
        catch (SAMLException e)
        {
            NDC.push("toString");
            log.error("caught a SAML exception while serializing XML: " + e);
            NDC.pop();
            return "";
        }
    }

    /**
     * Gets the type of this object. By default, all SAML objects
     * belong to this type equivalence set.
     *
     * @return the type of this object.
     */
    protected Class getTypeEquiv() {
        return org.globus.opensaml11.saml.SAMLObject.class;
    }

    /**
     * Compares this object with the given object by invoking the
     * Object#equals method.
     *
     * @param obj the object with which to compare.
     * @return true if and only if the objects are equal.
     *
     * @see java.lang.Object#equals
     */
    protected boolean localEquals(Object obj) {
        //if (obj == null) {return false;}
        return (this == obj);
    }

}

