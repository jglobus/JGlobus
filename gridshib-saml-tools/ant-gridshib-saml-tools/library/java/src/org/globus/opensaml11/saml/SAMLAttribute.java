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

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.util.Collection;
import java.util.Iterator;
import java.util.ArrayList;

import javax.xml.namespace.QName;

import org.apache.log4j.Category;
import org.apache.log4j.Logger;
import org.apache.log4j.NDC;
import org.w3c.dom.*;
import org.xml.sax.SAXException;

/**
 *  Basic SAML Attribute implementation that handles rudimentary attribute value
 *  types
 *
 * @author     Scott Cantor (created May 9, 2002)
 * @author     Tom Scavo
 */
public class SAMLAttribute extends SAMLObject implements Cloneable
{
    private static Logger log =
        Logger.getLogger(SAMLAttribute.class.getName());

    /**  Custom implementation hook for building attributes. */
    private static String factoryClass = null;

    /**
     *  Registers a class name to handle SAML attribute construction from XML
     *
     * @param className     The Java class to register
     */
    public static synchronized String setFactory(String className) {
        String temp = factoryClass;
        factoryClass = className;
        return temp;
    }

    /**
     *  Obtains a class name to handle SAML attribute construction from XML
     */
    public static synchronized String getFactory() {
        return factoryClass;
    }

    /**
     *  Locates an implementation class for an attribute and constructs it based
     *  on the DOM provided.
     *
     * @param e     The root of a DOM containing the SAML attribute
     * @return SAMLAttribute    A constructed attribute object
     *
     * @throws SAMLException    Thrown if an error occurs while constructing the object
     */
    public static SAMLAttribute getInstance(Element e) throws SAMLException {
        if (e == null)
            throw new MalformedException(SAMLException.RESPONDER, "SAMLAttribute.getInstance() given an empty DOM");

        // Look for a custom factory. If not, use the default class (this one).
        String className = getFactory();
        if (className == null)
            return new SAMLAttribute(e);
        try {
            Class implementation = Class.forName(className);
            Class[] paramtypes = {Element.class};
            Object[] params = {e};
            Constructor ctor = implementation.getDeclaredConstructor(paramtypes);
            return (SAMLAttribute)ctor.newInstance(params);
        }
        catch (ClassNotFoundException ex) {
            throw new SAMLException(SAMLException.REQUESTER, "SAMLAttribute.getInstance() unable to locate attribute factory class (" + className + ")", ex);
        }
        catch (NoSuchMethodException ex) {
            throw new SAMLException(SAMLException.REQUESTER, "SAMLAttribute.getInstance() unable to bind to constructor for attribute", ex);
        }
        catch (InstantiationException ex) {
            throw new SAMLException(SAMLException.REQUESTER, "SAMLAttribute.getInstance() unable to build implementation object for attribute", ex);
        }
        catch (IllegalAccessException ex) {
            throw new SAMLException(SAMLException.REQUESTER, "SAMLAttribute.getInstance() unable to access attribute factory", ex);
        }
        catch (java.lang.reflect.InvocationTargetException ex) {
            ex.printStackTrace();
            Throwable e2 = ex.getTargetException();
            if (e2 instanceof SAMLException)
                throw (SAMLException)e2;
            else
                throw new SAMLException(SAMLException.REQUESTER, "SAMLAttribute.getInstance() caught unknown exception while building attribute object: " + e2.getMessage());
        }
    }

    /**
     *  Locates an implementation class for an attribute and constructs it based
     *  on the stream provided.
     *
     * @param in     The stream to deserialize from
     * @return SAMLAttribute    A constructed attribute object
     *
     * @throws SAMLException    Thrown if an error occurs while constructing the object
     */
    public static SAMLAttribute getInstance(InputStream in) throws SAMLException {
        try {
            Document doc = XML.parserPool.parse(in);
            return getInstance(doc.getDocumentElement());
        }
        catch (SAXException e) {
            NDC.push("getInstance");
            Category.getInstance("SAMLAttribute").error("caught an exception while parsing a stream:\n" + e.getMessage());
            NDC.pop();
            throw new MalformedException("SAMLAttribute.getInstance() caught exception while parsing a stream",e);
        }
        catch (IOException e) {
            NDC.push("getInstance");
            Category.getInstance("SAMLAttribute").error("caught an exception while parsing a stream:\n" + e.getMessage());
            NDC.pop();
            throw new MalformedException("SAMLAttribute.getInstance() caught exception while parsing a stream",e);
        }
    }

    /**  Name of attribute */
    protected String name = null;

    /**  Namespace/qualifier of attribute */
    protected String namespace = null;

    /**  The schema type of attribute value(s) */
    protected QName type = null;

    /**  Effective lifetime of attribute's value(s) in seconds (0 means infinite) */
    protected long lifetime = 0;

    /**  An array of attribute values */
    protected ArrayList values = new ArrayList();

    /**
     *  Default constructor
     */
    public SAMLAttribute() {
    }

    /**
     *  Builds an Attribute out of its component parts
     *
     * @param  name               Name of attribute
     * @param  namespace          Namespace/qualifier of attribute
     * @param  type               The schema type of attribute value(s)
     * @param  lifetime           Effective lifetime of attribute's value(s) in
     *      seconds (0 means infinite)
     * @param  values             An array of attribute values
     * @exception  SAMLException  Thrown if attribute cannot be built from the
     *      supplied information
     */
    public SAMLAttribute(String name, String namespace, QName type, long lifetime, Collection values) throws SAMLException {
        this.name = XML.assign(name);
        this.namespace = XML.assign(namespace);
        this.type = type;
        this.lifetime = lifetime;

        if (values != null)
            this.values.addAll(values);
    }

    /**
     *  Reconstructs an attribute from a DOM tree
     *
     * @param  e                  The root of a DOM tree
     * @exception  SAMLException  Thrown if the object cannot be constructed
     */
    public SAMLAttribute(Element e) throws SAMLException {
        fromDOM(e);
    }

    /**
     *  Reconstructs an attribute from a stream
     *
     * @param  in                   A stream containing XML
     * @exception  SAMLException  Raised if an exception occurs while constructing
     *                              the object.
     */
    public SAMLAttribute(InputStream in) throws SAMLException {
        fromDOM(fromStream(in));
    }

    /**
     *  Initialization of attribute from a DOM element.<P>
     *
     *  Checks the attribute's syntactic validity. An exception
     *  is thrown if any problems are detected. The exception will contain a
     *  message describing the problem, and may wrap another exception.<P>
     *
     *  Because attributes are generalized, this base method only handles
     *  attributes whose values are of uniform schema type. The
     *  attribute's schema type is set by the first xsi:type attribute found in
     *  the value list, if any.<P>
     *
     *  The addValue method is used to actually process the values, and can be
     *  overridden to handle more complex values
     *
     * @param  e                   Root element of a DOM tree
     * @exception  SAMLException   Raised if an exception occurs while constructing the object.
     */
    public void fromDOM(Element e) throws SAMLException {
        super.fromDOM(e);

        if (config.getBooleanProperty("org.globus.opensaml11.saml.strict-dom-checking") && !XML.isElementNamed(e,XML.SAML_NS,"Attribute"))
            throw new MalformedException("SAMLAttribute.fromDOM() requires saml:Attribute at root");

        name = XML.assign(e.getAttributeNS(null, "AttributeName"));
        namespace = XML.assign(e.getAttributeNS(null, "AttributeNamespace"));

        // Iterate over AttributeValues.
        Element n = XML.getFirstChildElement(e, XML.SAML_NS, "AttributeValue");
        while (n != null) {
            if (type == null)
                type = XML.getQNameAttribute(n, XML.XSI_NS, "type");

            valueFromDOM(n);

            n = XML.getNextSiblingElement(n);
        }

        checkValidity();
    }

    /**
     *  Creates the internal representation of an attribute value from the specified element.<P>
     *
     *  The base implementation handles simple string values by extracting a single Text node.
     *  Override this method in your subclass to perform more advanced processing.
     *
     * @param e         The AttributeValue element to read from
     * @exception   SAMLException   Raised if an error occurs while parsing the DOM
     */
    protected void valueFromDOM(Element e) throws SAMLException {
        Node val = e.getFirstChild();
        if (val != null && val.getNodeType() == Node.TEXT_NODE)
            values.add(val.getNodeValue());
        else if (val == null)
            values.add("");
        else {
            values.add("");
            log.warn("skipping AttributeValue element without a simple text node");
        }
    }


    /**
     *  Gets the AttributeName attribute of the SAML Attribute
     *
     * @return    The name value
     */
    public String getName() {
        return name;
    }

    /**
     *  Sets the AttributeName attribute of the SAML Attribute
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
     *  Gets the AttributeNamespace attribute of the SAML Attribute
     *
     * @return    The namespace value
     */
    public String getNamespace() {
        return namespace;
    }

    /**
     *  Sets the AttributeNamespace attribute of the SAML Attribute
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
     *  Gets the value of the xsi:type attribute, if any, of the SAML Attribute
     *
     * @return    The schema type value
     */
    public QName getType() {
        return type;
    }

    /**
     *  Sets the value of the xsi:type attribute, if any, of the SAML Attribute
     *
     * @param   type    The schema type value
     */
    public void setType(QName type) {
        this.type = type;
        setDirty(true);
    }

    /**
     *  Gets the value's lifetime, in seconds
     *
     * @return    The effective lifetime of the attribute value, in seconds (0
     *      means infinite)
     */
    public long getLifetime() {
        return lifetime;
    }

    /**
     *  Sets the value's lifetime, in seconds
     *
     * @param   lifetime    The effective lifetime of the attribute value, in seconds (0
     *      means infinite)
     */
    public void setLifetime(long lifetime) {
        this.lifetime = lifetime;
    }

    /**
     *  Gets the values of the SAML Attribute
     *
     * @return    An iterator over the values
     */
    public Iterator getValues() {
        return values.iterator();
    }

    /**
     *  Gets the set of existing AttributeValue elements, if the DOM exists.
     *
     * @return A NodeList containing the elements, or null
     */
    public NodeList getValueElements() {
        return (!dirty && root != null) ? ((Element)root).getElementsByTagNameNS(XML.SAML_NS,"AttributeValue") : null;
    }

    /**
     *  Sets the values of the attribute
     *
     * @param values    The values to use
     * @throws SAMLException    Raised if the value cannot be added to the attribute
     */
    public void setValues(Collection values) throws SAMLException {
        this.values.clear();
        if (values != null) {
            this.values.addAll(values);
        }
        setDirty(true);
    }

    /**
     *  Adds a value to the attribute
     *
     * @param value     The value to add
     * @exception   SAMLException   Raised if the value cannot be properly added
     */
    public void addValue(Object value) throws SAMLException {
        if (value != null)
            values.add(value);
        else
            values.add("");
        setDirty(true);
    }

    /**
     *  Removes a value by position (zero-based)
     *
     * @param   index   The position of the value to remove
     */
    public void removeValue(int index) throws IndexOutOfBoundsException {
        values.remove(index);
        setDirty(true);
    }

    /**
     *  Computes the xsi:type attribute on each AttributeValue element with any supporting
     *  declarations created.
     *
     * @param e     The root element of the attribute
     * @return      The xsi:type value to use
     */
    protected String computeTypeDecl(Element e) {
        String xsitype = null;
        e.removeAttributeNS(XML.XMLNS_NS, "xmlns:typens");
        if (type != null) {
            String prefix;
            if (XML.XSD_NS.equals(type.getNamespaceURI())) {
                prefix = "xsd";
            }
            else {
                e.setAttributeNS(XML.XMLNS_NS, "xmlns:typens", type.getNamespaceURI());
                prefix = "typens";
            }
            xsitype = prefix + ":" + type.getLocalPart();
        }
        return xsitype;
    }

    /**
     *  @see org.globus.opensaml11.saml.SAMLObject#buildRoot(org.w3c.dom.Document,boolean)
     */
    protected Element buildRoot(Document doc, boolean xmlns) {
        Element a = doc.createElementNS(XML.SAML_NS, "Attribute");
        if (xmlns)
            a.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
        a.setAttributeNS(XML.XMLNS_NS, "xmlns:xsd", XML.XSD_NS);
        a.setAttributeNS(XML.XMLNS_NS, "xmlns:xsi", XML.XSI_NS);
        return a;
    }

    /**
     *  Creates the DOM representation of an attribute value in the specified element.<P>
     *
     *  The base implementation handles string values by creating a single Text node.
     *  Override this method in your subclass to perform more advanced processing.
     *
     * @param index     The position of the attribute value to DOM-ify
     * @param e         The AttributeValue element to write into
     * @exception   SAMLException   Raised if an error occurs while creating the DOM
     */
    protected void valueToDOM(int index, Element e) throws SAMLException {
        String val = values.get(index).toString();
        if (!XML.isEmpty(val))
            e.appendChild(e.getOwnerDocument().createTextNode(val));
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

            String xsitype = computeTypeDecl(a);

            for (int i = 0; i < values.size(); i++) {
                Element v = doc.createElementNS(XML.SAML_NS, "AttributeValue");
                if (xsitype != null)
                    v.setAttributeNS(XML.XSI_NS, "xsi:type", xsitype);
                valueToDOM(i, v);
                a.appendChild(v);
            }
            setDirty(false);
        }
        else if (xmlns) {
            a.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
            a.setAttributeNS(XML.XMLNS_NS, "xmlns:xsi", XML.XSI_NS);
            a.setAttributeNS(XML.XMLNS_NS, "xmlns:xsd", XML.XSD_NS);
        }
        return root;
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#checkValidity()
     */
    public void checkValidity() throws SAMLException {
        if (XML.isEmpty(name) || XML.isEmpty(namespace) || values.size() == 0)
            throw new MalformedException(SAMLException.RESPONDER, "Attribute invalid, requires name and namespace, and at least one value");
    }

    /**
     *  Copies a SAML object such that no dependencies exist between the original
     *  and the copy. Does not clone values.
     *
     * @return      The new object
     * @see Object#clone()
     */
    public Object clone() throws CloneNotSupportedException {
        SAMLAttribute dup=(SAMLAttribute)super.clone();

        dup.values = (ArrayList)values.clone();

        return dup;
    }

    /**
     * Gets the type of this object.
     * <p>
     * This implementation intentionally does not return
     * this.getClass().  Consequently, subclasses are encouraged
     * to inherit this method and thereby become type equivalent
     * to this class.
     *
     * @return the type of this object.
     *
     * @see org.globus.opensaml11.saml.SAMLObject#getTypeEquiv()
     */
    protected Class getTypeEquiv() {
        return org.globus.opensaml11.saml.SAMLAttribute.class;
    }

    /**
     * Compares this object with the given object. Two
     * <code>SAMLAttribute</code> objects are equal if and only
     * if their component parts are equal.
     *
     * @param obj the object with which to compare.
     * @return true if and only if the objects are equal,
     *         that is, component-wise equal.
     *
     * @see org.globus.opensaml11.saml.SAMLObject#localEquals(Object)
     */
    protected boolean localEquals(Object obj) {

        // type checking occurs in the calling method:
        SAMLAttribute attribute = (SAMLAttribute)obj;

        if (!XML.safeCompare(attribute.name, this.name) ||
            !XML.safeCompare(attribute.namespace, this.namespace)) {
            return false;
        }

        // do the values play any part in the equivalence relation?

        return true;
    }

    /**
     * Compares the values of this object with the values of the
     * given object.  This method returns true if and only if
     * the two objects have the same values.
     *
     * @param obj the object whose values will be compared
     *        to the values of this object
     * @return true if and only if the values associated
     *         with the two objects are equal
     */
    public boolean hasEqualValues(Object obj) {

        if (this == obj) return true;
        if (!(obj instanceof SAMLAttribute)) return false;

        SAMLAttribute attribute = (SAMLAttribute)obj;
        if (attribute.values.equals(this.values)) return true;

        return false;
    }

    /**
     * Compute the hash code of this <code>SAMLAttribute</saml> object.
     *
     * @return the computed hash code.
     *
     * @see org.globus.opensaml11.saml.SAMLObject#hashCode()
     */
    public int hashCode() {

        int code = ((this.name == null) ? 0 : this.name.hashCode());
        code &= ((this.namespace == null) ? 0 : this.namespace.hashCode());

        // do the values play any part in the computation of hashCode?

        return code;
    }
}
