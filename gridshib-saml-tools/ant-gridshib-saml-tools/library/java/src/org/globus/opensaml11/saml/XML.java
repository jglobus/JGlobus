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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Stack;
import java.util.Map.Entry;

import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Source;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;
import org.xml.sax.EntityResolver;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 *  Utility classes for XML constants and optimizations
 *
 * @author     Scott Cantor (created January 2, 2002)
 * @author     Howard Gilbert
 */
public class XML
{
    /** OpenSAML configuration */
    protected SAMLConfig config = SAMLConfig.instance();

    /**  XML core namespace */
    public final static String XML_NS = "http://www.w3.org/XML/1998/namespace";

    /**  XML namespace for xmlns attributes */
    public final static String XMLNS_NS = "http://www.w3.org/2000/xmlns/";

    /**  XML Schema Instance namespace */
    public final static String XSI_NS = "http://www.w3.org/2001/XMLSchema-instance";

    /**  XML Schema Instance namespace */
    public final static String XSD_NS = "http://www.w3.org/2001/XMLSchema";

    /**  OpenSAML XML namespace */
    public final static String OPENSAML_NS = "http://www.saml.org";

    /**  SAML XML namespace */
    public final static String SAML_NS = "urn:oasis:names:tc:SAML:1.0:assertion";

    /**  SAML protocol XML namespace */
    public final static String SAMLP_NS = "urn:oasis:names:tc:SAML:1.0:protocol";

    /**  SAML 1.1 subject-based assertion profile namespace, prefix, and type name */
    public final static String SAMLSAP_NS =
        "urn:oasis:names:tc:SAML:1.1:profiles:assertion:subject";
    public final static String SAMLSAP_NS_PREFIX = "samlsap";
    public final static String SAMLSAP_TYPE_NAME = "SubjectStatementType";

    /**  SAML 1.x Metadata Profile protocol indicators and namespace */
    public final static String SAML10_PROTOCOL_ENUM = SAMLP_NS;
    public final static String SAML11_PROTOCOL_ENUM = "urn:oasis:names:tc:SAML:1.1:protocol";
    public final static String SAML_ARTIFACT_SOURCEID = "urn:oasis:names:tc:SAML:profiles:v1metadata";

    /**  XML Signature namespace */
    public final static String XMLSIG_NS = "http://www.w3.org/2000/09/xmldsig#";

    /**  SOAP 1.1 Envelope XML namespace */
    public final static String SOAP11ENV_NS = "http://schemas.xmlsoap.org/soap/envelope/";

    /**  XML core schema identifier */
    public final static String XML_SCHEMA_ID = "xml.xsd";

    /**  SAML XML Schema Identifier */
    public final static String SAML_SCHEMA_ID = "cs-sstc-schema-assertion-01.xsd";

    /**  SAML protocol XML Schema Identifier */
    public final static String SAMLP_SCHEMA_ID = "cs-sstc-schema-protocol-01.xsd";

    /**  SAML 1.1 XML Schema Identifier */
    public final static String SAML11_SCHEMA_ID = "cs-sstc-schema-assertion-1.1.xsd";

    /**  SAML 1.1 protocol XML Schema Identifier */
    public final static String SAMLP11_SCHEMA_ID = "cs-sstc-schema-protocol-1.1.xsd";

    /**  SAML 1.1 subject-based assertion profile XML Schema Identifier */
    public final static String SAMLSAP_SCHEMA_ID =
        "sstc-saml1-profiles-assertion-subject.xsd";

    /**  Shibboleth XML Schema Identifier */
    public final static String SHIBBOLETH_SCHEMA_ID = "shibboleth.xsd";

    /**  XML Signature Schema Identifier */
    public final static String XMLSIG_SCHEMA_ID = "xmldsig-core-schema.xsd";

    /**  SOAP 1.1 Envelope Schema Identifier */
    public final static String SOAP11ENV_SCHEMA_ID = "soap-envelope.xsd";

    private static Logger log = Logger.getLogger(XML.class.getName());

    /**  A global object to manage a pool of custom DOM parsers */
    public static ParserPool parserPool = new ParserPool();

    /**
     *  A "safe" null/empty check for strings.
     *
     * @param s     The string to check
     * @return  true iff the string is null or length zero
     */
    public static boolean isEmpty(String s) {
        return (s==null || s.length() == 0);
    }

    /**
     *  A "safe" assignment function for strings that blocks the empty string
     *
     * @param s     The string to check
     * @return  s iff the string is non-empty or else null
     */
    public static String assign(String s) {
        return (s != null && s.length() > 0) ? s.trim() : null;
    }

    /**
     *  Compares two strings for equality, allowing for nulls
     *
     * @param s1    The first operand
     * @param s2    The second operand
     *
     * @return  true iff both are null or both are non-null and the same strng value
     */
    public static boolean safeCompare(String s1, String s2) {
        if (s1 == null || s2 == null)
            return s1 == s2;
        else
            return s1.equals(s2);
    }

    /**
     *  Shortcut for checking a DOM element node's namespace and local name
     *
     * @param  e            An element to compare against
     * @param  ns           An XML namespace to compare
     * @param  localName    A local name to compare
     * @return              true iff the element's local name and namespace match the
     *                          parameters
     */
    public static boolean isElementNamed(Element e, String ns, String localName) {
        return (e != null && safeCompare(ns, e.getNamespaceURI()) && safeCompare(localName, e.getLocalName()));
    }

    /**
     *  Gets the first child Element of the node, skipping any Text nodes such as whitespace.
     *
     * @param n     The parent in which to search for children
     * @return      The first child Element of n, or null if none
     */
    public static Element getFirstChildElement(Node n) {
        Node child = n.getFirstChild();
        while (child != null && child.getNodeType() != Node.ELEMENT_NODE)
            child = child.getNextSibling();
        if (child != null)
            return (Element)child;
        else
            return null;
    }

    /**
     *  Gets the last child Element of the node, skipping any Text nodes such as whitespace.
     *
     * @param n     The parent in which to search for children
     * @return      The last child Element of n, or null if none
     */
    public static Element getLastChildElement(Node n) {
        Node child = n.getLastChild();
        while (child != null && child.getNodeType() != Node.ELEMENT_NODE)
            child = child.getPreviousSibling();
        if (child != null)
            return (Element)child;
        else
            return null;
    }

    /**
     *  Gets the first child Element of the node of the given name,
     *  skipping any Text nodes such as whitespace.
     *
     * @param n     The parent in which to search for children
     * @param ns    The namespace URI of the element to locate
     * @param localName     The local name of the element to locate
     * @return      The first child Element of n with the specified name, or null if none
     */
    public static Element getFirstChildElement(Node n, String ns, String localName) {
        Element e = getFirstChildElement(n);
        while (e != null && !isElementNamed(e, ns, localName))
            e = getNextSiblingElement(e);
        return e;
    }

    /**
     *  Gets the last child Element of the node of the given name,
     *  skipping any Text nodes such as whitespace.
     *
     * @param n     The parent in which to search for children
     * @param ns    The namespace URI of the element to locate
     * @param localName     The local name of the element to locate
     * @return      The last child Element of n with the specified name, or null if none
     */
    public static Element getLastChildElement(Node n, String ns, String localName) {
        Element e = getLastChildElement(n);
        while (e != null && !isElementNamed(e, ns, localName))
            e = getPreviousSiblingElement(e);
        return e;
    }

    /**
     *  Gets the next sibling Element of the node, skipping any Text nodes such as whitespace.
     *
     * @param n     The sibling to start with
     * @return      The next sibling Element of n, or null if none
     */
    public static Element getNextSiblingElement(Node n) {
        Node sib = n.getNextSibling();
        while (sib != null && sib.getNodeType() != Node.ELEMENT_NODE)
            sib = sib.getNextSibling();
        if (sib != null)
            return (Element)sib;
        else
            return null;
    }

    /**
     *  Gets the previous sibling Element of the node, skipping any Text nodes such as whitespace.
     *
     * @param n     The sibling to start with
     * @return      The previous sibling Element of n, or null if none
     */
    public static Element getPreviousSiblingElement(Node n) {
        Node sib = n.getPreviousSibling();
        while (sib != null && sib.getNodeType() != Node.ELEMENT_NODE)
            sib = sib.getPreviousSibling();
        if (sib != null)
            return (Element)sib;
        else
            return null;
    }

    /**
     *  Gets the next sibling Element of the node of the given name,
     *  skipping any Text nodes such as whitespace.
     *
     * @param n     The sibling to start with
     * @param ns    The namespace URI of the element to locate
     * @param localName     The local name of the element to locate
     * @return      The next sibling Element of n with the specified name, or null if none
     */
    public static Element getNextSiblingElement(Node n, String ns, String localName) {
        Element e = getNextSiblingElement(n);
        while (e != null && !isElementNamed(e, ns, localName))
            e = getNextSiblingElement(e);
        return e;
    }

    /**
     *  Gets the previous sibling Element of the node of the given name,
     *  skipping any Text nodes such as whitespace.
     *
     * @param n     The sibling to start with
     * @param ns    The namespace URI of the element to locate
     * @param localName     The local name of the element to locate
     * @return      The previous sibling Element of n with the specified name, or null if none
     */
    public static Element getPreviousSiblingElement(Node n, String ns, String localName) {
        Element e = getPreviousSiblingElement(n);
        while (e != null && !isElementNamed(e, ns, localName))
            e = getPreviousSiblingElement(e);
        return e;
    }

    /**
     *  Builds a QName from a QName-valued attribute by evaluating it
     *
     * @param  e          The element containing the attribute
     * @param  namespace  The namespace of the attribute
     * @param  name       The local name of the attribute
     * @return            A QName containing the attribute value as a
     *      namespace/local name pair.
     */
    public static QName getQNameAttribute(Element e, String namespace, String name)
    {
        String qval = XML.assign(e.getAttributeNS(namespace, name));
        if (qval == null)
            return null;
        return new QName(getNamespaceForQName(qval, e), qval.substring(qval.indexOf(':') + 1));
    }

    /**
     *  Builds a QName from a QName-valued text node by evaluating it
     *
     * @param  t  The text node containing the QName value
     * @return    A QName containing the text node value as a namespace/local
     *      name pair.
     */
    public static QName getQNameTextNode(Text t)
    {
        String qval = XML.assign(t.getNodeValue());
        Node n = t.getParentNode();
        if (qval == null || n == null || n.getNodeType() != Node.ELEMENT_NODE)
            return null;
        return new QName(getNamespaceForQName(qval, (Element)n), qval.substring(qval.indexOf(':') + 1));
    }

    /**
     *  Gets the XML namespace URI that is mapped to the prefix of a QName, in
     *  the context of the DOM element e
     *
     * @param  qname  The QName value to map a prefix from
     * @param  e      The DOM element in which to calculate the prefix binding
     * @return        The XML namespace URI mapped to qname's prefix in the
     *      context of e
     */
    public static String getNamespaceForQName(String qname, Element e)
    {
        // Determine the QName prefix.
        String prefix = null;
        if (qname != null && qname.indexOf(':') >= 0)
            prefix = qname.substring(0, qname.indexOf(':'));
        return getNamespaceForPrefix(prefix, e);
    }

    /**
     *  Gets the XML namespace URI that is mapped to the specified prefix, in
     *  the context of the DOM element e
     *
     * @param  prefix  The namespace prefix to map
     * @param  e       The DOM element in which to calculate the prefix binding
     * @return         The XML namespace URI mapped to prefix in the context of
     *      e
     */
    public static String getNamespaceForPrefix(String prefix, Element e)
    {
        return e.lookupNamespaceURI(prefix);
        /*
        Node n = e;
        String ns = null;

        if (prefix != null)
        {
            if (prefix.equals("xml"))
                return XML.XML_NS;
            else if (prefix.equals("xmlns"))
                return XML.XMLNS_NS;
        }

        while ((ns == null || ns.length()==0) && n != null && n.getNodeType() == Node.ELEMENT_NODE)
        {
            ns = ((Element)n).getAttributeNS(XML.XMLNS_NS,(prefix!=null) ? prefix : "xmlns");
            n = n.getParentNode();
        }
        return ns;
        */
    }

    /**
     *  Nested class that provides XML parsers as a pooled resource
     *
     * @author     Scott Cantor (created January 15, 2002)
     * @author     Howard Gilbert
     */
    public static class ParserPool implements ErrorHandler, EntityResolver
    {

            /** OpenSAML configuration */
        protected SAMLConfig config = SAMLConfig.instance();

        // Stacks of DocumentBuilder parsers keyed by the Schema they support
        private Map /*<Schema,Stack>*/ pools = new HashMap();

        // The stack of non-schema-validating parsers
        private Stack unparsedpool = new Stack();

        // Resolution of extension schemas keyed by XML namespace
        private Map /*<String,EntityResolver>*/ extensions = new HashMap();

        /*
         * The 1.0 and 1.1 SAML XSD files use the same namespace but
         * they are not compatible. The 1.0 schema is "broken" and
         * should not be used, but it is included and made available
         * if someone needs to send or expects to receive 1.0 formatted
         * traffic.
         *
         * The default Default schema is 1.1. This can be overridden
         * by the hosting application if additional namespace information
         * will be injected into the SAML elements. For example,
         * Shibboleth must override the default and supply its own
         * Schema object constructed from the same files plus at least
         * the shibboleth.xsd file containing the definition of
         * namespace elements that override types of the AttributeValue
         * element.
         *
         * The default is assigned at static class initialization. It
         * can be changed at any time, before or after calls have been
         * made and the pools are partially filled. The default applies
         * only to calls that do not specify their own Schema object.
         * When the default changes, the old default Schema simply
         * becomes a pool of parsers that can be used if you provide
         * that Schema as an explicit argument.
         */
        private Schema defaultSchema=null; // The default schema (one of the following)
        private Schema schemaSAML10 = null; // The SAML 1.0 Standard schema
        private Schema schemaSAML11 = null; // The SAML 1.1 Standard schema (default)

        /**
         *  Original method to install a custom schema. Use setDefaultSchemas instead
         *  to maintain support for SAML 1.0 and 1.1.
         *
         * @param schema
         * @deprecated
         */
        public synchronized void setDefaultSchema(Schema schema) {
            this.defaultSchema = schema;
        }

        /**
         *  Directly installs a custom schema. You must supply both a SAML 1.0
         *  and a SAML 1.1 schema object.
         *
         * @param schema10  The schemas to use when handling SAML 1.0
         * @param schema11  The schemas to use when handling SAML 1.1
         */
        public synchronized void setDefaultSchemas(Schema schema10, Schema schema11) {
            this.schemaSAML10 = schema10;
            this.schemaSAML11 = schema11;
            if (SAMLConfig.instance().getBooleanProperty("org.globus.opensaml11.saml.compatibility-mode")) {
                defaultSchema=schemaSAML10;
            } else {
                defaultSchema=schemaSAML11;  // This is the expected default
            }
        }

        public synchronized Schema getDefaultSchema() {
            return defaultSchema;
        }
        public synchronized Schema getSchemaSAML10() {
            return schemaSAML10;
        }
        public synchronized Schema getSchemaSAML11() {
            return schemaSAML11;
        }

        /*
         * The JAXP factory is set up once and is then used to
         * create parsers in the parser pool. Access to this field
         * must be synchronized, and is in ParserPool.get()
         */
        private DocumentBuilderFactory dbf = null;

        /**
         * Constructor for the ParserPool object
         *
         * <p>To demonstrate the technology, the current version of this
         * code creates both 1.0 and 1.1 Schema objects. However, it then
         * selects only one of the two to use. Future code could refine
         * this and maintain two pools of parsers.
         */
        public ParserPool()
        {
            // Build a parser factory and the default schema set.
            dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            try {
                dbf.setFeature("http://apache.org/xml/features/validation/schema/normalized-value",false);
            } catch (ParserConfigurationException e) {
                log.warn("Unable to turn off data normalization in parser, supersignatures may fail with Xerces-J: " + e);
            }
            registerSchemas(null);

            /*
             * The DocumentBuilderFactory is almost ready. The last step
             * will be to assign a particular Schema to it before
             * obtaining each parser. The parser will then go in the
             * pool associated with that Schema object. This is done
             * at runtime in the get method.
             */
        }

        /**
         *  Registers one or more extension schemas in the default schema set. This relieves
         *  SAML applications from managing their own JAXP schema objects and enables dual
         *  compatibility with SAML 1.0 and 1.1<p>
         *  Note that you <b>must</b> insure that any dependencies are specified ahead of the
         *  schemas that require them, because they must be loaded by the SchemaFactory
         *  before they are required.
         *
         * @param exts  A map of EntityResolver interfaces keyed by "systemId" to
         *  enable the SAML runtime to obtain the schema instances anytime required
         */
        public synchronized void registerSchemas(Map /*<String,EntityResolver>*/ exts) {
            // First merge the new set into the maintained set.
            if (exts != null)
                extensions.putAll(exts);

            /*
             * Create a JAXP 1.3 Schema object from an array of open files.
             * There is no EntityResolver or ResourceResolver, so the list
             * must be complete (no dependencies on XSD files not in the
             * list. Also, to compile correctly, an XSD file must appear
             * in the list before another XSD that depends on (imports) it.
             */
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            ArrayList sources = new ArrayList();
            sources.add(new StreamSource(XML.class.getResourceAsStream("/schemas/" + XML_SCHEMA_ID),XML_SCHEMA_ID));
            sources.add(new StreamSource(XML.class.getResourceAsStream("/schemas/" + XML.XMLSIG_SCHEMA_ID),XML.XMLSIG_SCHEMA_ID));
            sources.add(new StreamSource(XML.class.getResourceAsStream("/schemas/" + XML.SOAP11ENV_SCHEMA_ID),XML.SOAP11ENV_SCHEMA_ID));
            sources.add(new StreamSource(XML.class.getResourceAsStream("/schemas/" + SAML_SCHEMA_ID),SAML_SCHEMA_ID));
            sources.add(new StreamSource(XML.class.getResourceAsStream("/schemas/" + SAMLP_SCHEMA_ID),SAMLP_SCHEMA_ID));
            for (Iterator i=extensions.entrySet().iterator(); i.hasNext();) {
                Entry entry = (Entry)i.next();
                try {
                    sources.add(new SAXSource(((EntityResolver)entry.getValue()).resolveEntity(null,(String)entry.getKey())));
                }
                catch (SAXException e) {
                    log.error("Unable to obtain extension schema (" + entry.getKey() + "): " + e);
                }
                catch (IOException e) {
                    log.error("Unable to obtain extension schema (" + entry.getKey() + "): " + e);
                }
            }
            try {
                schemaSAML10 = factory.newSchema((Source[])sources.toArray(new Source[0]));
            } catch (SAXException e) {
                log.error("Unable to parse SAML 1.0 Schemas: " + e);
            }
            // Note: I would like to close the InputStream objects, but the API
            // is silent on this. To be safe, I must assume they no longer belong
            // to me but have been transferred to JAXP.

            /*
             * Now do it again. We need new InputStream objects because the
             * previous streams have been read to the end of file.
             */
            sources.clear();
            sources.add(new StreamSource(XML.class.getResourceAsStream("/schemas/" + XML_SCHEMA_ID),XML_SCHEMA_ID));
            sources.add(new StreamSource(XML.class.getResourceAsStream("/schemas/" + XML.XMLSIG_SCHEMA_ID),XML.XMLSIG_SCHEMA_ID));
            sources.add(new StreamSource(XML.class.getResourceAsStream("/schemas/" + XML.SOAP11ENV_SCHEMA_ID),XML.SOAP11ENV_SCHEMA_ID));
            sources.add(new StreamSource(XML.class.getResourceAsStream("/schemas/" + SAML11_SCHEMA_ID),SAML11_SCHEMA_ID));
            sources.add(new StreamSource(XML.class.getResourceAsStream("/schemas/" + SAMLP11_SCHEMA_ID),SAMLP11_SCHEMA_ID));
            sources.add(new StreamSource(XML.class.getResourceAsStream("/schemas/" + SAMLSAP_SCHEMA_ID),SAMLSAP_SCHEMA_ID));
            sources.add(new StreamSource(XML.class.getResourceAsStream("/schemas/" + SHIBBOLETH_SCHEMA_ID),SHIBBOLETH_SCHEMA_ID));
            for (Iterator i=extensions.entrySet().iterator(); i.hasNext();) {
                Entry entry = (Entry)i.next();
                try {
                    sources.add(new SAXSource(((EntityResolver)entry.getValue()).resolveEntity(null,(String)entry.getKey())));
                }
                catch (SAXException e) {
                    log.error("Unable to obtain extension schema (" + entry.getKey() + "): " + e);
                }
                catch (IOException e) {
                    log.error("Unable to obtain extension schema (" + entry.getKey() + "): " + e);
                }
            }
            try {
                schemaSAML11 = factory.newSchema((Source[])sources.toArray(new Source[0]));
            } catch (SAXException e) {
                log.error("Unable to parse SAML 1.1 Schemas: " + e);
            }

            // A property can be used to select icky 1.0 syntax
            if (SAMLConfig.instance().getBooleanProperty("org.globus.opensaml11.saml.compatibility-mode")) {
                defaultSchema=schemaSAML10;
            } else {
                defaultSchema=schemaSAML11;  // This is the expected default
            }
        }

        /**
         *  Get a DOM parser suitable for our task
         *
         * @param schema JAXP 1.3 Schema object (or null for no XSD)
         * @return                    A DOM parser ready to use
         * @exception  org.globus.opensaml11.saml.SAMLException  Raised if a system error prevents a parser
         *      from being created
         */
        public synchronized DocumentBuilder get(Schema schema)
        throws SAMLException
        {
            DocumentBuilder p = null;

            Stack pool;
            if (schema!=null) {
                pool = (Stack) pools.get(schema);
                if (pool==null) {
                    pool = new Stack();
                    pools.put(schema,pool);
                }
            } else {
                pool = unparsedpool; // Parser with no xsd validation
            }

            if (pool.empty())
            {
                // Build a parser to order.
                try {
                    dbf.setSchema(schema); // null for no validation, or a Schema object
                    p = dbf.newDocumentBuilder();
                    p.setErrorHandler(this);
                    p.setEntityResolver(this);  // short-circuits URI resolution
                } catch (ParserConfigurationException e) {
                    log.error("Unable to obtain usable XML parser from environment");
                    throw new SAMLException("Unable to obtain usable XML parser from environment",e);
                }
            }
            else
                p = (DocumentBuilder)pool.pop();

            return p;
        }

        /**
         * Get a DocumentBuilder for the default Schema
         *
         * <p>Note: This uses the default (probably SAML 1.1) Schema.
         * To get an non-schema-validating parser, call "get(null)". </p>
         *
         * @return Document Builder
         * @throws org.globus.opensaml11.saml.SAMLException can't create a DocumentBuilder
         */
        public DocumentBuilder get() throws SAMLException{
            return get(getDefaultSchema());
        }

        /**
         *  Parses a document using a pooled parser with the proper settings
         *
         * @param  in                       A stream containing the content to
         *      be parsed
         * @param  schema                   Schema object or null
         * @return                          The DOM document resulting from the
         *      parse
         * @exception  org.globus.opensaml11.saml.SAMLException        Raised if a parser is unavailable
         * @exception  org.xml.sax.SAXException         Raised if a parsing error occurs
         * @exception  java.io.IOException  Raised if an I/O error occurs
         */
        public Document parse(InputSource in, Schema schema)
            throws SAMLException, SAXException, IOException
        {
            DocumentBuilder p = get(schema);
            try
            {
                Document doc =p.parse(in);
                return doc;
            }
            finally
            {
                put(p);
            }
        }


        /**
         * Short form of parse to support legacy callers
         *
         * <p>This version is not preferred. If the caller converts
         * the InputStream to an InputSource, then it can append a
         * file name as the systemId. Here we only get the InputStream
         * and create an InputSource with no identifier to be used in
         * logging or generating error messages.
         *
         * @param in InputStream of XML to be parsed
         * @return DOM Document
         * @exception  org.globus.opensaml11.saml.SAMLException        Raised if a parser is unavailable
         * @exception  org.xml.sax.SAXException         Raised if a parsing error occurs
         * @exception  java.io.IOException  Raised if an I/O error occurs
         */
        public Document parse(InputStream in)
        throws SAMLException, SAXException, IOException {
            return parse(new InputSource(in),getDefaultSchema());
        }

        /**
         *  Parses a document using a pooled parser with the proper settings
         *
         * @param  systemId                 The URI to parse
         * @return                          The DOM document resulting from the
         *      parse
         * @exception  org.globus.opensaml11.saml.SAMLException        Raised if a parser is unavailable
         * @exception  org.xml.sax.SAXException         Raised if a parsing error occurs
         * @exception  java.io.IOException  Raised if an I/O error occurs
         */
        public Document parse(String systemId, Schema schema)
            throws SAMLException, SAXException, IOException
        {
            DocumentBuilder p = get(schema);
            try
            {
                Document doc = p.parse(new InputSource(systemId));
                return doc;
            }
            finally
            {
                put(p);
            }
        }

        /**
         * Legacy version of parse where the default Schema is implied
         *
         * @param      systemId URI to be parsed, becomes systemId of InputSource
         * @return                          DOM Document
         * @exception  org.globus.opensaml11.saml.SAMLException        Raised if a parser is unavailable
         * @exception  org.xml.sax.SAXException         Raised if a parsing error occurs
         * @exception  java.io.IOException  Raised if an I/O error occurs
         */
        public Document parse(String systemId)
            throws SAMLException, SAXException, IOException {
            return parse(systemId,getDefaultSchema());
        }


        /**
         *  Builds a new DOM document
         *
         * <p>In JAXP, you get a new empty DOM document from a
         * DocumentBuilder. There is no evidence that the Schema
         * is attached to the DOM, so it doesn't matter what pool
         * to use.
         *
         * @return    An empty DOM document
         */
        public Document newDocument()
        {
            DocumentBuilder p=null;
            try {
                p = get();
            } catch (SAMLException e) {
                // Configuration error, no XML support. Return null??
                // Throw RuntimeException??
                return null;
            }
            Document doc = p.newDocument();
            put(p);
            return doc;
        }


        /**
         *  Return a parser to the pool
         *
         * @param  p  Description of Parameter
         */
        public synchronized void put(DocumentBuilder p)
        {
            Schema schema = p.getSchema();
            if (schema==null){
                unparsedpool.push(p);
            } else {
                Stack pool = (Stack) pools.get(schema);
                pool.push(p);
            }
        }


        /**
         *  Called by parser if a fatal error is detected, does nothing
         *
         * @param  e         Describes the error
         * @exception  org.xml.sax.SAXException  Can be raised to indicate an explicit error
         */
        public void fatalError(SAXParseException e)
            throws SAXException
        {
            throw e;
        }

        /**
         *  Called by parser if an error is detected, currently just throws e
         *
         * @param  e                      Description of Parameter
         * @exception  org.xml.sax.SAXParseException  Can be raised to indicate an explicit
         *      error
         */
        public void error(SAXParseException e)
            throws SAXParseException
        {
            throw e;
        }

        /**
         *  Called by parser if a warning is issued, currently logs the
         *  condition
         *
         * @param  e                      Describes the warning
         * @exception  org.xml.sax.SAXParseException  Can be raised to indicate an explicit
         *      error
         */
        public void warning(SAXParseException e)
            throws SAXParseException
        {
            log.warn("Parser warning: line = " + e.getLineNumber() + " : uri = " + e.getSystemId());
            log.warn("Parser warning (root cause): " + e.getMessage());
        }

        public InputSource resolveEntity(String publicId, String systemId) throws SAXException, IOException {
            /*
             * During parsing, this should not be called with a systemId corresponding to any known
             * externally resolvable entity. It prevents "accidental" resolution of external entities
             * via URI resolution. Network based retrieval of resources is NOT allowable and should
             * really be something the parser can block globally. We also can't return null, because
             * that signals URI resolution. So what we return is a dummy source to shortcut and
             * fail any such attempts.
             */
            return new InputSource();   // Hopefully this will fail the parser and not be treated as null.
        }
    }
}
