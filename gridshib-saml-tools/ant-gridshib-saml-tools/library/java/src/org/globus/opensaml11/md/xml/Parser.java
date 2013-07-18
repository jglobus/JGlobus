/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Parser.java
 *
 * Validating and non-validating XML parsing using JAXP 1.3.
 *
 * Previous versions of the code directly used the Xerces DOMParser
 * class. This class has been hidden in the Sun XML stack, and the
 * public interface is to use DocumentBuilderFactory. This module
 * requires the DOM 3 and JAXP 1.3 support built into J2SE 5.0 and
 * distributed separately for earlier releases of Java from
 * https://jaxp.dev.java.net/. It should also work with Xerces 2.7.0
 * when that release becomes available.
 *
 * The org.globus.opensaml11.saml.XML class already has most of the parsing
 * code, but it uses a subset of the required Schemas. Here we build a
 * wider Schema object, set it as the default SAML schema (because
 * some Shibboleth namespace fields appear in SAML statements), and
 * demand that Schema for every parser (DocumentBuilder) we request.
 *
 * Currently, this class exposes static methods. Should a real
 * framework be installed, it would become a singleton object.
 */
package org.globus.opensaml11.md.xml;

import org.globus.opensaml11.md.common.ShibResource;
import org.apache.log4j.Logger;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.globus.opensaml11.saml.SAMLException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.validation.Schema;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URL;
import java.util.Iterator;
import java.util.Map;

/**
 * Obtain schema validating and non-validating XML parsers.
 *
 * @author Howard Gilbert
 */
public class Parser {

    // This class is used by both the Idp and SP, so it must use
    // a conventionally declared logger. The SP has a special logger
    // setup so this package also logs to the init log.
    private static Logger log = Logger.getLogger(Parser.class);


    /**
     * All the namespaces used by any part of Shibboleth
     *
     * Note: The current Schema compiler requires that dependencies
     * (imports) be listed before the namespace of the schema
     * that imports them.
     */
    private static String[] namespaces = new String[]{
            "http://www.w3.org/2000/09/xmldsig#",
            "http://www.w3.org/2001/04/xmlenc#",
            "urn:oasis:names:tc:SAML:1.0:assertion",
            "urn:oasis:names:tc:SAML:1.1:profiles:assertion:subject",
            "urn:oasis:names:tc:SAML:2.0:assertion",
            "http://www.w3.org/XML/1998/namespace",
            "http://schemas.xmlsoap.org/soap/envelope/",
            "urn:mace:shibboleth:credentials:1.0",
            "urn:oasis:names:tc:SAML:1.0:protocol",
            "urn:mace:shibboleth:namemapper:1.0",
            "urn:mace:shibboleth:idp:config:1.0",
            "urn:mace:shibboleth:arp:1.0",
            "urn:mace:shibboleth:resolver:1.0",
            "urn:oasis:names:tc:SAML:2.0:metadata",
            "urn:oasis:names:tc:SAML:metadata:extension",
            "urn:mace:shibboleth:target:config:1.0",
            "urn:mace:shibboleth:trust:1.0",
            "urn:mace:shibboleth:metadata:1.0",
            "urn:mace:shibboleth:1.0",
            "http://schemas.xmlsoap.org/soap/envelope/"
    };

    private static String[] resources = new String[]{
            "credentials.xsd",
            "cs-sstc-schema-assertion-1.1.xsd",
            "cs-sstc-schema-protocol-1.1.xsd",
            "namemapper.xsd",
            "sstc-saml1-profiles-assertion-subject.xsd",
            "saml-schema-assertion-2.0.xsd",
            "saml-schema-metadata-2.0.xsd",
            "saml-schema-metadata-ext.xsd",
            "shibboleth-arp-1.0.xsd",
            "shibboleth-idpconfig-1.0.xsd",
            "shibboleth-metadata-1.0.xsd",
            "shibboleth-resolver-1.0.xsd",
            "shibboleth-targetconfig-1.0.xsd",
            "shibboleth-trust-1.0.xsd",
            "shibboleth.xsd",
            "soap-envelope.xsd",
            "wayfconfig.xsd",
            "xenc-schema.xsd",
            "xml.xsd",
            "xmldsig-core-schema.xsd"
    };

    private static String[] oldResources = new String[]{
            "cs-sstc-schema-assertion-01.xsd",
            "cs-sstc-schema-protocol-01.xsd",
            "xmldsig-core-schema.xsd"
    };

    // If there were a real Framework here (like Spring) then
    // the schemaBuilder would be inserted



    private static final boolean useResourceBuilder = true;

    private static SchemaStore schemaBuilder = null;

    private static SchemaStore oldSchemasBuilder = null;

    private static Schema schema = null;

    private static Schema schemaOldSAML= null;

    private static Integer initialized = null;


    // tfreeman: modifying to allow dynamic location, adding init methods
    private static String defaultSchemaDir =
                                "/org/globus/opensaml11/md/schemas/";

    public static void init() {
        init(defaultSchemaDir, defaultSchemaDir + "saml-1.0/");
    }

    public static void init(String defaultDirectory, String oldSchemasDir) {
        // initialized does not mean successfully initialized
        initialized = new Integer(1);

        schemaBuilder = (useResourceBuilder?
            (SchemaStore)
                new SchemasResourceListImpl(defaultDirectory,resources):
            (SchemaStore)
                new SchemasDirectoryImpl(defaultDirectory));

        oldSchemasBuilder = (useResourceBuilder?
                (SchemaStore)
                    new SchemasResourceListImpl(oldSchemasDir,oldResources):
                (SchemaStore)
                    new SchemasDirectoryImpl(oldSchemasDir));

        schema = schemaBuilder.compileSchema(namespaces);

        // Merge in the XSDs defining non-conflicting namespaces
        // A non-replacing putAll()
        Map/*<String,Document>*/ source = schemaBuilder.getSchemaMap();
        Map/*<String,Document>*/ sink   = oldSchemasBuilder.getSchemaMap();
        Iterator/*<String>*/ nsi = source.keySet().iterator();
        while (nsi.hasNext()) {
            String namespace = (String) nsi.next();
            if (!sink.containsKey(namespace)) {
                sink.put(namespace,source.get(namespace));
            }
        }

        schemaOldSAML = oldSchemasBuilder.compileSchema(namespaces);


        /*
         * Override the OpenSAML default schema from SAML 1.1 to
         * SAML 1.1 plus Shibboleth (and some SAML 2.0).
         */
        //org.globus.opensaml11.saml.XML.parserPool.setDefaultSchema(schema);
        org.globus.opensaml11.saml.XML.parserPool.setDefaultSchemas(schemaOldSAML,schema);

    }






    /**
     * Load a DOM from a wrapped byte stream.
     *
     * @param ins InputSource The XML document
     * @param validate If true, use Schema. Otherwise, its raw XML.
     * @return A DOM 3 tree
     */
    public static Document loadDom(InputSource ins, boolean validate)
        throws SAMLException, SAXException, IOException {

        if (initialized == null) {
            init();
        }

        Document doc = null;
        log.debug("Loading XML from (" + ins.getSystemId() + ")" + (validate ? " with Schema validation" : ""));
        if (validate) {
            if (schema==null)
                throw new SAXException("Cannot validate XML because of invalid Schemas");
            doc = org.globus.opensaml11.saml.XML.parserPool.parse(ins, schema);
        } else {
            doc = org.globus.opensaml11.saml.XML.parserPool.parse(ins, null);
        }
        return doc;
    }


    /**
     * A dummy class that pretends to be an old Xerces DOMParser to simplify conversion of existing code.
     */
    public static class DOMParser {
        Document doc = null;
        boolean validate = false;

        public DOMParser(boolean validate) {
            this.validate=validate;
        }

        public Document parse(InputSource ins) throws SAXException, IOException, SAMLException {
            doc = loadDom(ins,validate);
            return doc;
        }

        public Document getDocument() {
            return doc;
        }
    }

    /**
     * Write a DOM out to a character stream (for debugging and logging)
     *
     * @param dom The DOM tree to write
     * @return A string containing the XML in character form.
     */
    public static String jaxpSerialize(Node dom) {

        if (initialized == null) {
            init();
        }

        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = null;
        DOMSource source = new DOMSource(dom);
        try {
            transformer = factory.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        } catch (TransformerConfigurationException e) {
            return null;
        }
        StringWriter stringWriter = new StringWriter();
        StreamResult result = new StreamResult(stringWriter);
        try {
            transformer.transform(source, result);
        } catch (TransformerException e1) {
            return null;
        }
        return stringWriter.toString();
    }

    /**
     *  Serializes the XML representation of the SAML object to a stream
     *
     */
    public static String serialize(Node root){

        if (initialized == null) {
            init();
        }

        byte[] bs = null;
        try
        {
            Canonicalizer c = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            bs = c.canonicalizeSubtree(root, "#default saml samlp ds xsd xsi code kind rw typens");
        }
        catch (InvalidCanonicalizerException e)
        {
            log.error("Error obtaining an XML canonicalizer ",e);
            return null;
        }
        catch (CanonicalizationException e)
        {
            log.error("Error canonicalizing XML ",e);
            return null;
        }
        return new String(bs);
    }


    /**
     * Version of loadDom where the file is specified as a resource name
     *
     * @param configFilePath input resource
     * @param validate if true, use Schema
     * @return DOM tree or null if file cannot be loaded or parsed
     */
    public static Document loadDom(String configFilePath,boolean validate) throws SAMLException, SAXException, IOException
    {

        if (initialized == null) {
            init();
        }

       InputSource insrc;
       try {
            InputStream resourceAsStream =
                new ShibResource(configFilePath).getInputStream();
            insrc = new InputSource(resourceAsStream);
            insrc.setSystemId(configFilePath);
        } catch (Exception e1) {
            log.error("Configuration file "+configFilePath+" could not be located.");
            return null;
        }

        return loadDom(insrc,validate); // Now pass on to the main routine

    }

    /**
     * Version of loadDom where the file is specified as a URL.
     *
     * @param configURL input resource
     * @param validate if true, use Schema
     * @return DOM tree
     */
    public static Document loadDom(URL configURL, boolean validate) throws SAMLException, SAXException, IOException
    {

        if (initialized == null) {
            init();
        }

       InputSource insrc;
       try {
            InputStream resourceAsStream = configURL.openStream();
            insrc = new InputSource(resourceAsStream);
            insrc.setSystemId(configURL.toString());
        } catch (Exception e1) {
            log.error("Configuration URL "+configURL+" could not be accessed.");
            return null;
        }

        return loadDom(insrc,validate); // Now pass on to the main routine

    }



}
