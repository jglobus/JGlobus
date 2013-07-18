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
 * Load and compile a bunch of XSD files from some repository. Schemas may be stored in a directory on disk, as
 * resources in the Java classpath, in columns of an XML aware database, or in an XML "catalog" respository. This
 * interface describes the functions that a SchemaStore must provide. Implementations will have additional properties or
 * constructor arguments that define file paths, URL's (database, jdbc, jar, ...).
 */

package org.globus.opensaml11.md.xml;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.xml.XMLConstants;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 * Compile a Schema object from a Map of DOM objects representing XSD files keyed by the Namespace that the XSD defines.
 * <p>
 * This class is typically subclassed by implementations that obtain the Map of XSD DOMs from some external source.
 * </p>
 *
 * @author Howard Gilbert
 */
public class SchemaStore implements ErrorHandler {

    private static Logger log = Logger.getLogger(SchemaStore.class);

    protected Map/* <String,Document> */bucket = new HashMap/* <String,Document> */();

    /**
     * You can create the Map through a subclass and then just get a copy of the Map without compiling. This is useful
     * when merging sources.
     */
    public Map/* <String,Document> */getSchemaMap() {

        return bucket;
    }

    /**
     * Can only construct this class from a Map.
     *
     * @param bucket
     */
    public SchemaStore(Map/* <String,Document> */bucket) {

        super();
        this.bucket = bucket;
    }

    protected SchemaStore() {

    }

    /**
     * Create JAXP 1.3 Schema object from list of namespaces and resource dir
     * <p>
     * This is an alternate approach to the Schema building logic used in org.opensaml.XML. That module is driven off a
     * list of file names. This code reads in all the *.xsd files in a directory, indexes them by the namespace the
     * schema defines, and then is driven off a list of namespaces. This is more more indirect and requires a bit more
     * code, but it is more in line with the actual XSD standard where files and filenames are incidental. It can also
     * be quickly ported to some other schema storage medium (LDAP, Database, ...).
     * </p>
     *
     * @param namespaces
     *            Array of required XML namespaces for validation
     * @return Schema object combining all namespaces.
     */
    public Schema compileSchema(String[] namespaces) {

        Schema schema = null;
        ArrayList sources = new ArrayList();
        for (int i = 0; i < namespaces.length; i++) {
            Document doc = (Document) bucket.get(namespaces[i]);
            if (doc == null) {
                log.error("Schema missing for namespace (" + namespaces[i] + ").");
            } else {
                sources.add(new DOMSource(doc));
            }
        }
        // Now compile all the XSD files into a single composite Schema object
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        try {
            factory.setErrorHandler(this);
            schema = factory.newSchema((Source[]) sources.toArray(new Source[0]));
        } catch (SAXException e) {
            log.error("Schemas failed to compile, dependencies may be corrupt: " + e);
        }
        return schema;
    }

    public void warning(SAXParseException exception) throws SAXException {
        log.warn(exception);

    }

    public void error(SAXParseException exception) throws SAXException {
        log.error(exception);
        throw exception;
    }

    public void fatalError(SAXParseException exception) throws SAXException {
        log.error(exception);
        throw exception;
    }

}
