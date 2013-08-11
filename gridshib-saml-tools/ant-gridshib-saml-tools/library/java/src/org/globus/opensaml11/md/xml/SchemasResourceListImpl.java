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

package org.globus.opensaml11.md.xml;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import java.io.InputStream;

/**
 *  
 * Find Schemas as a list of resource files.
 * 
 * <p>Java resources are files found in the Classpath of the current
 * ClassLoader. They may be in directories on disk, in jar files, or
 * elsewhere. This class must be passed a list of resource names, but
 * it uses the Java runtime to actually locate the xsd data.
 * 
 * @author Howard Gilbert
 */
public class SchemasResourceListImpl extends SchemaStore {
    
    // This class is used by both the Idp and SP, so it must use
    // a conventionally declared logger. The SP has a special logger
    // setup so this package also logs to the init log.
    private static Logger log = Logger.getLogger(SchemasResourceListImpl.class);
    
    private String resourceprefix = "/schemas/";
    private String[] resourceNames = null;

    /**
     * @param resourcedir
     */
    public SchemasResourceListImpl(String resourcedir, String[] resources) {
        this.resourceprefix = resourcedir;
        this.resourceNames = resources;
        this.loadBucket();
    }
    
   
    private void loadBucket() {
		for (int i=0;i<resourceNames.length;i++) {
            String filename = resourceNames[i];
            if (!filename.endsWith(".xsd")) {
                log.error(filename + " doesn't end in .xsd, ignoring it.");
                continue;
            }
            String resourceName = resourceprefix+filename;
            InputStream inputStream =
                SchemasResourceListImpl.class.getResourceAsStream(
                            resourceName);
            if (inputStream == null) {
                log.error("Resource "+resourceName+" not found, ignoring it.");
                continue;
            }
            InputSource insrc = new InputSource(inputStream);
            insrc.setSystemId(resourceName);
           
            // Non-validating parse to DOM
            Document xsddom;
			try {
				xsddom = Parser.loadDom(insrc,false);
			} catch (Exception e) {
				log.error("Error parsing XML schema (" + resourceName + "): " + e);
				continue;
			}
            
            // Get the target namespace from the root element
            Element ele = xsddom.getDocumentElement();
            if (!ele.getLocalName().equals("schema")) {
                log.error("Schema file wrong root element:"+resourceName);
                continue;
            }
            String targetNamespace = ele.getAttribute("targetNamespace");
            if (targetNamespace==null) {
                log.error("Schema has no targetNamespace: "+resourceName);
                continue;
            }
            
            // Put the DOM in the Bucket keyed by namespace
            if (bucket.containsKey(targetNamespace)) {
                log.debug("Replacing XSD for namespace: "+targetNamespace+" "+filename);
            } else {
                log.debug("Defining XSD for namespace:  "+targetNamespace+" "+filename);
            }
            bucket.put(targetNamespace,xsddom);
        }
	}

}
