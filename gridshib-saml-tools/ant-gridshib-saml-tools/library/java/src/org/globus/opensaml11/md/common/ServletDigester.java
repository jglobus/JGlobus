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

package org.globus.opensaml11.md.common;

import org.apache.commons.digester.Digester;
import org.apache.log4j.Logger;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.XMLReader;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Properties;
import java.util.StringTokenizer;

/**
 * This class is a jakarta Digester style parser that will pull schemas from /WEB-INF/schemas, if they exist.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class ServletDigester extends Digester {

	private static Logger log = Logger.getLogger(ServletDigester.class.getName());

	public ServletDigester() {

		super();
		setErrorHandler(new PassThruErrorHandler());
	}

	public ServletDigester(SAXParser parser) {

		super(parser);
		super.setErrorHandler(new PassThruErrorHandler());
	}

	public ServletDigester(XMLReader reader) {

		super(reader);
		super.setErrorHandler(new PassThruErrorHandler());
	}

	/**
	 * @see org.xml.sax.EntityResolver#resolveEntity(String, String)
	 */
	public InputSource resolveEntity(String publicId, String systemId) throws SAXException {

		log.debug("Resolving entity for System ID: " + systemId);
		if (systemId != null) {
			StringTokenizer tokenString = new StringTokenizer(systemId, "/");
			String xsdFile = "";
			while (tokenString.hasMoreTokens()) {
				xsdFile = tokenString.nextToken();
			}
			if (xsdFile.endsWith(".xsd")) {
				InputStream stream;
				try {
					stream = new ShibResource("/schemas/" + xsdFile, this.getClass()).getInputStream();
				} catch (IOException ioe) {
					log.error("Error loading schema: " + xsdFile + ": " + ioe);
					return null;
				}
				if (stream != null) { return new InputSource(stream); }
			}
		}
		return null;

	}

	/**
	 * Return the SAXParser we will use to parse the input stream. If there is a problem creating the parser, return
	 * <code>null</code>.
	 */
	public SAXParser getParser() {

		// Return the parser we already created (if any)
		if (parser != null) { return (parser); }

		// Create and return a new parser
		synchronized (this) {
			try {
				if (factory == null) {
					factory = SAXParserFactory.newInstance();
				}
				factory.setNamespaceAware(namespaceAware);
				factory.setValidating(validating);
				if (validating) {
					factory.setFeature("http://xml.org/sax/features/namespaces", true);
					factory.setFeature("http://xml.org/sax/features/validation", true);
					factory.setFeature("http://apache.org/xml/features/validation/schema", true);
					factory.setFeature("http://apache.org/xml/features/validation/schema-full-checking", true);
				}
				parser = factory.newSAXParser();
				if (validating) {

					Properties schemaProps = new Properties();
					schemaProps.load(new ShibResource("/conf/schemas.properties", this.getClass()).getInputStream());
					String schemaLocations = "";
					Enumeration schemas = schemaProps.propertyNames();
					while (schemas.hasMoreElements()) {
						String ns = (String) schemas.nextElement();
						schemaLocations += ns + " " + schemaProps.getProperty(ns) + " ";
					}
					log.debug("Overriding schema locations for the following namespace: " + schemaLocations);
					parser.setProperty("http://apache.org/xml/properties/schema/external-schemaLocation",
							schemaLocations);
				}
				return (parser);
			} catch (Exception e) {
				log.error("Error during Digester initialization", e);
				return (null);
			}
		}

	}

	/**
	 * Sax <code>ErrorHandler</code> that passes all errors up as new exceptions.
	 */

	public class PassThruErrorHandler implements ErrorHandler {

		/**
		 * @see org.xml.sax.ErrorHandler#error(SAXParseException)
		 */
		public void error(SAXParseException arg0) throws SAXException {

			throw new SAXException("Error parsing xml file: " + arg0);
		}

		/**
		 * @see org.xml.sax.ErrorHandler#fatalError(SAXParseException)
		 */
		public void fatalError(SAXParseException arg0) throws SAXException {

			throw new SAXException("Error parsing xml file: " + arg0);
		}

		/**
		 * @see org.xml.sax.ErrorHandler#warning(SAXParseException)
		 */
		public void warning(SAXParseException arg0) throws SAXException {

			throw new SAXException("Error parsing xml file: " + arg0);
		}

	}
}
