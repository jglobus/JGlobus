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

package org.globus.opensaml11.md.metadata.provider;

import org.globus.opensaml11.md.common.ResourceWatchdog;
import org.globus.opensaml11.md.common.ResourceWatchdogExecutionException;
import org.globus.opensaml11.md.common.ShibResource;
import org.globus.opensaml11.md.common.ShibResource.ResourceNotAvailableException;
import org.globus.opensaml11.md.metadata.EntitiesDescriptor;
import org.globus.opensaml11.md.metadata.EntityDescriptor;
import org.globus.opensaml11.md.metadata.Metadata;
import org.globus.opensaml11.md.metadata.MetadataException;
import org.globus.opensaml11.md.xml.Parser;
import org.apache.log4j.Logger;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.XML;
import org.globus.opensaml11.saml.artifact.Artifact;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import java.io.IOException;

/**
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public class XMLMetadata extends ResourceWatchdog implements Metadata {

	private static Logger log = Logger.getLogger(XMLMetadataLoadWrapper.class.getName());
	private Metadata currentMeta;

	public XMLMetadata(Element configuration) throws MetadataException, ResourceNotAvailableException {

		super(new ShibResource(configuration.getAttribute("uri"), XMLMetadata.class));

		try {

			if (configuration.getAttribute("uri") != null && !configuration.getAttribute("uri").equals("")) {
				// The configuration points to a metadata file
				InputSource src = new InputSource(resource.getInputStream());
				src.setSystemId(resource.getURL().toString());
				Document doc = Parser.loadDom(src, true);
				currentMeta = new XMLMetadataProvider(doc.getDocumentElement());

				// Start checking for metadata updates
				start();

			} else {
				// Hopefully, the configuration is inline (don't reload in this case)

                // tfreeman: added:
                // first check if given element is itself EntitiesDescriptor
                // or EntityDescriptor

                if ((XML.isElementNamed(configuration,
                                org.globus.opensaml11.md.common.XML.SAML2META_NS, "EntitiesDescriptor") || XML
                                .isElementNamed(configuration,
                                        org.globus.opensaml11.md.common.XML.SAML2META_NS,
                                        "EntityDescriptor"))) {
                    currentMeta = new XMLMetadataProvider(configuration);
                    return;
                }



                NodeList children = configuration.getChildNodes();
				for (int i = 0; i < children.getLength(); i++) {

                    Node node = children.item(i);

                    if ((node instanceof Element)
							&& (XML.isElementNamed((Element) node,
									org.globus.opensaml11.md.common.XML.SAML2META_NS, "EntitiesDescriptor") || XML
									.isElementNamed((Element) node,
											org.globus.opensaml11.md.common.XML.SAML2META_NS,
											"EntityDescriptor"))) {
						currentMeta = new XMLMetadataProvider((Element) node);
						return;
					}
				}
				// We didn't find a uri pointer or inline metadata, bail out
				log.error("Encountered a problem reading metadata: <MetadataProvider/> configuration must "
						+ "include either a (uri) attribute or inline metadata.");
				throw new MetadataException("Unable to read metadata.");
			}

		} catch (IOException e) {
			log.error("Encountered a problem reading metadata source: " + e);
			throw new MetadataException("Unable to read metadata: " + e);
		} catch (SAXException e) {
			log.error("Encountered a problem parsing metadata source: " + e);
			throw new MetadataException("Unable to read metadata: " + e);
		} catch (SAMLException e) {
			log.error("Encountered a problem processing metadata source: " + e);
			throw new MetadataException("Unable to read metadata: " + e);
		}

	}

	public XMLMetadata(String sitesFileLocation) throws MetadataException, ResourceNotAvailableException {

		super(new ShibResource(sitesFileLocation, XMLMetadata.class));
		try {
			InputSource src = new InputSource(resource.getInputStream());
			src.setSystemId(resource.getURL().toString());
			Document doc = Parser.loadDom(src, true);
			currentMeta = new XMLMetadataProvider(doc.getDocumentElement());
		} catch (IOException e) {
			log.error("Encountered a problem reading metadata source: " + e);
			throw new MetadataException("Unable to read metadata: " + e);
		} catch (SAXException e) {
			log.error("Encountered a problem parsing metadata source: " + e);
			throw new MetadataException("Unable to read metadata: " + e);
		} catch (SAMLException e) {
			log.error("Encountered a problem processing metadata source: " + e);
			throw new MetadataException("Unable to read metadata: " + e);
		}

		// Start checking for metadata updates
		start();

	}

	public EntityDescriptor lookup(String providerId) {
		return lookup(providerId, true);
	}

	public EntityDescriptor lookup(Artifact artifact) {
		return lookup(artifact, true);
	}

	public EntityDescriptor lookup(String id, boolean strict) {
		synchronized (currentMeta) {
			return currentMeta.lookup(id, strict);
		}
	}

	public EntityDescriptor lookup(Artifact artifact, boolean strict) {
		synchronized (currentMeta) {
			return currentMeta.lookup(artifact, strict);
		}
	}

	public EntityDescriptor getRootEntity() {
		synchronized (currentMeta) {
			return currentMeta.getRootEntity();
		}
	}

	public EntitiesDescriptor getRootEntities() {
		synchronized (currentMeta) {
			return currentMeta.getRootEntities();
		}
	}

	protected void doOnChange() throws ResourceWatchdogExecutionException {

		Metadata newMeta = null;

		try {
			log.info("Detected a change in the metadata. Reloading from (" + resource.getURL().toString() + ").");
			newMeta = new XMLMetadataProvider(XML.parserPool.parse(resource.getInputStream()).getDocumentElement());
		} catch (IOException e) {
			log.error("Encountered an error retrieving updated SAML metadata, continuing to use stale copy: " + e);
			return;
		} catch (SAXException e) {
			log.error("Encountered an error retrieving updated SAML metadata, continuing to use stale copy: " + e);
			return;
		} catch (SAMLException e) {
			log.error("Encountered an error retrieving updated SAML metadata, continuing to use stale copy: " + e);
			return;
		}

		if (newMeta != null) {
			synchronized (currentMeta) {
				currentMeta = newMeta;
			}
		}
	}
}
