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

package org.globus.opensaml11.md.common.provider;

import org.globus.opensaml11.md.common.IdentityProvider;
import org.globus.opensaml11.md.common.NameIdentifierMapping;
import org.globus.opensaml11.md.common.NameIdentifierMappingException;
import org.apache.log4j.Logger;
import org.globus.opensaml11.saml.SAMLNameIdentifier;
import org.w3c.dom.Element;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Base class for processing name identifier mapping configuration.
 * 
 * @author Walter Hoehn
 */
public abstract class BaseNameIdentifierMapping implements NameIdentifierMapping {

	private static Logger log = Logger.getLogger(BaseNameIdentifierMapping.class.getName());
	private URI format;
	private String id;

	public BaseNameIdentifierMapping(Element config) throws NameIdentifierMappingException {

		if (!config.getLocalName().equals("NameMapping")) { throw new IllegalArgumentException(); }

		String rawFormat = ((Element) config).getAttribute("format");
		if (rawFormat == null || rawFormat.equals("")) {
			log.error("Name Mapping requires a \"format\" attribute.");
			throw new NameIdentifierMappingException("Invalid mapping information specified.");
		}

		try {
			format = new URI(rawFormat);
		} catch (URISyntaxException e) {
			log.error("Name Mapping attribute \"format\" is not a valid URI: " + e);
			throw new NameIdentifierMappingException("Invalid mapping information specified.");
		}

		String id = ((Element) config).getAttribute("id");
		if (id != null && !id.equals("")) {
			this.id = id;
		}

	}

	public URI getNameIdentifierFormat() {

		return format;
	}

	public String getId() {

		return id;
	}

	public void destroy() {

	// nothing to do
	}

	protected void verifyQualifier(SAMLNameIdentifier nameId, IdentityProvider idProv)
			throws NameIdentifierMappingException {

		if (idProv.getProviderId() == null || !idProv.getProviderId().equals(nameId.getNameQualifier())) {
			log.error("The name qualifier (" + nameId.getNameQualifier()
					+ ") for the referenced subject is not valid for this identity provider.");
			throw new NameIdentifierMappingException("The name qualifier (" + nameId.getNameQualifier()
					+ ") for the referenced subject is not valid for this identity provider.");
		}
	}
}