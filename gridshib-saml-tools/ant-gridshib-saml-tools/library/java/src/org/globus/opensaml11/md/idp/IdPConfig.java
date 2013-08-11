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

package org.globus.opensaml11.md.idp;

import org.apache.log4j.Logger;
import org.globus.opensaml11.md.common.ShibbolethConfigurationException;
import org.w3c.dom.Element;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

/**
 * @author Walter Hoehn
 */
public class IdPConfig {

	private String defaultRelyingPartyName;
	private String providerId;
	public static final String configNameSpace = "urn:mace:shibboleth:idp:config:1.0";
	private String resolverConfig = "/conf/resolver.xml";
	private boolean passThruErrors = false;
	private int maxThreads = 30;
	private String authHeaderName = "REMOTE_USER";
	private URI defaultAuthMethod;
	private URL AAUrl;

	private static Logger log = Logger.getLogger(IdPConfig.class.getName());

	public IdPConfig(Element config) throws ShibbolethConfigurationException {

		if (!config.getTagName().equals("IdPConfig")) { throw new ShibbolethConfigurationException(
				"Unexpected configuration data.  <IdPConfig/> is needed."); }

		log.debug("Loading global configuration properties.");

		// Global providerId
		providerId = ((Element) config).getAttribute("providerId");
		if (providerId == null || providerId.equals("")) {
			log.error("Global providerId not set.  Add a (providerId) attribute to <IdPConfig/>.");
			throw new ShibbolethConfigurationException("Required configuration not specified.");
		}

		// Default Relying Party
		defaultRelyingPartyName = ((Element) config).getAttribute("defaultRelyingParty");
		if (defaultRelyingPartyName == null || defaultRelyingPartyName.equals("")) {
			log.error("Default Relying Party not set.  Add a (defaultRelyingParty) attribute to <IdPConfig/>.");
			throw new ShibbolethConfigurationException("Required configuration not specified.");
		}

		// Attribute resolver config file location
		String rawResolverConfig = ((Element) config).getAttribute("resolverConfig");
		if (rawResolverConfig != null && !rawResolverConfig.equals("")) {
			resolverConfig = rawResolverConfig;
		}

		// Global Pass thru error setting
		String attribute = ((Element) config).getAttribute("passThruErrors");
		if (attribute != null && !attribute.equals("")) {
			passThruErrors = Boolean.valueOf(attribute).booleanValue();
		}

		attribute = ((Element) config).getAttribute("AAUrl");
		if (attribute == null || attribute.equals("")) {
			log.error("Global Attribute Authority URL not set.  Add an (AAUrl) attribute to <IdPConfig/>.");
			throw new ShibbolethConfigurationException("Required configuration not specified.");
		}
		try {
			AAUrl = new URL(attribute);
		} catch (MalformedURLException e) {
			log.error("(AAUrl) attribute to is not a valid URL.");
			throw new ShibbolethConfigurationException("Required configuration is invalid.");
		}

		attribute = ((Element) config).getAttribute("defaultAuthMethod");
		if (attribute == null || attribute.equals("")) {
			try {
				defaultAuthMethod = new URI("urn:oasis:names:tc:SAML:1.0:am:unspecified");
			} catch (URISyntaxException e1) {
				// Shouldn't happen
				throw new ShibbolethConfigurationException("Default Auth Method URI could not be constructed.");
			}
		} else {
			try {
				defaultAuthMethod = new URI(attribute);
			} catch (URISyntaxException e1) {
				log.error("(defaultAuthMethod) attribute to is not a valid URI.");
				throw new ShibbolethConfigurationException("Required configuration is invalid.");
			}
		}

		attribute = ((Element) config).getAttribute("maxSigningThreads");
		if (attribute != null && !attribute.equals("")) {
			try {
				maxThreads = Integer.parseInt(attribute);
			} catch (NumberFormatException e) {
				log.error("(maxSigningThreads) attribute to is not a valid integer.");
				throw new ShibbolethConfigurationException("Configuration is invalid.");
			}
		}

		attribute = ((Element) config).getAttribute("authHeaderName");
		if (attribute != null && !attribute.equals("")) {
			authHeaderName = attribute;
		}

		log.debug("Global IdP config: (AAUrl) = (" + getAAUrl() + ").");
		log.debug("Global IdP config: (defaultAuthMethod) = (" + getDefaultAuthMethod() + ").");
		log.debug("Global IdP config: (maxSigningThreads) = (" + getMaxThreads() + ").");
		log.debug("Global IdP config: (authHeaderName) = (" + getAuthHeaderName() + ").");

		log.debug("Global IdP config: (resolverConfig) = (" + getResolverConfigLocation() + ").");
		log.debug("Global IdP config: (passThruErrors) = (" + passThruErrors() + ").");
		log.debug("Global IdP config: Default Relying Party: (" + getDefaultRelyingPartyName() + ").");
	}

	public String getProviderId() {

		return providerId;
	}

	public String getDefaultRelyingPartyName() {

		return defaultRelyingPartyName;
	}

	public String getResolverConfigLocation() {

		return resolverConfig;
	}

	public boolean passThruErrors() {

		return passThruErrors;
	}

	public int getMaxThreads() {

		return maxThreads;
	}

	public String getAuthHeaderName() {

		return authHeaderName;
	}

	public URI getDefaultAuthMethod() {

		return defaultAuthMethod;
	}

	public URL getAAUrl() {

		return AAUrl;
	}
}