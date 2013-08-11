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

import org.globus.opensaml11.md.idp.IdPConfig;
import org.globus.opensaml11.md.metadata.EntitiesDescriptor;
import org.globus.opensaml11.md.metadata.EntityDescriptor;
import org.globus.opensaml11.md.metadata.Metadata;
import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Class for determining the effective relying party from the unique id of the service provider. Checks first for an
 * exact match on the service provider, then for membership in a group of providers (perhaps a federation). Uses the
 * default relying party if neither is found.
 * 
 * @author Walter Hoehn
 */
public class ServiceProviderMapper {

	private static Logger log = Logger.getLogger(ServiceProviderMapper.class.getName());
	protected Map relyingParties = new HashMap();
	private Metadata metaData;
	private IdPConfig configuration;
	private Credentials credentials;
	private NameMapper nameMapper;

	public ServiceProviderMapper(Element rawConfig, IdPConfig configuration, Credentials credentials,
			NameMapper nameMapper) throws ServiceProviderMapperException {

		this.configuration = configuration;
		this.credentials = credentials;
		this.nameMapper = nameMapper;

		NodeList itemElements = rawConfig.getElementsByTagNameNS(IdPConfig.configNameSpace, "RelyingParty");

		for (int i = 0; i < itemElements.getLength(); i++) {
			addRelyingParty((Element) itemElements.item(i));
		}

		verifyDefaultParty(configuration);

	}

	public void setMetadata(Metadata metadata) {

		this.metaData = metadata;
	}

	private IdPConfig getIdPConfig() {

		return configuration;
	}

	protected void verifyDefaultParty(IdPConfig configuration) throws ServiceProviderMapperException {

		// Verify we have a proper default party
		String defaultParty = configuration.getDefaultRelyingPartyName();
		if (defaultParty == null || defaultParty.equals("")) {
			if (relyingParties.size() != 1) {
				log
						.error("Default Relying Party not specified.  Add a (defaultRelyingParty) attribute to <IdPConfig>.");
				throw new ServiceProviderMapperException("Required configuration not specified.");
			} else {
				log.debug("Only one Relying Party loaded.  Using this as the default.");
			}
		}
		log.debug("Default Relying Party set to: (" + defaultParty + ").");
		if (!relyingParties.containsKey(defaultParty)) {
			log.error("Default Relying Party refers to a Relying Party that has not been loaded.");
			throw new ServiceProviderMapperException("Invalid configuration (Default Relying Party).");
		}
	}

	protected RelyingParty getRelyingPartyImpl(String providerIdFromSP) {

		// Null request, send the default
		if (providerIdFromSP == null) {
			RelyingParty relyingParty = getDefaultRelyingParty();
			log.info("Using default Relying Party: (" + relyingParty.getName() + ").");
			return new UnknownProviderWrapper(relyingParty, providerIdFromSP);
		}

		// Look for a configuration for the specific relying party
		if (relyingParties.containsKey(providerIdFromSP)) {
			log.info("Found Relying Party for (" + providerIdFromSP + ").");
			return (RelyingParty) relyingParties.get(providerIdFromSP);
		}

		// Next, check to see if the relying party is in any groups
		RelyingParty groupParty = findRelyingPartyByGroup(providerIdFromSP);
		if (groupParty != null) {
			log.info("Provider is a member of Relying Party (" + groupParty.getName() + ").");
			return new RelyingPartyGroupWrapper(groupParty, providerIdFromSP);
		}

		// OK, we can't find it... just send the default
		RelyingParty relyingParty = getDefaultRelyingParty();
		log.info("Could not locate Relying Party configuration for (" + providerIdFromSP
				+ ").  Using default Relying Party: (" + relyingParty.getName() + ").");
		return new UnknownProviderWrapper(relyingParty, providerIdFromSP);
	}

	private RelyingParty findRelyingPartyByGroup(String providerIdFromSP) {

		if (metaData == null) { return null; }

		EntityDescriptor provider = metaData.lookup(providerIdFromSP);
		if (provider != null) {
			EntitiesDescriptor parent = provider.getEntitiesDescriptor();
			while (parent != null) {
				if (parent.getName() != null) {
					if (relyingParties.containsKey(parent.getName())) {
						log.info("Found matching Relying Party for group (" + parent.getName() + ").");
						return (RelyingParty) relyingParties.get(parent.getName());
					}
					else {
						log.debug("Provider is a member of group (" + parent.getName()
								+ "), but no matching Relying Party was found.");
					}
				}
				parent = parent.getEntitiesDescriptor();
			}
		}
		return null;
	}

	public RelyingParty getDefaultRelyingParty() {

		// If there is no explicit default, pick the single configured Relying
		// Party
		String defaultParty = getIdPConfig().getDefaultRelyingPartyName();
		if (defaultParty == null || defaultParty.equals("")) { return (RelyingParty) relyingParties.values().iterator()
				.next(); }

		// If we do have a default specified, use it...
		return (RelyingParty) relyingParties.get(defaultParty);
	}

	/**
	 * Returns the relying party for a legacy provider(the default)
	 */
	public RelyingParty getLegacyRelyingParty() {

		RelyingParty relyingParty = getDefaultRelyingParty();
		log.info("Request is from legacy shib SP.  Selecting default Relying Party: (" + relyingParty.getName() + ").");
		return new LegacyWrapper((RelyingParty) relyingParty);

	}

	/**
	 * Returns the appropriate relying party for the supplied service provider id.
	 */
	public RelyingParty getRelyingParty(String providerIdFromSP) {

		if (providerIdFromSP == null || providerIdFromSP.equals("")) {
			RelyingParty relyingParty = getDefaultRelyingParty();
			log.info("Selecting default Relying Party: (" + relyingParty.getName() + ").");
			return new NoMetadataWrapper((RelyingParty) relyingParty);
		}

		return (RelyingParty) getRelyingPartyImpl(providerIdFromSP);
	}

	private void addRelyingParty(Element e) throws ServiceProviderMapperException {

		log.debug("Found a Relying Party.");
		try {
			if (e.getLocalName().equals("RelyingParty")) {
				RelyingParty party = new RelyingPartyImpl(e, configuration, credentials, nameMapper);
				log.debug("Relying Party (" + party.getName() + ") loaded.");
				relyingParties.put(party.getName(), party);
			}
		} catch (ServiceProviderMapperException exc) {
			log.error("Encountered an error while attempting to load Relying Party configuration.  Skipping...");
		}

	}

	/**
	 * Base relying party implementation.
	 * 
	 * @author Walter Hoehn
	 */
	protected class RelyingPartyImpl implements RelyingParty {

		private RelyingPartyIdentityProvider identityProvider;
		private String name;
		private String overridenIdPProviderId;
		private URL overridenAAUrl;
		private URI overridenDefaultAuthMethod;
		private List mappingIds = new ArrayList();
		private IdPConfig configuration;
		private boolean overridenPassThruErrors = false;
		private boolean passThruIsOverriden = false;
		private boolean forceAttributePush = false;
		private boolean forceAttributeNoPush = false;
		private boolean singleAssertion = false;
		private boolean defaultToPOST = true;
		private boolean wantsAssertionsSigned = false;
		private int preferredArtifactType = 1;
		private String defaultTarget;
		private boolean wantsSchemaHack = false;

		public RelyingPartyImpl(Element partyConfig, IdPConfig globalConfig, Credentials credentials,
				NameMapper nameMapper) throws ServiceProviderMapperException {

			configuration = globalConfig;

			// Get party name
			name = ((Element) partyConfig).getAttribute("name");
			if (name == null || name.equals("")) {
				log.error("Relying Party name not set.  Add a (name) attribute to <RelyingParty>.");
				throw new ServiceProviderMapperException("Required configuration not specified.");
			}
			log.debug("Loading Relying Party: (" + name + ").");

			// Process overrides for global configuration data
			String attribute = ((Element) partyConfig).getAttribute("providerId");
			if (attribute != null && !attribute.equals("")) {
				log.debug("Overriding providerId for Relying Pary (" + name + ") with (" + attribute + ").");
				overridenIdPProviderId = attribute;
			}

			attribute = ((Element) partyConfig).getAttribute("AAUrl");
			if (attribute != null && !attribute.equals("")) {
				log.debug("Overriding AAUrl for Relying Pary (" + name + ") with (" + attribute + ").");
				try {
					overridenAAUrl = new URL(attribute);
				} catch (MalformedURLException e) {
					log.error("(AAUrl) attribute to is not a valid URL.");
					throw new ServiceProviderMapperException("Configuration is invalid.");
				}
			}

			attribute = ((Element) partyConfig).getAttribute("defaultAuthMethod");
			if (attribute != null && !attribute.equals("")) {
				log.debug("Overriding defaultAuthMethod for Relying Pary (" + name + ") with (" + attribute + ").");
				try {
					overridenDefaultAuthMethod = new URI(attribute);
				} catch (URISyntaxException e1) {
					log.error("(defaultAuthMethod) attribute to is not a valid URI.");
					throw new ServiceProviderMapperException("Configuration is invalid.");
				}
			}

			attribute = ((Element) partyConfig).getAttribute("passThruErrors");
			if (attribute != null && !attribute.equals("")) {
				log.debug("Overriding passThruErrors for Relying Pary (" + name + ") with (" + attribute + ").");
				overridenPassThruErrors = Boolean.valueOf(attribute).booleanValue();
				passThruIsOverriden = true;
			}

			// SSO profile defaulting
			attribute = ((Element) partyConfig).getAttribute("defaultToPOSTProfile");
			if (attribute != null && !attribute.equals("")) {
				defaultToPOST = Boolean.valueOf(attribute).booleanValue();
			}
			if (defaultToPOST) {
				log.debug("Relying party defaults to POST profile.");
			} else {
				log.debug("Relying party defaults to Artifact profile.");
			}

			attribute = ((Element) partyConfig).getAttribute("singleAssertion");
			if (attribute != null && !attribute.equals("")) {
				singleAssertion = Boolean.valueOf(attribute).booleanValue();
			}
			if (singleAssertion) {
				log.debug("Relying party defaults to a single assertion when pushing attributes.");
			} else {
				log.debug("Relying party defaults to multiple assertions when pushing attributes.");
			}
			
			// Relying Party wants assertions signed?
			attribute = ((Element) partyConfig).getAttribute("signAssertions");
			if (attribute != null && !attribute.equals("")) {
				wantsAssertionsSigned = Boolean.valueOf(attribute).booleanValue();
			}
			if (wantsAssertionsSigned) {
				log.debug("Relying party wants SAML Assertions to be signed.");
			} else {
				log.debug("Relying party does not want SAML Assertions to be signed.");
			}

			// Decide whether or not to use the schema hack for old xerces
			attribute = ((Element) partyConfig).getAttribute("schemaHack");
			if (attribute != null && !attribute.equals("")) {
				wantsSchemaHack = Boolean.valueOf(attribute).booleanValue();
			}
			if (wantsSchemaHack) {
				log.debug("XML schema hack enabled for this relying party.");
			}

			// Set a default target for use in artifact redirects
			defaultTarget = ((Element) partyConfig).getAttribute("defaultTarget");

			// Determine whether or not we are forcing attribute push on or off
			String forcePush = ((Element) partyConfig).getAttribute("forceAttributePush");
			String forceNoPush = ((Element) partyConfig).getAttribute("forceAttributeNoPush");

			if (forcePush != null && Boolean.valueOf(forcePush).booleanValue() && forceNoPush != null
					&& Boolean.valueOf(forceNoPush).booleanValue()) {
				log.error("Invalid configuration:  Attribute push is forced to ON and OFF for this relying "
						+ "party.  Turning off forcing in favor of profile defaults.");
			} else {
				forceAttributePush = Boolean.valueOf(forcePush).booleanValue();
				forceAttributeNoPush = Boolean.valueOf(forceNoPush).booleanValue();
				log.debug("Attribute push forcing is set to (" + forceAttributePush + ").");
				log.debug("No attribute push forcing is set to (" + forceAttributeNoPush + ").");
			}

			attribute = ((Element) partyConfig).getAttribute("preferredArtifactType");
			if (attribute != null && !attribute.equals("")) {
				log.debug("Overriding AAUrl for Relying Pary (" + name + ") with (" + attribute + ").");
				try {
					preferredArtifactType = Integer.parseInt(attribute);
				} catch (NumberFormatException e) {
					log.error("(preferredArtifactType) attribute to is not a valid integer.");
					throw new ServiceProviderMapperException("Configuration is invalid.");
				}
				log.debug("Preferred artifact type: (" + preferredArtifactType + ").");
			}

			// Load and verify the name mappings that should be used in
			// assertions for this RelyingParty

			NodeList nameIDs = ((Element) partyConfig).getElementsByTagNameNS(IdPConfig.configNameSpace, "NameID");
			// If no specification. Make sure we have a default mapping
			if (nameIDs.getLength() < 1) {
				if (nameMapper.getNameIdentifierMappingById(null) == null) {
					log.error("Relying Party NameId configuration not set.  Add a <NameID> element to <RelyingParty>.");
					throw new ServiceProviderMapperException("Required configuration not specified.");
				}

			} else {

				// We do have a specification, so make sure it points to a
				// valid Name Mapping

				for (int i = 0; i < nameIDs.getLength(); i++) {

					String mappingId = ((Element) nameIDs.item(i)).getAttribute("nameMapping");
					if (mappingId == null || mappingId.equals("")) {
						log.error("Name mapping not set.  Add a (nameMapping) attribute to <NameID>.");
						throw new ServiceProviderMapperException("Required configuration not specified.");
					}

					if (nameMapper.getNameIdentifierMappingById(mappingId) == null) {
						log.error("Relying Party NameID refers to a name mapping that is not loaded.");
						throw new ServiceProviderMapperException("Required configuration not specified.");
					}

					mappingIds.add(mappingId);
				}
			}

			// Load the credential for signing
			String credentialName = ((Element) partyConfig).getAttribute("signingCredential");
			Credential signingCredential = credentials.getCredential(credentialName);
			if (signingCredential == null) {
				if (credentialName == null || credentialName.equals("")) {
					log.error("Relying Party credential not set.  Add a (signingCredential) "
							+ "attribute to <RelyingParty>.");
					throw new ServiceProviderMapperException("Required configuration not specified.");
				} else {
					log.error("Relying Party credential invalid.  Fix the (signingCredential) attribute "
							+ "on <RelyingParty>.");
					throw new ServiceProviderMapperException("Required configuration is invalid.");
				}

			}

			// Initialize and Identity Provider object for this use by this relying party
			identityProvider = new RelyingPartyIdentityProvider(overridenIdPProviderId != null
					? overridenIdPProviderId
					: configuration.getProviderId(), signingCredential);

		}

		public String getProviderId() {

			return name;
		}

		public String getName() {

			return name;
		}

		public IdentityProvider getIdentityProvider() {

			return identityProvider;
		}

		public boolean isLegacyProvider() {

			return false;
		}

		public String[] getNameMapperIds() {

			return (String[]) mappingIds.toArray(new String[0]);
		}

		public URI getDefaultAuthMethod() {

			if (overridenDefaultAuthMethod != null) {
				return overridenDefaultAuthMethod;
			} else {
				return configuration.getDefaultAuthMethod();
			}
		}

		public URL getAAUrl() {

			if (overridenAAUrl != null) {
				return overridenAAUrl;
			} else {
				return configuration.getAAUrl();
			}
		}

		public boolean passThruErrors() {

			if (passThruIsOverriden) {
				return overridenPassThruErrors;
			} else {
				return configuration.passThruErrors();
			}
		}

		public boolean forceAttributePush() {

			return forceAttributePush;
		}

		public boolean forceAttributeNoPush() {

			return forceAttributeNoPush;
		}

		public boolean singleAssertion() {
			return singleAssertion;
		}
		
		public boolean defaultToPOSTProfile() {

			return defaultToPOST;
		}

		public boolean wantsAssertionsSigned() {

			return wantsAssertionsSigned;
		}

		public int getPreferredArtifactType() {

			return preferredArtifactType;
		}

		public String getDefaultTarget() {

			return defaultTarget;
		}

		public boolean wantsSchemaHack() {

			return wantsSchemaHack;
		}

		/**
		 * Default identity provider implementation.
		 * 
		 * @author Walter Hoehn
		 */
		protected class RelyingPartyIdentityProvider implements IdentityProvider {

			private String providerId;
			private Credential credential;

			public RelyingPartyIdentityProvider(String providerId, Credential credential) {

				this.providerId = providerId;
				this.credential = credential;
			}

			/*
			 * @see edu.internet2.middleware.shibboleth.common.IdentityProvider#getProviderId()
			 */
			public String getProviderId() {

				return providerId;
			}

			/*
			 * @see edu.internet2.middleware.shibboleth.common.IdentityProvider#getSigningCredential()
			 */
			public Credential getSigningCredential() {

				return credential;
			}
		}
	}

	/**
	 * Relying party implementation wrapper for relying parties that are groups.
	 * 
	 * @author Walter Hoehn
	 */
	class RelyingPartyGroupWrapper implements RelyingParty {

		private RelyingParty wrapped;
		private String providerId;

		RelyingPartyGroupWrapper(RelyingParty wrapped, String providerId) {

			this.wrapped = wrapped;
			this.providerId = providerId;
		}

		public String getName() {

			return wrapped.getName();
		}

		public boolean isLegacyProvider() {

			return false;
		}

		public IdentityProvider getIdentityProvider() {

			return wrapped.getIdentityProvider();
		}

		public String getProviderId() {

			return providerId;
		}

		public String[] getNameMapperIds() {

			return wrapped.getNameMapperIds();
		}

		public URL getAAUrl() {

			return wrapped.getAAUrl();
		}

		public URI getDefaultAuthMethod() {

			return wrapped.getDefaultAuthMethod();
		}

		public boolean passThruErrors() {

			return wrapped.passThruErrors();
		}

		public boolean forceAttributePush() {

			return wrapped.forceAttributePush();
		}

		public boolean forceAttributeNoPush() {

			return wrapped.forceAttributeNoPush();
		}

		public boolean singleAssertion() {
			
			return wrapped.singleAssertion();
		}
		
		public boolean defaultToPOSTProfile() {

			return wrapped.defaultToPOSTProfile();
		}

		public boolean wantsAssertionsSigned() {

			return wrapped.wantsAssertionsSigned();
		}

		public int getPreferredArtifactType() {

			return wrapped.getPreferredArtifactType();
		}

		public String getDefaultTarget() {

			return wrapped.getDefaultTarget();
		}

		public boolean wantsSchemaHack() {

			return wrapped.wantsSchemaHack();
		}
	}

	/**
	 * Relying party implementation wrapper for anonymous service providers.
	 * 
	 * @author Walter Hoehn
	 */
	protected class UnknownProviderWrapper implements RelyingParty {

		protected RelyingParty wrapped;
		protected String providerId;

		protected UnknownProviderWrapper(RelyingParty wrapped, String providerId) {

			this.wrapped = wrapped;
			this.providerId = providerId;
		}

		public String getName() {

			return wrapped.getName();
		}

		public IdentityProvider getIdentityProvider() {

			return wrapped.getIdentityProvider();
		}

		public String getProviderId() {

			return providerId;
		}

		public String[] getNameMapperIds() {

			return wrapped.getNameMapperIds();
		}

		public boolean isLegacyProvider() {

			return wrapped.isLegacyProvider();
		}

		public URL getAAUrl() {

			return wrapped.getAAUrl();
		}

		public URI getDefaultAuthMethod() {

			return wrapped.getDefaultAuthMethod();
		}

		public boolean passThruErrors() {

			return wrapped.passThruErrors();
		}

		public boolean forceAttributePush() {

			return false;
		}

		public boolean forceAttributeNoPush() {

			return false;
		}

		public boolean singleAssertion() {
			
			return false;
		}
		
		public boolean defaultToPOSTProfile() {

			return true;
		}

		public boolean wantsAssertionsSigned() {

			return wrapped.wantsAssertionsSigned();
		}

		public int getPreferredArtifactType() {

			return wrapped.getPreferredArtifactType();
		}

		public String getDefaultTarget() {

			return wrapped.getDefaultTarget();
		}

		public boolean wantsSchemaHack() {

			return wrapped.wantsSchemaHack();
		}
	}

	/**
	 * Relying party wrapper for Shibboleth &lt;=1.1 service providers.
	 * 
	 * @author Walter Hoehn
	 */
	class LegacyWrapper extends UnknownProviderWrapper implements RelyingParty {

		LegacyWrapper(RelyingParty wrapped) {

			super(wrapped, null);
		}

		public boolean isLegacyProvider() {

			return true;
		}

		public String[] getNameMapperIds() {

			return ((RelyingParty) wrapped).getNameMapperIds();
		}

		public URL getAAUrl() {

			return ((RelyingParty) wrapped).getAAUrl();
		}

		public URI getDefaultAuthMethod() {

			return ((RelyingParty) wrapped).getDefaultAuthMethod();
		}
	}

	/**
	 * Relying party wrapper for providers for which we have no metadata
	 * 
	 * @author Walter Hoehn
	 */
	class NoMetadataWrapper extends UnknownProviderWrapper implements RelyingParty {

		NoMetadataWrapper(RelyingParty wrapped) {

			super(wrapped, null);
		}

		public String[] getNameMapperIds() {

			return ((RelyingParty) wrapped).getNameMapperIds();
		}

		public URL getAAUrl() {

			return ((RelyingParty) wrapped).getAAUrl();
		}

		public URI getDefaultAuthMethod() {

			return ((RelyingParty) wrapped).getDefaultAuthMethod();
		}
	}
}