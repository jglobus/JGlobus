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

import java.security.Principal;

import org.apache.log4j.Logger;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLNameIdentifier;
import org.w3c.dom.Element;

import org.globus.opensaml11.md.common.IdentityProvider;
import org.globus.opensaml11.md.common.InvalidNameIdentifierException;
import org.globus.opensaml11.md.common.LocalPrincipal;
import org.globus.opensaml11.md.common.NameIdentifierMapping;
import org.globus.opensaml11.md.common.NameIdentifierMappingException;
import org.globus.opensaml11.md.common.ServiceProvider;

/**
 * {@link NameIdentifierMapping}implementation to use when the SAML name identifier format matches the Shibboleth
 * internal representation of the principal.
 * 
 * @author Walter Hoehn
 */
public class PrincipalNameIdentifier extends BaseNameIdentifierMapping {

	private static Logger log = Logger.getLogger(PrincipalNameIdentifier.class.getName());

	public PrincipalNameIdentifier(Element config) throws NameIdentifierMappingException {

		super(config);
	}

	public Principal getPrincipal(SAMLNameIdentifier nameId, ServiceProvider sProv, IdentityProvider idProv)
			throws NameIdentifierMappingException, InvalidNameIdentifierException {

		verifyQualifier(nameId, idProv);
		return new LocalPrincipal(nameId.getName());
	}

	public SAMLNameIdentifier getNameIdentifier(LocalPrincipal principal, ServiceProvider sProv, IdentityProvider idProv)
			throws NameIdentifierMappingException {

		if (principal == null) {
			log.error("A principal must be supplied for Name Identifier creation.");
			throw new IllegalArgumentException("A principal must be supplied for Name Identifier creation.");
		}

		try {
			SAMLNameIdentifier nameid = SAMLNameIdentifier.getInstance(getNameIdentifierFormat().toString());
			nameid.setName(principal.getName());
			nameid.setNameQualifier(idProv.getProviderId());
			return nameid;
		} catch (SAMLException e) {
			throw new NameIdentifierMappingException("Unable to generate Name Identifier: " + e);
		}
	}
}