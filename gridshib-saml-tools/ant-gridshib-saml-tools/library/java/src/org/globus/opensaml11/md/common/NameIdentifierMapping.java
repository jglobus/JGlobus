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

import java.net.URI;
import java.security.Principal;

import org.globus.opensaml11.saml.SAMLNameIdentifier;

/**
 * Defines a mechanism for converting back and forth between SAML Name Identifiers and local {@link LocalPrincipal}
 * objects.
 * 
 * @author Walter Hoehn
 */
public interface NameIdentifierMapping {

	public static final String mappingNamespace = "urn:mace:shibboleth:namemapper:1.0";

	/**
	 * @return the id of this mapping or <code>null</code> is it is not configured with one
	 */
	public String getId();

	/**
	 * Returns the Name Identifier format for this mapping.
	 * 
	 * @return the format
	 */
	public URI getNameIdentifierFormat();

	/**
	 * Maps a SAML Name Identifier to a local principal using the appropriate registered mapping. Must ensure that the
	 * SAML NameIdentifer is properly qualified.
	 * 
	 * @param nameId
	 *            the SAML Name Identifier that should be converted
	 * @param sProv
	 *            the provider initiating the request
	 * @param idProv
	 *            the provider handling the request
	 * @return the local principal
	 * @throws NameIdentifierMappingException
	 *             If the {@link NameMapper}encounters an internal error
	 * @throws InvalidNameIdentifierException
	 *             If the {@link SAMLNameIdentifier}contains invalid data
	 */
	public Principal getPrincipal(SAMLNameIdentifier nameId, ServiceProvider sProv, IdentityProvider idProv)
			throws NameIdentifierMappingException, InvalidNameIdentifierException;

	/**
	 * Maps a local principal to a SAML Name Identifier.
	 * 
	 * @param principal
	 *            the principal to map
	 * @param sProv
	 *            the provider initiating the request
	 * @param idProv
	 *            the provider handling the request
	 * @return the SAML name identifier
	 * @throws NameIdentifierMappingException
	 *             If the {@link NameMapper}encounters an internal error
	 */
	public SAMLNameIdentifier getNameIdentifier(LocalPrincipal principal, ServiceProvider sProv, IdentityProvider idProv)
			throws NameIdentifierMappingException;

	/**
	 * Cleanup resources that won't be released when this object is garbage-collected
	 */
	public void destroy();

}