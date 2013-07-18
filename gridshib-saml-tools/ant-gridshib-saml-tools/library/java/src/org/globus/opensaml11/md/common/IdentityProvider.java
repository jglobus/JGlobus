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

/**
 * Defines a producer of SAML authentication and attribute assertions. A single instantiation of the Shibboleth IdP
 * software may represent more than one logical identity provider.
 * 
 * @see ServiceProvider
 * @author Walter Hoehn
 */
public interface IdentityProvider {

	/**
	 * Returns the unique identifier for the indentity provider.
	 * 
	 * @return the provider ID
	 */
	public String getProviderId();

	/**
	 * Returns the credential that this provider uses to sign SAML responses and assertions.
	 * 
	 * @return the credential
	 */
	public Credential getSigningCredential();

}