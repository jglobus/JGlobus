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

import org.w3c.dom.Element;

/**
 * Defines a method for loading a credential from a particular storage mechanism.
 * 
 * @author Walter Hoehn
 */
public interface CredentialResolver {

	/**
	 * Loads a credential as specified by the XML configuration.
	 * 
	 * @param e
	 *            DOM representation of credential resolver configuration
	 * 
	 * @return the credential
	 * 
	 * @throws CredentialFactoryException
	 *             if the credential could not be loaded
	 */
	Credential loadCredential(Element e) throws CredentialFactoryException;
}
