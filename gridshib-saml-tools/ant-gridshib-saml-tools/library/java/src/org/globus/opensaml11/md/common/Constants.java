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
 * @author Scott Cantor
 * 
 */
public class Constants {
	
	public static final String SHIB_VERSION = "1.3";

	/** Shibboleth "transient" NameIdentifier Format */
	public static final String SHIB_NAMEID_FORMAT_URI = "urn:mace:shibboleth:1.0:nameIdentifier";

	/** Shibboleth attribute profile AttributeNamespace */
	public static final String SHIB_ATTRIBUTE_NAMESPACE_URI = "urn:mace:shibboleth:1.0:attributeNamespace:uri";

	/** Shibboleth AuthnRequest profile URI */
	public static final String SHIB_AUTHNREQUEST_PROFILE_URI = "urn:mace:shibboleth:1.0:profiles:AuthnRequest";
}
