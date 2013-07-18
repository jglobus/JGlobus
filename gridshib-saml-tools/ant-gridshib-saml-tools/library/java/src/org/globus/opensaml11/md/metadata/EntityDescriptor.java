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

package org.globus.opensaml11.md.metadata;

import org.w3c.dom.Element;

import java.util.Iterator;
import java.util.Map;

/**
 * <p>
 * Corresponds to SAML Metadata Schema "EntityDescriptorType".
 * </p>
 * <p>
 * Entities are campuses or departments with either an origin or target infrastructure (or both). Each implemented
 * component (HS, AA, SHAR) has a Role definition with URLs and PKI to locate and authenticate the provider of that
 * role. Although the Metadata may define all roles, target code tends to build objects describing origins, and origins
 * are only interested in targets.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public interface EntityDescriptor {

	public String getId(); // Unique ID used as global key of Provider

	public boolean isValid(); // Is this entity descriptor "active"?

	public Iterator /* <RoleDescriptor> */getRoleDescriptors(); // Role definitions

	/**
	 * Finds a role descriptor of a particular type that supports the specified protocol.
	 * 
	 * @param type
	 *            The type of role to locate
	 * @param protocol
	 *            The protocol constant that must be supported
	 * @return The matching role decsriptor, if any
	 */
	public RoleDescriptor getRoleByType(Class type, String protocol);

	public IDPSSODescriptor getIDPSSODescriptor(String protocol);

	public SPSSODescriptor getSPSSODescriptor(String protocol);

	public AuthnAuthorityDescriptor getAuthnAuthorityDescriptor(String protocol);

	public AttributeAuthorityDescriptor getAttributeAuthorityDescriptor(String protocol);

	public AttributeRequesterDescriptor getAttributeRequesterDescriptor(String protocol);

	public PDPDescriptor getPDPDescriptor(String protocol);

	public AffiliationDescriptor getAffiliationDescriptor();

	public Organization getOrganization(); // associated organization

	public Iterator /* <ContactPerson> */getContactPersons(); // support contacts

	public Map /* <String,String> */getAdditionalMetadataLocations(); // XML Namespace - location pairs

	public EntitiesDescriptor getEntitiesDescriptor(); // parent group, if any

	public Element getElement(); // punch through to raw XML, if enabled
}
