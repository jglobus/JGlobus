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

import java.net.URL;
import java.util.Iterator;

/**
 * <p>
 * Corresponds to SAML Metadata Schema "RoleDescriptorType".
 * </p>
 * <p>
 * A child of the EntityDescriptor element (the Provider object). Example Roles are IDP (Identity Provider),
 * Authentication Authority (HS), Attribute Authority (AA), SP
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public interface RoleDescriptor {

	public EntityDescriptor getEntityDescriptor(); // parent EntityDescriptor

	public Iterator /* <String> */getProtocolSupportEnumeration();

	public boolean hasSupport(final String version); // does role support protocol?

	public boolean isValid(); // is role valid?

	public URL getErrorURL();

	public Iterator /* <KeyDescriptor> */getKeyDescriptors(); // direct or indirect key references

	public Organization getOrganization(); // associated organization

	public Iterator /* <ContactPerson> */getContactPersons();

	public Element getElement(); // punch through to XML content if permitted
}
