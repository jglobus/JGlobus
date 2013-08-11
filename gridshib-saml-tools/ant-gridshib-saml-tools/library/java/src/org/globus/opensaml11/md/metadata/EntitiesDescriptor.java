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

/**
 * <p>
 * Corresponds to SAML Metadata Schema "EntitiesDescriptorType".
 * </p>
 * <p>
 * Groups multiple entities into a named set for policy/configuration
 * 
 * @author Scott Cantor
 */
public interface EntitiesDescriptor {

	public String getName(); // name of group

	public boolean isValid(); // Is this group "active"?

	public EntitiesDescriptor getEntitiesDescriptor(); // parent group, if any

	public Iterator /* <EntitiesDescriptor> */getEntitiesDescriptors(); // child groups, if any

	public Iterator /* <EntityDescriptor> */getEntityDescriptors(); // child entities, if any

	public Element getElement(); // punch through to raw XML, if enabled
}
