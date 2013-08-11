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

import org.globus.opensaml11.saml.artifact.Artifact;

/**
 * Ported from Scott Cantor's C++ interfaces
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public interface Metadata {

	/**
	 * Find an entity descriptor by its unique identifier.
	 * 
	 * @param id	The unique identifier of the site of interest
	 * @param strict Honor metadata validity information?
	 *             
	 * @return The corresponding entity
	 */
	EntityDescriptor lookup(String id, boolean strict);

	/**
	 * Find an entity descriptor that issued a SAML artifact.
	 * 
	 * @param artifact	The artifact whose source site is of interest
	 * @param strict Honor metadata validity information?

	 * @return The issuing entity
	 */
	EntityDescriptor lookup(Artifact artifact, boolean strict);

	/**
	 * Find an entity descriptor by its unique identifier.
	 * 
	 * @param id
	 *            The unique identifier of the site of interest
	 * @return The corresponding entity
	 */
	EntityDescriptor lookup(String id);

	/**
	 * Find an entity descriptor that issued a SAML artifact.
	 * 
	 * @param artifact
	 *            The artifact whose source site is of interest
	 * @return The issuing entity
	 */
	EntityDescriptor lookup(Artifact artifact);

	/**
	 * 	Get access to the root entity in the metadata instance,
	 * 	or null if the root is a group.
	 * 
	 * @return	The root entity, if any
	 */
	EntityDescriptor getRootEntity();

	/**
	 * 	Get access to the root entity group in the metadata instance,
	 * 	or null if the root is a single entity.
	 * 
	 * @return	The root group, if any
	 */
	EntitiesDescriptor getRootEntities();
}
