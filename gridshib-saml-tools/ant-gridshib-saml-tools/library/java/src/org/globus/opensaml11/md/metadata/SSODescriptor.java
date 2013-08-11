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

import java.util.Iterator;

/**
 * <p>
 * Corresponds to SAML Metadata Schema "SSODescriptorType".
 * </p>
 * <p>
 * Base class with common behavior among SP and IdP roles.
 * 
 * @author Scott Cantor
 */
public interface SSODescriptor extends RoleDescriptor {

	public EndpointManager getArtifactResolutionServiceManager();

	public EndpointManager getSingleLogoutServiceManager();

	public EndpointManager getManageNameIDServiceManager();

	public Iterator /* <String> */getNameIDFormats();
}
