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

package org.globus.opensaml11.md.metadata.provider;

import org.w3c.dom.Element;
import org.globus.opensaml11.md.common.ShibResource.ResourceNotAvailableException;
import org.globus.opensaml11.md.metadata.MetadataException;

/**
 * @author Walter Hoehn (wassa@columbia.edu)
 * 
 * Class left in as a deprecated mechanism to install metadata in older config files.
 */
public class XMLMetadataLoadWrapper extends XMLMetadata {

	public XMLMetadataLoadWrapper(String sitesFileLocation) throws MetadataException, ResourceNotAvailableException {

		super(sitesFileLocation);
	}

	public XMLMetadataLoadWrapper(Element configuration) throws MetadataException, ResourceNotAvailableException {

		super(configuration);
	}
}
