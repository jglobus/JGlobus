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

/*
 * import org.apache.xml.security.keys.KeyInfo;
 */

/**
 * Shibboleth metadata extension for defining a set of "authorities" in the form of ds:KeyInfo objects and an associated
 * Depth limit.
 * 
 * @author Scott Cantor
 */
public interface KeyAuthority {

	/**
	 * Limits the length of the path validation chains that should be built using any of these authorities.
	 * 
	 * @return The depth limit
	 */
	public int getVerifyDepth();

	/**
	 * Returns a set of ds:KeyInfo objects representing the authorities. No constraints on key representation are
	 * enforced at this layer.
	 * 
	 * @return An iterator of KeyInfo objects
	 * @see org.apache.xml.security.keys.KeyInfo
	 */
	public Iterator /* <org.apache.xml.security.keys.KeyInfo> */getKeyInfos();
}
