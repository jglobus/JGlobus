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

import org.apache.xml.security.keys.KeyInfo;

/**
 * <p>
 * Corresponds to SAML Metadata Schema "KeyDescriptorType".
 * </p>
 * <p>
 * Provides information about the cryptographic keys that an EntityDescriptor/Provider uses to sign data. However, this
 * is nested inside a RoleDescriptor instead of appearing at the EntityDescriptor level.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public interface KeyDescriptor {

	public final static int UNSPECIFIED = -1;
	public final static int ENCRYPTION = 0;
	public final static int SIGNING = 1;

	public int getUse();

	public KeyInfo getKeyInfo();

	public Iterator /* <org.apache.xml.security.encryption.EncryptionMethod.EncryptionMethod> */getEncryptionMethods();
}
