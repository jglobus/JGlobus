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

package org.globus.opensaml11.md.common.provider;

import org.apache.log4j.Logger;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.globus.opensaml11.md.common.Trust;
import org.globus.opensaml11.md.metadata.KeyDescriptor;
import org.globus.opensaml11.md.metadata.RoleDescriptor;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLSignedObject;

import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Iterator;

/**
 * <code>Trust</code> implementation that validates against standard inline keying data within SAML 2 metadata.
 * 
 * @author Walter Hoehn
 */
public class BasicTrust implements Trust {

	private static Logger log = Logger.getLogger(BasicTrust.class.getName());

	/*
	 * @see edu.internet2.middleware.shibboleth.common.Trust#validate(java.security.cert.X509Certificate,
	 *      java.security.cert.X509Certificate[], edu.internet2.middleware.shibboleth.metadata.RoleDescriptor, boolean)
	 */
	public boolean validate(X509Certificate certificateEE, X509Certificate[] certificateChain,
			RoleDescriptor descriptor, boolean checkName) {

		if (descriptor == null || certificateEE == null) {
			log.error("Appropriate data was not supplied for trust evaluation.");
			return false;
		}

		// Iterator through all the keys in the metadata
		Iterator keyDescriptors = descriptor.getKeyDescriptors();
		while (keyDescriptors.hasNext()) {
			// Look for a key descriptor with the right usage bits
			KeyDescriptor keyDescriptor = (KeyDescriptor) keyDescriptors.next();
			if (keyDescriptor.getUse() == KeyDescriptor.ENCRYPTION) {
				log.debug("Skipping key descriptor with inappropriate usage indicator.");
				continue;
			}

			// We found one, attempt to do an exact match between the metadata certificate
			// and the supplied end-entity certificate
			KeyInfo keyInfo = keyDescriptor.getKeyInfo();
			if (keyInfo.containsX509Data()) {
				log.debug("Attempting to match X509 certificate.");
				try {
					X509Certificate metaCert = keyInfo.getX509Certificate();
					if (Arrays.equals(metaCert.getEncoded(), certificateEE.getEncoded())) {
						log.debug("Match successful.");
						return true;
					} else {
						log.debug("Certificate did not match.");
					}

				} catch (KeyResolverException e) {
					log.error("Error extracting X509 certificate from metadata.");
				} catch (CertificateEncodingException e) {
					log.error("Error while comparing X509 encoded data.");
				}
			}
		}
		return false;
	}

	/*
	 * @see edu.internet2.middleware.shibboleth.common.Trust#validate(java.security.cert.X509Certificate,
	 *      java.security.cert.X509Certificate[], edu.internet2.middleware.shibboleth.metadata.RoleDescriptor)
	 */
	public boolean validate(X509Certificate certificateEE, X509Certificate[] certificateChain, RoleDescriptor descriptor) {

		return validate(certificateEE, certificateChain, descriptor, true);
	}

	/*
	 * @see edu.internet2.middleware.shibboleth.common.Trust#validate(org.globus.opensaml11.saml.SAMLSignedObject,
	 *      edu.internet2.middleware.shibboleth.metadata.RoleDescriptor)
	 */
	public boolean validate(SAMLSignedObject token, RoleDescriptor descriptor) {

		/*
		 * Run through the Role Metadata testing Public Keys
		 */
		Iterator ikeyDescriptors = descriptor.getKeyDescriptors();
		while (ikeyDescriptors.hasNext()) {
			KeyDescriptor keyDescriptor = (KeyDescriptor) ikeyDescriptors.next();
			if (keyDescriptor.getUse() != KeyDescriptor.ENCRYPTION) {
				// KeyInfo can be used for signing
				KeyInfo keyInfo = keyDescriptor.getKeyInfo();
				try {
					// XMLSEC drills down to extract a Public Key
					PublicKey publicKey = keyInfo.getPublicKey();
					try {
						token.verify(publicKey);
						return true;
					} catch (SAMLException e) {
						continue;
					}
				} catch (KeyResolverException e) {
					continue;
				}
			}
		}
		return false;
	}
}