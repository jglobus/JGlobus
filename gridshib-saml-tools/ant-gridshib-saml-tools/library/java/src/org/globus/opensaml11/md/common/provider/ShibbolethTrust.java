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

import org.globus.opensaml11.md.common.PluggableConfigurationComponent;
import org.globus.opensaml11.md.common.ShibbolethConfigurationException;
import org.globus.opensaml11.md.common.Trust;
import org.globus.opensaml11.md.metadata.EntitiesDescriptor;
import org.globus.opensaml11.md.metadata.EntityDescriptor;
import org.globus.opensaml11.md.metadata.ExtendedEntitiesDescriptor;
import org.globus.opensaml11.md.metadata.ExtendedEntityDescriptor;
import org.globus.opensaml11.md.metadata.KeyAuthority;
import org.globus.opensaml11.md.metadata.KeyDescriptor;
import org.globus.opensaml11.md.metadata.RoleDescriptor;
import org.apache.log4j.Logger;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.KeyName;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509CRL;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERString;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLSignedObject;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * <code>Trust</code> implementation that does PKIX validation against key authorities included in shibboleth-specific
 * extensions to SAML 2 metadata.
 * 
 * @author Walter Hoehn
 */
public class ShibbolethTrust extends BasicTrust implements Trust, PluggableConfigurationComponent {

	private static Logger log = Logger.getLogger(ShibbolethTrust.class.getName());
	private static final String CN_OID = "2.5.4.3";

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

		if (super.validate(token, descriptor)) return true;

		/* Certificates supplied with the signed object */
		ArrayList/* <X509Certificate> */certificates = new ArrayList/* <X509Certificate> */();
		X509Certificate certificateEE = null;

		/* Iterate to count the certificates, and look for the signer */
		Iterator icertificates;
		try {
			icertificates = token.getX509Certificates();
		} catch (SAMLException e1) {
			return false;
		}
		while (icertificates.hasNext()) {
			X509Certificate certificate = (X509Certificate) icertificates.next();
			try {
				token.verify(certificate);
				// This is the certificate that signed the object
				certificateEE = certificate;
				certificates.add(certificate);
			} catch (SAMLException e) {
				certificates.add(certificate);
			}
		}

		if (certificateEE == null) return false; // No key validates the signature

		// With a count we can now build a typed array
		X509Certificate[] certificateChain = new X509Certificate[certificates.size()];
		int i = 0;
		for (icertificates = certificates.iterator(); icertificates.hasNext();) {
			certificateChain[i++] = (X509Certificate) icertificates.next();
		}
		return validate(certificateEE, certificateChain, descriptor);
	}

	/*
	 * @see edu.internet2.middleware.shibboleth.common.Trust#validate(java.security.cert.X509Certificate,
	 *      java.security.cert.X509Certificate[], edu.internet2.middleware.shibboleth.metadata.RoleDescriptor, boolean)
	 */
	public boolean validate(X509Certificate certificateEE, X509Certificate[] certificateChain,
			RoleDescriptor descriptor, boolean checkName) {

		// If we can successfully validate with an inline key, that's fine
		boolean defaultValidation = super.validate(certificateEE, certificateChain, descriptor, checkName);
		if (defaultValidation == true) { return true; }

		// Make sure we have the data we need
		if (descriptor == null || certificateEE == null) {
			log.error("Appropriate data was not supplied for trust evaluation.");
			return false;
		}
		log.debug("Inline validation was unsuccessful.  Attmping PKIX...");
		// If not, try PKIX validation against the shib-custom metadata extensions

		// First, we want to see if we can match a keyName from the metadata against the cert
		// Iterator through all the keys in the metadata
		if (checkName) {

			if (matchProviderId(certificateChain[0], descriptor.getEntityDescriptor().getId())) {
				checkName = false;
			} else {

				Iterator keyDescriptors = descriptor.getKeyDescriptors();
				while (checkName && keyDescriptors.hasNext()) {
					// Look for a key descriptor with the right usage bits
					KeyDescriptor keyDescriptor = (KeyDescriptor) keyDescriptors.next();
					if (keyDescriptor.getUse() == KeyDescriptor.ENCRYPTION) {
						log.debug("Skipping key descriptor with inappropriate usage indicator.");
						continue;
					}

					// We found one, see if we can match the metadata's keyName against the cert
					KeyInfo keyInfo = keyDescriptor.getKeyInfo();
					if (keyInfo.containsKeyName()) {
						for (int i = 0; i < keyInfo.lengthKeyName(); i++) {
							try {
								if (matchKeyName(certificateChain[0], keyInfo.itemKeyName(i))) {
									checkName = false;
									break;
								}
							} catch (XMLSecurityException e) {
								log.error("Problem retrieving key name from metadata: " + e);
							}
						}
					}
				}
			}
		}

		if (checkName) {
			log.error("cannot match certificate subject against acceptable key names based on the "
					+ "metadata entityId or KeyDescriptors");
			return false;
		}

		if (pkixValidate(certificateEE, certificateChain, descriptor.getEntityDescriptor())) { return true; }
		return false;
	}

	private boolean pkixValidate(X509Certificate certEE, X509Certificate[] certChain, EntityDescriptor entity) {

		if (entity instanceof ExtendedEntityDescriptor) {
			Iterator keyAuthorities = ((ExtendedEntityDescriptor) entity).getKeyAuthorities();
			// if we have any key authorities, construct a flat list of trust anchors representing each and attempt to
			// validate against them in turn
			while (keyAuthorities.hasNext()) {
				if (pkixValidate(certEE, certChain, (KeyAuthority) keyAuthorities.next())) { return true; }
			}
		}

		// We couldn't do path validation based on metadata attached to the entity, we now need to walk up the chain of
		// nested entities and attempt to validate at each group level
		EntitiesDescriptor group = entity.getEntitiesDescriptor();
		if (group != null) {
			if (pkixValidate(certEE, certChain, group)) { return true; }
		}

		// We've walked the entire metadata chain with no success, so fail
		return false;
	}

	private boolean pkixValidate(X509Certificate certEE, X509Certificate[] certChain, EntitiesDescriptor group) {

		log.debug("Attemping to validate against parent group.");
		if (group instanceof ExtendedEntitiesDescriptor) {
			Iterator keyAuthorities = ((ExtendedEntitiesDescriptor) group).getKeyAuthorities();
			// if we have any key authorities, construct a flat list of trust anchors representing each and attempt to
			// validate against them in turn
			while (keyAuthorities.hasNext()) {
				if (pkixValidate(certEE, certChain, (KeyAuthority) keyAuthorities.next())) { return true; }
			}
		}

		// If not, attempt to walk up the chain for validation
		EntitiesDescriptor parent = group.getEntitiesDescriptor();
		if (parent != null) {
			if (pkixValidate(certEE, certChain, parent)) { return true; }
		}

		return false;
	}

	private boolean pkixValidate(X509Certificate certEE, X509Certificate[] certChain, KeyAuthority authority) {

		Set anchors = new HashSet();
		Set crls = new HashSet();
		Iterator keyInfos = authority.getKeyInfos();
		while (keyInfos.hasNext()) {
			KeyInfo keyInfo = (KeyInfo) keyInfos.next();
			if (keyInfo.containsX509Data()) {
				try {
					// Add all certificates in the authority as trust anchors
					for (int i = 0; i < keyInfo.lengthX509Data(); i++) {
						X509Data data = keyInfo.itemX509Data(i);
						if (data.containsCertificate()) {
							for (int j = 0; j < data.lengthCertificate(); j++) {
								XMLX509Certificate xmlCert = data.itemCertificate(j);
								anchors.add(new TrustAnchor(xmlCert.getX509Certificate(), null));
							}
						}
						// Compile all CRLs in the authority
						if (data.containsCRL()) {
							for (int j = 0; j < data.lengthCRL(); j++) {
								XMLX509CRL xmlCrl = data.itemCRL(j);
								try {
									X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(
											new ByteArrayInputStream(xmlCrl.getCRLBytes()));
									if (crl.getRevokedCertificates() != null && crl.getRevokedCertificates().size() > 0) {
										crls.add(crl);
									}
								} catch (GeneralSecurityException e) {
									log.error("Encountered an error parsing CRL from shibboleth metadata: " + e);
								}
							}
						}
					}

				} catch (XMLSecurityException e) {
					log.error("Encountered an error constructing trust list from shibboleth metadata: " + e);
				}
			}
		}

		// alright, if we were able to create a trust list, attempt a pkix validation against the list
		if (anchors.size() > 0) {
			log.debug("Constructed a trust list from key authority.  Attempting path validation...");
			try {
				CertPathValidator validator = CertPathValidator.getInstance("PKIX");

				X509CertSelector selector = new X509CertSelector();
				selector.setCertificate(certEE);
				PKIXBuilderParameters params = new PKIXBuilderParameters(anchors, selector);
				params.setMaxPathLength(authority.getVerifyDepth());
				List storeMaterial = new ArrayList(crls);
				storeMaterial.addAll(Arrays.asList(certChain));
				CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(storeMaterial));
				List stores = new ArrayList();
				stores.add(store);
				params.setCertStores(stores);
				if (crls.size() > 0) {
					params.setRevocationEnabled(true);
				} else {
					params.setRevocationEnabled(false);
				}
				// System.err.println(params.toString());
				CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
				PKIXCertPathBuilderResult buildResult = (PKIXCertPathBuilderResult) builder.build(params);

				PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(buildResult
						.getCertPath(), params);
				log.debug("Path successfully validated.");
				return true;

			} catch (CertPathValidatorException e) {
				log.debug("Path failed to validate: " + e);
			} catch (GeneralSecurityException e) {
				log.error("Encountered an error during validation: " + e);
			}
		}
		return false;
	}

	private static boolean matchKeyName(X509Certificate certificate, KeyName keyName) {

		// First, try to match DN against metadata
		try {
			if (certificate.getSubjectX500Principal().getName(X500Principal.RFC2253).equals(
					new X500Principal(keyName.getKeyName()).getName(X500Principal.RFC2253))) {
				log.debug("Matched against DN.");
				return true;
			}
		} catch (IllegalArgumentException iae) {
			// squelch this runtime exception, since
			// this might be a valid case
		}

		// If that doesn't work, we try matching against
		// some Subject Alt Names
		try {
			Collection altNames = certificate.getSubjectAlternativeNames();
			if (altNames != null) {
				for (Iterator nameIterator = altNames.iterator(); nameIterator.hasNext();) {
					List altName = (List) nameIterator.next();
					if (altName.get(0).equals(new Integer(2)) || altName.get(0).equals(new Integer(6))) {
						// 2 is DNS, 6 is URI
						if (altName.get(0).equals(keyName.getKeyName())) {
							log.debug("Matched against SubjectAltName.");
							return true;
						}
					}
				}
			}
		} catch (CertificateParsingException e1) {
			log.error("Encountered an problem trying to extract Subject Alternate "
					+ "Name from supplied certificate: " + e1);
		}

		// If that doesn't work, try to match using
		// SSL-style hostname matching
		if (getHostNameFromDN(certificate.getSubjectX500Principal()).equals(keyName.getKeyName())) {
			log.debug("Matched against hostname.");
			return true;
		}

		return false;
	}

	public static String[] getCredentialNames(X509Certificate certificate) {
		ArrayList names = new ArrayList();
		names.add(certificate.getSubjectX500Principal().getName(X500Principal.RFC2253));
		try {
			Collection altNames = certificate.getSubjectAlternativeNames();
			if (altNames != null) {
				for (Iterator nameIterator = altNames.iterator(); nameIterator.hasNext();) {
					List altName = (List) nameIterator.next();
					if (altName.get(0).equals(new Integer(2))) { // 2 is DNS
						names.add(altName.get(1));
					}
					else if (altName.get(0).equals(new Integer(6))) { // 6 is URI
						names.add(altName.get(1));
					}
				}
			}
		} catch (CertificateParsingException e1) {
			log.error("Encountered an problem trying to extract Subject Alternate "
					+ "Name from supplied certificate: " + e1);
		}
		names.add(getHostNameFromDN(certificate.getSubjectX500Principal()));
		return (String[]) names.toArray(new String[1]);
	}
	
	private static boolean matchProviderId(X509Certificate certificate, String id) {

		// Try matching against URI Subject Alt Names
		try {
			Collection altNames = certificate.getSubjectAlternativeNames();
			if (altNames != null) {
				for (Iterator nameIterator = altNames.iterator(); nameIterator.hasNext();) {
					List altName = (List) nameIterator.next();
					if (altName.get(0).equals(new Integer(6))) { // 6 is URI
						if (altName.get(1).equals(id)) {
							log.debug("Entity ID matched against SubjectAltName.");
							return true;
						}
					}
				}
			}
		} catch (CertificateParsingException e1) {
			log.error("Encountered an problem trying to extract Subject Alternate "
					+ "Name from supplied certificate: " + e1);
		}

		// If that doesn't work, try to match using
		// SSL-style hostname matching
		if (getHostNameFromDN(certificate.getSubjectX500Principal()).equals(id)) {
			log.debug("Entity ID matched against hostname.");
			return true;
		}

		return false;
	}

	public static String getHostNameFromDN(X500Principal dn) {

		// Parse the ASN.1 representation of the dn and grab the last CN component that we find
		// We used to do this with the dn string, but the JDK's default parsing caused problems with some DNs
		try {

            // tfreeman: needed to add this to match Globus' bounycastle
            // lib.  ASN1InputStream's constructor cannot take byte[]
            // directly (dn.getEncoded() returns byte[] )
            ByteArrayInputStream bais = new ByteArrayInputStream(dn.getEncoded());

            ASN1InputStream asn1Stream = new ASN1InputStream(bais);
			DERObject parent = asn1Stream.readObject();

			if (!(parent instanceof DERSequence)) {
				log.error("Unable to extract host name name from certificate subject DN: incorrect ASN.1 encoding.");
				return null;
			}

			String cn = null;
			for (int i = 0; i < ((DERSequence) parent).size(); i++) {
				DERObject dnComponent = ((DERSequence) parent).getObjectAt(i).getDERObject();
				if (!(dnComponent instanceof DERSet)) {
					log.debug("No DN components.");
					continue;
				}

				// Each DN component is a set
				for (int j = 0; j < ((DERSet) dnComponent).size(); j++) {
					DERObject grandChild = ((DERSet) dnComponent).getObjectAt(j).getDERObject();

					if (((DERSequence) grandChild).getObjectAt(0) != null
							&& ((DERSequence) grandChild).getObjectAt(0).getDERObject() instanceof DERObjectIdentifier) {
						DERObjectIdentifier componentId = (DERObjectIdentifier) ((DERSequence) grandChild).getObjectAt(
								0).getDERObject();

						if (CN_OID.equals(componentId.getId())) {
							// OK, this dn component is actually a cn attribute
							if (((DERSequence) grandChild).getObjectAt(1) != null
									&& ((DERSequence) grandChild).getObjectAt(1).getDERObject() instanceof DERString) {
								cn = ((DERString) ((DERSequence) grandChild).getObjectAt(1).getDERObject()).getString();
							}
						}
					}
				}
			}
			asn1Stream.close();
			return cn;

		} catch (IOException e) {
			log.error("Unable to extract host name name from certificate subject DN: ASN.1 parsing failed: " + e);
			return null;
		}
	}

// tfreeman: removed xmlbeans dependence, lone use of XmlException
//	public void initialize(Node dom) throws XmlException, ShibbolethConfigurationException {
//
//	}

	public void initialize(Element dom) throws SAMLException, ShibbolethConfigurationException {
		
	}

}