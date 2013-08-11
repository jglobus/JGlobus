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

package org.globus.opensaml11.md.common;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Uses {@link CredentialResolver}implementations to create {@link Credential}s.
 * 
 * @author Walter Hoehn
 */
public class Credentials {

	public static final String credentialsNamespace = "urn:mace:shibboleth:credentials:1.0";

	private static Logger log = Logger.getLogger(Credentials.class.getName());
	private Hashtable data = new Hashtable();
	private boolean singleMode = false;

	/**
	 * Creates credentials based on XML configuration.
	 * 
	 * @param e
	 *            DOM representation of credentials configuration
	 */
	public Credentials(Element e) {

		if (e != null && e.getLocalName().equals("Credential")) {
			singleMode = true;
		} else if (e == null || !e.getLocalName().equals("Credentials")) { throw new IllegalArgumentException(); }

		NodeList resolverNodes = e.getChildNodes();
		if (resolverNodes.getLength() <= 0) {
			log.error("Credentials configuration inclues no Credential Resolver definitions.");
			throw new IllegalArgumentException("Cannot load credentials.");
		}

		for (int i = 0; resolverNodes.getLength() > i; i++) {
			if (resolverNodes.item(i).getNodeType() == Node.ELEMENT_NODE) {
				try {
					String credentialId = ((Element) resolverNodes.item(i)).getAttribute("Id");
					if (credentialId == null || credentialId.equals("")) {
						if (singleMode) {
							credentialId = "SINGLE";
						} else {
							log
									.error("Found credential that was not labeled with a unique \"Id\" attribute. Skipping.");
						}
					}

					if (data.containsKey(credentialId)) {
						log.error("Duplicate credential id (" + credentialId + ") found. Skipping");
					}

					log.info("Found credential (" + credentialId + "). Loading...");
					data.put(credentialId, CredentialFactory.loadCredential((Element) resolverNodes.item(i)));

				} catch (CredentialFactoryException cfe) {
					log.error("Could not load credential, skipping: " + cfe.getMessage());
				} catch (ClassCastException cce) {
					log.error("Problem realizing credential configuration " + cce.getMessage());
				}
			}
		}
	}

	public boolean containsCredential(String identifier) {

		return data.containsKey(identifier);
	}

	public Credential getCredential(String identifier) {

		// Default if there is only one credential
		if ((identifier == null || identifier.equals("")) && data.size() == 1) { return (Credential) data.values()
				.iterator().next(); }

		return (Credential) data.get(identifier);
	}

	public Credential getCredential() {

		return (Credential) data.values().iterator().next();
	}

	static class CredentialFactory {

		private static Logger log = Logger.getLogger(CredentialFactory.class.getName());

		public static Credential loadCredential(Element e) throws CredentialFactoryException {

			if (e.getLocalName().equals("KeyInfo")) { return new KeyInfoCredentialResolver().loadCredential(e); }

			if (e.getLocalName().equals("FileResolver")) { return new FileCredentialResolver().loadCredential(e); }

			if (e.getLocalName().equals("KeyStoreResolver")) { return new KeystoreCredentialResolver()
					.loadCredential(e); }

			if (e.getLocalName().equals("CustomResolver")) { return new CustomCredentialResolver().loadCredential(e); }

			log.error("Unrecognized Credential Resolver type: " + e.getTagName());
			throw new CredentialFactoryException("Failed to load credential.");
		}

	}

}

class KeyInfoCredentialResolver implements CredentialResolver {

	private static Logger log = Logger.getLogger(KeyInfoCredentialResolver.class.getName());

	KeyInfoCredentialResolver() throws CredentialFactoryException {

		log.error("Credential Resolver (KeyInfoCredentialResolver) not implemented");
		throw new CredentialFactoryException("Failed to load credential.");
	}

	public Credential loadCredential(Element e) {

		return null;
	}
}

/**
 * Loads a credential from a file. Supports DER, PEM, encrypted PEM, PKCS8, and encrypted PKCS8 for RSA and DSA.
 * 
 * @author Walter Hoehn
 * @author Chad La Joie
 */

class FileCredentialResolver implements CredentialResolver {

	private static Logger log = Logger.getLogger(FileCredentialResolver.class.getName());

	/**
	 * Reads a private key, and certificate information, specified by the configuration element, and creates a security
	 * credential which can then be used for operations such a assertion signing. DER and PEM encoded keys (both
	 * none-encrypted and encrypted) and PEM encoded certificated are supported.
	 * 
	 * @param e
	 *            the credentials configuration element
	 * @throws CredentialFactoryException
	 *             thrown if an error is encountered during any step of the credential creation, exact error specified
	 *             in exception message
	 */
	public Credential loadCredential(Element e) throws CredentialFactoryException {

		if (!e.getLocalName().equals("FileResolver")) {
			log.error("Invalid Credential Resolver configuration: expected <FileResolver> .");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		PrivateKey key = getPrivateKey(e);
		if (key == null) {
			log.error("Failed to load private key.");
			throw new CredentialFactoryException("Failed to load private key.");
		}

		List certChain = getCertificateChain(e, key);

		Credential credential = new Credential(((X509Certificate[]) certChain.toArray(new X509Certificate[0])), key);
		if (log.isDebugEnabled()) {
			log.debug("Credential created");
		}

		return credential;
	}

	/**
	 * Gets the private key for the credentials. Keys can be in either DER or PEM format and either password protected
	 * (encrypted) or not.
	 * 
	 * @param credentialConfigElement
	 *            the credential configuration element
	 * @return the private key
	 * @throws CredentialFactoryException
	 *             thrown if the private key file can not be found, the private key format can not be determined, or
	 *             some IO error occurs reading from the private key file
	 */
	private PrivateKey getPrivateKey(Element credentialConfigElement) throws CredentialFactoryException {

		String keyPath = getKeyPath(credentialConfigElement);
		String password = getKeyPassword(credentialConfigElement);

		InputStream keyStream = null;
		try {
			if (log.isDebugEnabled()) {
				log.debug("Attempting to load private key from file " + keyPath);
			}
			keyStream = new ShibResource(keyPath, this.getClass()).getInputStream();
			int encoding = getKeyEncodingFormat(credentialConfigElement, keyStream);
			EncodedKey encodedKey;

			switch (encoding) {
				case EncodedKey.DER_ENCODING :
					if (log.isDebugEnabled()) {
						log.debug("Private key in file " + keyPath + " determined to be DER encoded");
					}
					encodedKey = new DERKey(keyStream, password);
					return encodedKey.getPrivateKey();

				case EncodedKey.PEM_ENCODING :
					if (log.isDebugEnabled()) {
						log.debug("Private key in file " + keyPath + " determined to be PEM encoded");
					}
					encodedKey = new PEMKey(keyStream, password);
					return encodedKey.getPrivateKey();

				default :
					log.error("Unable to determine format of private key specified in file " + keyPath);
					throw new CredentialFactoryException("Unable to determine private key format.");
			}
		} catch (IOException ioe) {
			log.error("Could not load credential from specified file (" + keyPath + "): " + ioe);
			throw new CredentialFactoryException("Unable to load private key.");
		} finally {
			if (keyStream != null) {
				try {
					keyStream.close();
				} catch (IOException e1) {
					// ignore
				}
			}
		}
	}

	/**
	 * Gets the complete certificate chain specified by the configuration element. Currently only X.509 certificates are
	 * supported.
	 * 
	 * @param credentialConfigElement
	 *            the Credentials configuration element
	 * @param key
	 *            the private key for the certificate
	 * @return the certificate chain as a list of certificates
	 * @throws CredentialFactoryException
	 *             thrown if the certificate files is not found, can not be parsed, or an IOException occurs whils
	 *             reading the file
	 */
	private List getCertificateChain(Element credentialConfigElement, PrivateKey key) throws CredentialFactoryException {

		List certChain = new ArrayList();
		String certPath = getCertPath(credentialConfigElement);

		if (certPath == null || certPath.equals("")) {
			if (log.isInfoEnabled()) {
				log.info("No certificates specified.");
			}
		} else {
			if (log.isDebugEnabled()) {
				log.debug("Certificate Path: (" + certPath + ").");
			}

			// A placeholder in case we want to make this configurable
			String certType = "X.509";

			// The loading code should work for other types, but the chain
			// construction code would break
			if (!certType.equals("X.509")) {
				log.error("File credential resolver only supports the X.509 certificates.");
				throw new CredentialFactoryException("Only X.509 certificates are supported");
			}

			ArrayList allCerts = new ArrayList();

			try {
				Certificate[] certsFromPath = loadCertificates(new ShibResource(certPath, this.getClass())
						.getInputStream(), certType);

				allCerts.addAll(Arrays.asList(certsFromPath));

				// Find the end-entity cert first
				if (certsFromPath == null || certsFromPath.length == 0) {
					log.error("File at (" + certPath + ") did not contain any valid certificates.");
					throw new CredentialFactoryException("File did not contain any valid certificates.");
				}

				if (certsFromPath.length == 1) {
					if (log.isDebugEnabled()) {
						log.debug("Certificate file only contains 1 certificate.");
						log.debug("Ensuring that it matches the private key.");
					}
					if (!isMatchingKey(certsFromPath[0].getPublicKey(), key)) {
						log.error("Certificate file " + certPath
								+ "only contained one certificate and it does not match the private key.");
						throw new CredentialFactoryException(
								"No certificate in chain that matches specified private key");
					}
					certChain.add(certsFromPath[0]);
					if (log.isDebugEnabled()) {
						log.debug("Successfully identified the end entity cert: "
								+ ((X509Certificate) certChain.get(0)).getSubjectDN());
					}

				} else {
					if (log.isDebugEnabled()) {
						log.debug("Certificate file contains multiple certificates.");
						log
								.debug("Trying to determine the end-entity cert by the matching certificates against the private key.");
					}
					for (int i = 0; certsFromPath.length > i; i++) {
						if (isMatchingKey(certsFromPath[i].getPublicKey(), key)) {
							if (log.isDebugEnabled()) {
								log.debug("Found matching end cert: "
										+ ((X509Certificate) certsFromPath[i]).getSubjectDN());
							}
							certChain.add(certsFromPath[i]);
						}
					}
					if (certChain.size() < 1) {
						log.error("Certificate file " + certPath
								+ "only contained multiple certificates and none matched the private key.");
						throw new CredentialFactoryException(
								"No certificate in chain that matches specified private key");
					}
					if (certChain.size() > 1) {
						log.error("More than one certificate in chain that matches specified private key");
						throw new CredentialFactoryException(
								"More than one certificate in chain that matches specified private key");
					}
					if (log.isDebugEnabled()) {
						log.debug("Successfully identified the end entity cert: "
								+ ((X509Certificate) certChain.get(0)).getSubjectDN());
					}
				}

				// Now load additional certs and construct a chain
				String[] caPaths = getCAPaths(credentialConfigElement);
				if (caPaths != null && caPaths.length > 0) {
					if (log.isDebugEnabled()) {
						log
								.debug("Attempting to load certificates from (" + caPaths.length
										+ ") CA certificate files.");
					}
					for (int i = 0; i < caPaths.length; i++) {
						allCerts.addAll(Arrays.asList(loadCertificates(new ShibResource(caPaths[i], this.getClass())
								.getInputStream(), certType)));
					}
				}

				if (log.isDebugEnabled()) {
					log.debug("Attempting to construct a certificate chain.");
				}
				walkChain((X509Certificate[]) allCerts.toArray(new X509Certificate[0]), certChain);

				if (log.isDebugEnabled()) {
					log.debug("Verifying that each link in the cert chain is signed appropriately");
				}
				for (int i = 0; i < certChain.size() - 1; i++) {
					PublicKey pubKey = ((X509Certificate) certChain.get(i + 1)).getPublicKey();
					try {
						((X509Certificate) certChain.get(i)).verify(pubKey);
					} catch (Exception se) {
						log.error("Certificate chain cannot be verified: " + se);
						throw new CredentialFactoryException("Certificate chain cannot be verified: " + se);
					}
				}
				if (log.isDebugEnabled()) {
					log.debug("All signatures verified. Certificate chain creation successful.");
				}

				if (log.isInfoEnabled()) {
					log.info("Successfully loaded certificates.");
				}
			} catch (IOException ioe) {
				log.error("Could not load resource from specified location (" + certPath + "): " + ioe);
				throw new CredentialFactoryException("Unable to load certificates.");
			}
		}

		return certChain;
	}
    
    /**
     * Determines whether the key is PEM or DER encoded.
     * 
     * @param e the file credential resolver configuration element
     * @param keyStream an input stream reading the private key
     * 
     * @return the encoding format of the key
     * 
     * @throws CredentialFactoryException thrown if the key format can not be determined or the key can not be read
     */
    private int getKeyEncodingFormat(Element e, InputStream keyStream) throws CredentialFactoryException {
        NodeList keyElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "Key");
        if (keyElements.getLength() < 1) {
            log.error("No private key specified in file credential resolver");
            throw new CredentialFactoryException("File Credential Resolver requires a <Key> specification.");
        }

        if (keyElements.getLength() > 1) {
            log.error("Multiple Key path specifications, using first.");
        }

        String formatStr = ((Element) keyElements.item(0)).getAttribute("format");
        
        if(formatStr != null && formatStr.length() > 0) {
            if(formatStr.equals("PEM")) {
                return EncodedKey.PEM_ENCODING;
            }else if(formatStr.equals("DER")) {
                return EncodedKey.DER_ENCODING;
            }else if(formatStr.equals("PKCS12")) {
                log.error("PKCS12 private keys are not yet supported");
                return -1;
            }
        }
        
        if(log.isInfoEnabled()) {
            log.info("Private key format was not specified in file credential resolver configuration, attempting to auto-detect it.");
        }
        try {
            // Need to mark the stream and then reset it, after getting the
            // first byte so that the private key decoder starts reading at
            // the correct position
            keyStream.mark(2);
            int firstByte = keyStream.read();
            keyStream.reset();

            // PEM encoded keys must start with a "-", a decimal value of 45
            if (firstByte == 45) { return EncodedKey.PEM_ENCODING; }

            // DER encoded keys must start with a decimal value of 48
            if (firstByte == 48) { return EncodedKey.DER_ENCODING; }

            // Can not determine type
            return -1;
        }catch (IOException ioe) {
            throw new CredentialFactoryException("Could not determine the type of private key for file credential resolver.");
        }
    }

	/**
	 * Gets the private key password from the Credentials configuration element if one exists.
	 * 
	 * @param e
	 *            the credentials configuration element
	 * @return the password if one is given or an empty string if one is not
	 * @throws CredentialFactoryException
	 *             thrown if no Key element is present in the configuration
	 */
	private String getKeyPassword(Element e) throws CredentialFactoryException {

		NodeList keyElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "Key");
		if (keyElements.getLength() < 1) {
			log.error("Key not specified.");
			throw new CredentialFactoryException("File Credential Resolver requires a <Key> specification.");
		}

		if (keyElements.getLength() > 1) {
			log.error("Multiple Key path specifications, using first.");
		}

		String password = ((Element) keyElements.item(0)).getAttribute("password");
		if (password == null) {
			password = "";
		}
		return password;
	}

	/**
	 * Gets the certificate path from the Credentials configuration element. If multiple paths are specified only the
	 * first one is used.
	 * 
	 * @param e
	 *            the credentials configuration element
	 * @return the certificate path, or null if non is specificed
	 * @throws CredentialFactoryException
	 *             thrown if no Path element is given or it's empty
	 */
	private String getCertPath(Element e) throws CredentialFactoryException {

		NodeList certificateElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "Certificate");
		if (certificateElements.getLength() < 1) {
			if (log.isDebugEnabled()) {
				log.debug("No <Certificate> element found.");
			}
			return null;
		}

		NodeList pathElements = ((Element) certificateElements.item(0)).getElementsByTagNameNS(
				Credentials.credentialsNamespace, "Path");

		if (pathElements.getLength() < 1) {
			log.error("Certificate path not specified.");
			throw new CredentialFactoryException(
					"File Credential Resolver requires a <Certificate><Path/></Certificate> specification, none was specified.");
		}

		if (pathElements.getLength() > 1) {
			log.error("Multiple Certificate path specifications, using first.");
		}
		Node tnode = pathElements.item(0).getFirstChild();
		String path = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			path = tnode.getNodeValue();
		}
		if (path == null || path.equals("")) {
			log.error("Certificate path was empty.");
			throw new CredentialFactoryException(
					"File Credential Resolver requires a <Certificate><Path/></Certificate> specification, the specified one was empty.");
		}

		return path;
	}

	/**
	 * Get the CA certificate paths from the Credentials configuration element. Paths should be delimited with the
	 * operating system path delimiter. If multiple Certificate elements are found only the first is used.
	 * 
	 * @param e
	 *            the credentials configuration element
	 * @return an array of CA certificate paths, or null if no certificate path was specified
	 * @throws CredentialFactoryException
	 *             no certificate path was specified
	 */
	private String[] getCAPaths(Element e) throws CredentialFactoryException {

		NodeList certificateElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "Certificate");
		if (certificateElements.getLength() < 1) {
			log.error("Certificate not specified.");
			throw new CredentialFactoryException("File Credential Resolver requires a <Certificate> specification.");
		}
		if (certificateElements.getLength() > 1) {
			log.error("Multiple Certificate path specifications, using first.");
		}

		NodeList pathElements = ((Element) certificateElements.item(0)).getElementsByTagNameNS(
				Credentials.credentialsNamespace, "CAPath");
		if (pathElements.getLength() < 1) {
			if (log.isDebugEnabled()) {
				log.debug("No CA Certificate paths specified.");
			}
			return null;
		}
		ArrayList paths = new ArrayList();
		for (int i = 0; i < pathElements.getLength(); i++) {
			Node tnode = pathElements.item(i).getFirstChild();
			String path = null;
			if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
				path = tnode.getNodeValue();
			}
			if (path != null && !(path.equals(""))) {
				paths.add(path);
			}
			if (paths.isEmpty()) {
				if (log.isDebugEnabled()) {
					log.debug("No CA Certificate paths specified.");
				}
			}
		}
		return (String[]) paths.toArray(new String[0]);
	}

	/**
	 * Gets the path to the private key from the Credentials configuration element. If more than one is specified only
	 * the first one is used.
	 * 
	 * @param e
	 *            the credentials configuration element
	 * @return path to the private key
	 * @throws CredentialFactoryException
	 *             thrown if no path is specified or it's null.
	 */
	private String getKeyPath(Element e) throws CredentialFactoryException {

		NodeList keyElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "Key");
		if (keyElements.getLength() < 1) {
			log.error("Key not specified.");
			throw new CredentialFactoryException("File Credential Resolver requires a <Key> specification.");
		}
		if (keyElements.getLength() > 1) {
			log.error("Multiple Key path specifications, using first.");
		}

		NodeList pathElements = ((Element) keyElements.item(0)).getElementsByTagNameNS(
				Credentials.credentialsNamespace, "Path");
		if (pathElements.getLength() < 1) {
			log.error("Key path not specified.");
			throw new CredentialFactoryException(
					"File Credential Resolver requires a <Key><Path/></Certificate> specification.");
		}
		if (pathElements.getLength() > 1) {
			log.error("Multiple Key path specifications, using first.");
		}
		Node tnode = pathElements.item(0).getFirstChild();
		String path = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			path = tnode.getNodeValue();
		}
		if (path == null || path.equals("")) {
			log.error("Key path is empty.");
			throw new CredentialFactoryException(
					"File Credential Resolver requires a <Key><Path/></Certificate> specification.");
		}
		return path;
	}

	/**
	 * Loads a specified bundle of certs individually and returns an array of {@link Certificate}objects. This is
	 * needed because the standard {@link CertificateFactory#getCertificates(InputStream)}method bails out when it has
	 * trouble loading any cert and cannot handle "comments".
	 */
	private Certificate[] loadCertificates(InputStream inStream, String certType) throws CredentialFactoryException {

		ArrayList certificates = new ArrayList();

		try {
			CertificateFactory certFactory = CertificateFactory.getInstance(certType);

			BufferedReader in = new BufferedReader(new InputStreamReader(inStream));
			String str;
			boolean insideCert = false;
			StringBuffer rawCert = null;
			while ((str = in.readLine()) != null) {

				if (insideCert) {
					rawCert.append(str);
					rawCert.append(System.getProperty("line.separator"));
					if (str.matches("^.*-----END CERTIFICATE-----.*$")) {
						insideCert = false;
						try {
							Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(rawCert
									.toString().getBytes()));
							certificates.add(cert);
						} catch (CertificateException ce) {
							log.warn("Failed to load a certificate from the certificate bundle: " + ce);
							if (log.isDebugEnabled()) {
								if (log.isDebugEnabled()) {
									log.debug("Dump of bad certificate: " + System.getProperty("line.separator")
											+ rawCert.toString());
								}
							}
						}
						continue;
					}
				} else if (str.matches("^.*-----BEGIN CERTIFICATE-----.*$")) {
					insideCert = true;
					rawCert = new StringBuffer();
					rawCert.append(str);
					rawCert.append(System.getProperty("line.separator"));
				}
			}
			in.close();
		} catch (IOException p) {
			log.error("Could not load resource from specified location: " + p);
			throw new CredentialFactoryException("Unable to load certificates.");
		} catch (CertificateException p) {
			log.error("Problem loading certificate factory: " + p);
			throw new CredentialFactoryException("Unable to load certificates.");
		}

		return (Certificate[]) certificates.toArray(new Certificate[0]);
	}

	/**
	 * Given an ArrayList containing a base certificate and an array of unordered certificates, populates the ArrayList
	 * with an ordered certificate chain, based on subject and issuer.
	 * 
	 * @param chainSource
	 *            array of certificates to pull from
	 * @param chainDest
	 *            ArrayList containing base certificate
	 * @throws InvalidCertificateChainException
	 *             thrown if a chain cannot be constructed from the specified elements
	 */
	protected void walkChain(X509Certificate[] chainSource, List chainDest) throws CredentialFactoryException {

		X509Certificate currentCert = (X509Certificate) chainDest.get(chainDest.size() - 1);
		if (currentCert.getSubjectDN().equals(currentCert.getIssuerDN())) {
			if (log.isDebugEnabled()) {
				log.debug("Found self-signed root cert: " + currentCert.getSubjectDN());
			}
			return;
		} else {
			for (int i = 0; chainSource.length > i; i++) {
				if (currentCert.getIssuerDN().equals(chainSource[i].getSubjectDN())) {
					chainDest.add(chainSource[i]);
					walkChain(chainSource, chainDest);
					return;
				}
			}
			if (log.isDebugEnabled()) {
				log.debug("Certificate chain is incomplete.");
			}
		}
	}

	/**
	 * Boolean indication of whether a given private key and public key form a valid keypair.
	 * 
	 * @param pubKey
	 *            the public key
	 * @param privKey
	 *            the private key
	 */
	protected boolean isMatchingKey(PublicKey pubKey, PrivateKey privKey) {

		try {
			String controlString = "asdf";
			if (log.isDebugEnabled()) {
				log.debug("Checking for matching private key/public key pair");
			}

			Signature signature = null;
			try {
				signature = Signature.getInstance(privKey.getAlgorithm());
			} catch (NoSuchAlgorithmException nsae) {
				if (log.isDebugEnabled()) {
					log.debug("No provider for (RSA) signature, attempting (MD5withRSA).");
				}
				if (privKey.getAlgorithm().equals("RSA")) {
					signature = Signature.getInstance("MD5withRSA");
				} else {
					throw nsae;
				}
			}
			signature.initSign(privKey);
			signature.update(controlString.getBytes());
			byte[] sigBytes = signature.sign();
			signature.initVerify(pubKey);
			signature.update(controlString.getBytes());
			if (signature.verify(sigBytes)) {
				if (log.isDebugEnabled()) {
					log.debug("Found match.");
				}
				return true;
			}
		} catch (Exception e) {
			log.warn(e);
		}
		if (log.isDebugEnabled()) {
			log.debug("This pair does not match.");
		}
		return false;
	}

	/**
	 * Auto-enlarging container for bytes.
	 */
	// Sure makes you wish bytes were first class objects.
	private class ByteContainer {

		private byte[] buffer;
		private int cushion;
		private int currentSize = 0;

		private ByteContainer(int initSize, int growBy) {

			buffer = new byte[initSize];
			this.cushion = growBy;
		}

		private void grow() {

			int newSize = currentSize + cushion;
			byte[] b = new byte[newSize];
			int toCopy = Math.min(currentSize, newSize);
			int i;
			for (i = 0; i < toCopy; i++) {
				b[i] = buffer[i];
			}
			buffer = b;
		}

		/**
		 * Returns an array of the bytes in the container.
		 * <p>
		 */

		private byte[] toByteArray() {

			byte[] b = new byte[currentSize];
			System.arraycopy(buffer, 0, b, 0, currentSize);
			return b;
		}

		/**
		 * Add one byte to the end of the container.
		 */

		private void append(byte b) {

			if (currentSize == buffer.length) {
				grow();
			}
			buffer[currentSize] = b;
			currentSize++;
		}

	}

	/**
	 * Abstract class representing private keys encoded in formats like PEM and DER.
	 * 
	 * @author Chad La Joie
	 */
	private abstract class EncodedKey {

		/**
		 * DER encoded key
		 */
		public static final int DER_ENCODING = 0;

		/**
		 * PEM encoded key
		 */
		public static final int PEM_ENCODING = 1;

		/**
		 * OID for DSA keys
		 */
		public final static String DSAKey_OID = "1.2.840.10040.4.1";

		/**
		 * OID for RSA keys
		 */
		public final static String RSAKey_OID = "1.2.840.113549.1.1.1";

		/**
		 * PKCS8 key format
		 */
		public final static int PKCS8 = 0;

		/**
		 * RSA key format
		 */
		public final static int RSA = 1;

		/**
		 * DSA key format
		 */
		public final static int DSA = 2;

		/**
		 * Key encryption algorithim DES-CDC
		 */
		public final static int DES_CBC = 0;

		/**
		 * Key encryption algorithim DES-EDE3-CBC
		 */
		public final static int DES_EDE3_CBC = 1;

		/**
		 * Format of the PEM encoded key
		 */
		private int format = -1;

		/**
		 * Is the key encrypted?
		 */
		private boolean encrypted;

		/**
		 * Password for the encrypted key
		 */
		private String keyPassword;

		/**
		 * Encryption algorithim used for this key
		 */
		private int encAlgo = -1;

		/**
		 * Initialization vector for the encryption algorithim
		 */
		private String initVector = "";

		/**
		 * DER encoded key
		 */
		private byte[] keyBytes;

		/**
		 * Gets the format (PKCS8, RSA, DSA) of the key.
		 * 
		 * @return format of the key
		 */
		public int getFormat() {

			return format;
		}

		/**
		 * Sets the format (PKCS8, RSA, DSA) of the key.
		 * 
		 * @param format
		 *            the format of the key
		 */
		public void setFormat(int format) {

			this.format = format;
		}

		/**
		 * Gets whether this PEM key is encrypted.
		 * 
		 * @return true if this key is encrypted, false if not
		 */
		public boolean isEncrypted() {

			return encrypted;
		}

		/**
		 * Sets whether the key is encrypted.
		 * 
		 * @param encrypted
		 *            whether the key is encrypted
		 */
		public void setEncrypted(boolean encrypted) {

			this.encrypted = encrypted;
		}

		/**
		 * Gets the password to decrypt this key
		 * 
		 * @return the password to decrypt this key
		 */
		public String getEncryptionPassword() {

			return keyPassword;
		}

		/**
		 * Sets the password to decrypt this key
		 * 
		 * @param keyPassword
		 *            the password to decrypt this key
		 */
		public void setEncryptionPassword(String keyPassword) {

			this.keyPassword = keyPassword;
		}

		/**
		 * Gets the encryption algorithim used to encrypt the private key.
		 * 
		 * @return the encryption algorithim used to encrypt the private key
		 */
		public int getEncryptionAlgorithim() {

			return encAlgo;
		}

		/**
		 * Sets the encryption algorithim used to encrypt the private key.
		 * 
		 * @param encAlgo
		 *            the encryption algorithim used to encrypt the private key
		 */
		public void setEncryptionAlgorithim(int encAlgo) {

			this.encAlgo = encAlgo;
		}

		/**
		 * Gets the initialization vector used in the encryption of the private key.
		 * 
		 * @return the initialization vector used in the encryption of the private key
		 */
		public String getInitializationVector() {

			return initVector;
		}

		/**
		 * Sets the initialization vector used in the encryption of the private key.
		 * 
		 * @param initVector
		 *            ets the initialization vector used in the encryption of the private key
		 */
		public void setInitializationVector(String initVector) {

			this.initVector = initVector;
		}

		/**
		 * Gets the private key as bytes.
		 * 
		 * @return the private key as bytes.
		 */
		public byte[] getKeyBytes() {

			return keyBytes;
		}

		/**
		 * Sets the private key as bytes.
		 * 
		 * @param keyBytes
		 *            the private key as bytes
		 */
		public void setKeyBytes(byte[] keyBytes) {

			this.keyBytes = keyBytes;
		}

		/**
		 * Gets the private key from this encoded key.
		 * 
		 * @return the private key from this encoded key
		 */
		public abstract PrivateKey getPrivateKey() throws CredentialFactoryException;
	}

	/**
	 * Represents a PEM formatted cryptographic key. Used to determine it's format (PKCS8, RSA, DSA), whether it's been
	 * encrypted or not, get the Base64 encoded key, and then decoded the key into the DER encoded key.
	 * 
	 * @author Chad La Joie
	 */
	private class PEMKey extends EncodedKey {

		/**
		 * DER encoded key
		 */
		private DERKey derKey;

		/**
		 * Constructor
		 * 
		 * @param pemKey
		 *            the PEM key
		 * @throws CredentialFactoryException
		 * @throws CredentialFactoryException
		 * @throws IOException
		 */
		public PEMKey(String pemKey, String password) throws IOException, CredentialFactoryException {

			setEncryptionPassword(password);
			BufferedReader keyReader = new BufferedReader(new StringReader(pemKey));
			parsePEMKey(keyReader);
		}

		/**
		 * Constructor
		 * 
		 * @param pemKeyStream
		 *            and input stream with the PEM key
		 * @throws CredentialFactoryException
		 * @throws CredentialFactoryException
		 * @throws IOException
		 */
		public PEMKey(InputStream pemKeyStream, String password) throws IOException, CredentialFactoryException {

			setEncryptionPassword(password);
			BufferedReader keyReader = new BufferedReader(new InputStreamReader(pemKeyStream));
			parsePEMKey(keyReader);
		}

		/**
		 * Gets the private key from this PEM encoded key
		 * 
		 * @throws CredentialFactoryException
		 */
		public PrivateKey getPrivateKey() throws CredentialFactoryException {

			return derKey.getPrivateKey();
		}

		/**
		 * Parses the PEM key to determine its format, whether it's encrypted, then extract the Base64 encoded key and
		 * decodes it into the DER encoded key.
		 * 
		 * @param keyReader
		 *            the PEM key
		 * @throws IOException
		 *             thrown if there is problem reading the key
		 * @throws CredentialFactoryException
		 */
		private void parsePEMKey(BufferedReader keyReader) throws IOException, CredentialFactoryException {

			if (log.isDebugEnabled()) {
				log.debug("Parsing PEM enocded private key");
			}
			String currentLine = keyReader.readLine();

			if (currentLine.matches("^.*-----BEGIN PRIVATE KEY-----.*$")) {
				if (log.isDebugEnabled()) {
					log.debug("Key appears to be in PKCS8 format.");
				}

				setFormat(PKCS8);
				setEncrypted(false);

			} else if (currentLine.matches("^.*-----BEGIN ENCRYPTED PRIVATE KEY-----.*$")) {
				if (log.isDebugEnabled()) {
					log.debug("Key appears to be in encrypted PKCS8 format.");
				}
				setFormat(PKCS8);
				setEncrypted(true);

			} else if (currentLine.matches("^.*-----BEGIN RSA PRIVATE KEY-----.*$")) {
				setFormat(RSA);

				// Mark the stream, if it's not encrypted we need to reset
				// or lose the first line of the base64 key
				keyReader.mark(100);
				currentLine = keyReader.readLine();
				if (currentLine.matches("^.*Proc-Type: 4,ENCRYPTED.*$")) {
					if (log.isDebugEnabled()) {
						log.debug("Key appears to be encrypted RSA in raw format.");
					}
					setEncrypted(true);
				} else {
					if (log.isDebugEnabled()) {
						log.debug("Key appears to be RSA in raw format.");
					}
					keyReader.reset();
					setEncrypted(false);
				}

			} else if (currentLine.matches("^.*-----BEGIN DSA PRIVATE KEY-----.*$")) {
				setFormat(DSA);

				// Mark the stream, if it's not encrypted we need to reset
				// or lose the first line of the base64 key
				keyReader.mark(100);
				currentLine = keyReader.readLine();
				if (currentLine.matches("^.*Proc-Type: 4,ENCRYPTED.*$")) {
					if (log.isDebugEnabled()) {
						log.debug("Key appears to be encrypted DSA in raw format.");
					}
					setEncrypted(true);
				} else {
					if (log.isDebugEnabled()) {
						log.debug("Key appears to be DSA in raw format.");
					}
					keyReader.reset();
					setEncrypted(false);
				}
			}

			// Key is an encrypted RSA or DSA key, need to get the algorithim used
			if (isEncrypted() && (getFormat() == RSA || getFormat() == DSA)) {
				if (log.isDebugEnabled()) {
					log.debug("Key data is encrypted RSA or DSA, inspecting encryption properties");
				}
				currentLine = keyReader.readLine();
				String[] components = currentLine.split(":\\s");
				if (components.length != 2) {
					log.error("Encrypted key did not contain DEK-Info specification.");
					// throw new CredentialFactoryException("Unable to load private key.");
				}
				String[] cryptData = components[1].split(",");
				if (cryptData.length != 2 || cryptData[0] == null || cryptData[0].equals("") || cryptData[1] == null
						|| cryptData[1].equals("")) {
					log.error("Encrypted key did not contain a proper DEK-Info specification.");
					// throw new CredentialFactoryException("Unable to load private key.");
				}
				if (cryptData[0].equals("DES-CBC")) {
					if (log.isDebugEnabled()) {
						log.debug("Key encryption method determined to be DES-CBC");
					}
					setEncryptionAlgorithim(DES_CBC);
				} else if (cryptData[0].equals("DES-EDE3-CBC")) {
					if (log.isDebugEnabled()) {
						log.debug("Key encryption method determined to be DES-EDE3-CBC");
					}
					setEncryptionAlgorithim(DES_EDE3_CBC);
				} else {
					setEncryptionAlgorithim(-1);
					log.error("Key encryption method unknown: " + cryptData[0]);
				}

				if (log.isDebugEnabled()) {
					log.debug("Key encryption algorithim initialization vector determined to be " + cryptData[1]);
				}
				setInitializationVector(cryptData[1]);
			}

			// Now that we've parsed the headers, get the base64 encoded key itself
			StringBuffer keyBuf = new StringBuffer();
			while ((currentLine = keyReader.readLine()) != null) {
				if (currentLine.matches("^.*END.*$")) {
					break;
				}

				keyBuf.append(currentLine);
			}

			String base64Key = keyBuf.toString();
			if (log.isDebugEnabled()) {
				log.debug("Base64 encoded key: " + base64Key);
			}

			// Base64 decode the key, gives teh DER encoded key data
			if (log.isDebugEnabled()) {
				log.debug("Base64 decoding key");
			}
			setKeyBytes(Base64.decode(base64Key));

			// If the key was a raw RSA/DSA encrypted we need to decrypt it now
			// If it was a PKCS8 key we'll decrypt it when we parse it's DER data
			if (isEncrypted() && (getFormat() == RSA || getFormat() == DSA)) {
				if (log.isDebugEnabled()) {
					log.debug("Decrypting RSA/DSA key");
				}
				decryptKey();
			}

			// We now have a key encoded in DER format
			if (log.isDebugEnabled()) {
				log.debug("PEM key has been decoded into DER encoded data, processing it as DER key");
			}
			derKey = new DERKey(getKeyBytes(), getEncryptionPassword());

			// Close the reader, we're done
			keyReader.close();
		}

		/**
		 * Decrypts an encrypted private key.
		 * 
		 * @throws CredentialFactoryException
		 */
		private void decryptKey() throws CredentialFactoryException {

			try {
				byte[] ivBytes = new byte[8];
				for (int j = 0; j < 8; j++) {
					ivBytes[j] = (byte) Integer.parseInt(getInitializationVector().substring(j * 2, j * 2 + 2), 16);
				}
				IvParameterSpec paramSpec = new IvParameterSpec(ivBytes);

				byte[] keyBuffer = new byte[24];
				// The key generation method (with the IV used as the salt, and
				// the single proprietary iteration)
				// is the reason we can't use the pkcs5 providers to read the
				// OpenSSL encrypted format

				byte[] keyPass = getEncryptionPassword().getBytes();
				MessageDigest md = MessageDigest.getInstance("MD5");
				md.update(keyPass);
				md.update(paramSpec.getIV());
				byte[] digested = md.digest();
				System.arraycopy(digested, 0, keyBuffer, 0, 16);

				md.update(digested);
				md.update(keyPass);
				md.update(paramSpec.getIV());
				digested = md.digest();
				System.arraycopy(digested, 0, keyBuffer, 16, 8);

				SecretKeySpec keySpec = null;
				Cipher cipher = null;
				if (getEncryptionAlgorithim() == EncodedKey.DES_CBC) {
					// Special handling!!!
					// For DES, we use the same key generation,
					// then just chop off the end :-)
					byte[] desBuff = new byte[8];
					System.arraycopy(keyBuffer, 0, desBuff, 0, 8);
					keySpec = new SecretKeySpec(desBuff, "DES");
					cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
				}
				if (getEncryptionAlgorithim() == EncodedKey.DES_EDE3_CBC) {
					keySpec = new SecretKeySpec(keyBuffer, "DESede");
					cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
				}

				cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec);
				byte[] decrypted = cipher.doFinal(getKeyBytes());

				setEncrypted(false);
				setKeyBytes(decrypted);
			} catch (BadPaddingException e) {
				log.error("Incorrect password to unlock private key.", e);
				throw new CredentialFactoryException("Unable to load private key.");
			} catch (Exception e) {
				log
						.error("Unable to decrypt private key.  Installed JCE implementations don't support the necessary algorithm: "
								+ e);
				throw new CredentialFactoryException("Unable to load private key.");
			}
		}
	}

	/**
	 * Represents a DER formatted cryptographic key. Used to determine it's format (PKCS8, RSA, DSA), whether it's been
	 * encrypted or not
	 * 
	 * @author Chad La Joie
	 */
	private class DERKey extends EncodedKey {

		DERSequence rootDerTag;

		/**
		 * Constructor.
		 * 
		 * @param derKeyStream
		 *            the inputstream that contains the key
		 * @throws IOException
		 *             thrown if there is an error reading from the stream
		 * @throws CredentialFactoryException
		 *             thrown if there is an error parsing the stream data
		 */
		public DERKey(InputStream derKeyStream, String password) throws IOException, CredentialFactoryException {

			setEncryptionPassword(password);
			ByteContainer derKey = new ByteContainer(600, 50);

			for (int i = derKeyStream.read(); i != -1; i = derKeyStream.read()) {
				derKey.append((byte) i);
			}

			setKeyBytes(derKey.toByteArray());
			parseDerKey();
		}

		public DERKey(byte[] derKey, String password) throws IOException, CredentialFactoryException {

			setEncryptionPassword(password);
			setKeyBytes(derKey);
			parseDerKey();
		}

		public PrivateKey getPrivateKey() throws CredentialFactoryException {

			switch (getFormat()) {
				case EncodedKey.PKCS8 :
					if (!isEncrypted()) {
						return getPkcs8Key();
					} else {
						return getEncryptedPkcs8Key();
					}

				case EncodedKey.RSA :
					return getRSARawDerKey();

				case EncodedKey.DSA :
					return getDSARawDerKey();

				default :
					throw new CredentialFactoryException("Unable to determine format of DER encoded private key");
			}
		}

		/**
		 * Takes a set of ASN.1 encoded bytes and converts them into a DER object.
		 * 
		 * @param keyBytes
		 *            the ASN.1 encoded bytes
		 * @return the DER object
		 * @throws IOException
		 *             thrown if the bytes aren't ASN.1 encoded
		 */
		private DERObject getRootDerTag(byte[] keyBytes) throws IOException {

			InputStream derKeyStream = new BufferedInputStream(new ByteArrayInputStream(getKeyBytes()));
			ASN1InputStream asn1Stream = new ASN1InputStream(derKeyStream);
			DERObject derObject = asn1Stream.readObject();
			derKeyStream.close();
			asn1Stream.close();

			return derObject;
		}

		/**
		 * Parse the key stream and determines data about the key.
		 * 
		 * @param derKeyStream
		 *            the inputstream that contains the key
		 * @throws IOExceptionthrown
		 *             if there is an error reading from the stream
		 * @throws CredentialFactoryException
		 *             thrown if there is an error parsing the stream data
		 */
		private void parseDerKey() throws IOException, CredentialFactoryException {

			if (log.isDebugEnabled()) {
				log.debug("Starting to parse " + getKeyBytes().length + " byte DER formatted key.");
			}
			DERObject derObject = getRootDerTag(getKeyBytes());

			if (log.isDebugEnabled()) {
				log
						.debug("Parsed ASN.1 object which has the following structure:\n"
								+ ASN1Dump.dumpAsString(derObject));
			}

			// All supported key formats start with a DER sequence tag
			if (!(derObject instanceof DERSequence)) {
				log.error("Private key is not in valid DER format, it does not start with a DER sequence");
				throw new CredentialFactoryException("Private key is not in valid DER format");
			}
			DERSequence rootSeq = (DERSequence) derObject;
			if (rootSeq.size() < 2) {
				// Valid key in any format will have at least two tags under the root
				log.error("Private key is not in valid DER format; does not contain more than 2 ASN.1 tags");
				throw new CredentialFactoryException("Private key is not in valid DER format");
			}

			DERObject firstChild = rootSeq.getObjectAt(0).getDERObject();

			if (firstChild instanceof DERSequence) {
				if (log.isDebugEnabled()) {
					log.debug("First ASN.1 tag is a sequence, checking to see if this is an encrypted PKCS8 key");
				}
				// Might be encrypted PKCS8, lets check some more
				DERSequence firstChildSeq = (DERSequence) firstChild;
				DERObject grandChildObj = firstChildSeq.getObjectAt(0).getDERObject();
				DERObject secondChild = rootSeq.getObjectAt(1).getDERObject();

				// Encrypted PKCS8 have an octet string as the second child (from the root)
				// and an object identifier as the child of the first child from the root
				if (secondChild instanceof DEROctetString && grandChildObj instanceof DERObjectIdentifier) {
					if (log.isDebugEnabled()) {
						log.debug("DER encoded key determined to be encrypted PKCS8");
					}
					rootDerTag = rootSeq;
					setFormat(PKCS8);
					setEncrypted(true);
				}
			} else if (firstChild instanceof DERInteger) {
				if (log.isDebugEnabled()) {
					log
							.debug("First child ASN.1 tag is a Integer, checking to see if this is an PKCS8, RSA, or DSA key");
				}
				// Might be unencrypted PKCS8, RSA, or DSA

				// Check to see if it's PKCS8 with contains an
				// Integer, then Sequence, then OctetString
				if (rootSeq.size() == 3) {
					if (log.isDebugEnabled()) {
						log.debug("First ASN.1 sequence tag has 3 children, checking to see if this is an PKCS8 key");
					}
					if (rootSeq.getObjectAt(0).getDERObject() instanceof DERInteger
							&& rootSeq.getObjectAt(1).getDERObject() instanceof DERSequence
							&& rootSeq.getObjectAt(2).getDERObject() instanceof DEROctetString) {
						if (log.isDebugEnabled()) {
							log.debug("DER encoded key determined to be PKCS8");
						}
						rootDerTag = rootSeq;
						setFormat(PKCS8);
						setEncrypted(false);
					}
				} else {
					// Might be RSA or DSA. DSA will have 6 Integers
					// under the root sequences, RSA will have 9
					Enumeration children = rootSeq.getObjects();
					DERObject child;
					boolean allInts = true;

					while (children.hasMoreElements()) {
						child = ((DEREncodable) children.nextElement()).getDERObject();
						if (!(child instanceof DERInteger)) {
							allInts = false;
						}
					}

					if (rootSeq.size() == 6) {
						if (log.isDebugEnabled()) {
							log.debug("First ASN.1 sequence tag has 6 children, checking to see if this is an DSA key");
						}
						// DSA keys have six integer tags in the root sequence
						if (allInts) {
							if (log.isDebugEnabled()) {
								log.debug("DER encoded key determined to be raw DSA");
							}
							rootDerTag = rootSeq;
							setFormat(DSA);
							setEncrypted(false);
						}
					} else if (rootSeq.size() == 9) {
						if (log.isDebugEnabled()) {
							log.debug("First ASN.1 sequence tag has 9 children, checking to see if this is an DSA key");
						}
						// RSA (PKCS1) keys have 9 integer tags in the root sequence
						if (allInts) {
							if (log.isDebugEnabled()) {
								log.debug("DER encoded key determined to be raw RSA");
							}
							rootDerTag = rootSeq;
							setFormat(RSA);
							setEncrypted(false);
						}
					}
				}
			}

			// If we don't know what the format is now then the stream wasn't a valid DER encoded key
			if (getFormat() == -1) {
				log.error("Private key is not in valid DER format");
				throw new CredentialFactoryException("Private key is not in valid DER format");
			}
		}

		/**
		 * Gets the private key from a encrypted PKCS8 formatted key.
		 * 
		 * @param bytes
		 *            the PKCS8 formatted key
		 * @param password
		 *            the password to decrypt the key
		 * @return the private key
		 * @throws CredentialFactoryException
		 *             thrown is there is an error loading the private key
		 */
		private PrivateKey getEncryptedPkcs8Key() throws CredentialFactoryException {

			if (log.isDebugEnabled()) {
				log.debug("Beginning to decrypt encrypted PKCS8 key");
			}
			try {
				// Convince the JCE provider that it does know how to do
				// pbeWithMD5AndDES-CBC
				Provider provider = Security.getProvider("SunJCE");
				if (provider != null) {
					provider.setProperty("Alg.Alias.AlgorithmParameters.1.2.840.113549.1.5.3", "PBE");
					provider.setProperty("Alg.Alias.SecretKeyFactory.1.2.840.113549.1.5.3", "PBEWithMD5AndDES");
					provider.setProperty("Alg.Alias.Cipher.1.2.840.113549.1.5.3", "PBEWithMD5AndDES");
				}

				if (log.isDebugEnabled()) {
					log.debug("Inspecting key properties");
				}
				EncryptedPrivateKeyInfo encryptedKeyInfo = new EncryptedPrivateKeyInfo(getKeyBytes());
				if (log.isDebugEnabled()) {
					log.debug("Key encryption Algorithim: " + encryptedKeyInfo.getAlgName());
					log.debug("Key encryption parameters: " + encryptedKeyInfo.getAlgParameters());
				}

				AlgorithmParameters params = encryptedKeyInfo.getAlgParameters();

				if (params == null) {
					log.error("Unable to decrypt private key.  Installed JCE implementations don't support the ("
							+ encryptedKeyInfo.getAlgName() + ") algorithm.");
					throw new CredentialFactoryException("Unable to load private key; " + encryptedKeyInfo.getAlgName()
							+ " is not a supported by this JCE");
				}

				if (log.isDebugEnabled()) {
					log.debug("Key encryption properties determined, decrypting key");
				}
				SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(encryptedKeyInfo.getAlgName());
				PBEKeySpec passwordSpec = new PBEKeySpec(getEncryptionPassword().toCharArray());
				SecretKey key = keyFactory.generateSecret(passwordSpec);

				Cipher cipher = Cipher.getInstance(encryptedKeyInfo.getAlgName());
				cipher.init(Cipher.DECRYPT_MODE, key, params);
				PKCS8EncodedKeySpec decrypted = encryptedKeyInfo.getKeySpec(cipher);

				if (log.isDebugEnabled()) {
					log.debug("Key decrypted, key format now non-encrypted PKCS8");
				}

				setEncrypted(false);
				setKeyBytes(decrypted.getEncoded());

				// Now that we've decrypted the key we've changed the ASN.1 structure
				// and so need to reread it.
				rootDerTag = (DERSequence) getRootDerTag(getKeyBytes());

				return getPkcs8Key();

			} catch (IOException e) {
				log.error("Invalid DER encoding for PKCS8 formatted encrypted key: " + e);
				throw new CredentialFactoryException("Unable to load private key; invalid key format.");
			} catch (InvalidKeySpecException e) {
				log.error("Incorrect password to unlock private key.", e);
				throw new CredentialFactoryException("Unable to load private key; incorrect key decryption password");
			} catch (GeneralSecurityException e) {
				log.error("JCE does not support algorithim to decrypt key: " + e);
				throw new CredentialFactoryException(
						"Unable to load private key; JCE does not support algorithim to decrypt key");
			}
		}

		/**
		 * Gets the private key from a PKCS8 formatted key.
		 * 
		 * @param bytes
		 *            the PKCS8 formatted key
		 * @return the private key
		 * @throws CredentialFactoryException
		 *             thrown is there is an error loading the private key
		 */
		private PrivateKey getPkcs8Key() throws CredentialFactoryException {

			if (log.isDebugEnabled()) {
				log.debug("Reading unecrypted PKCS8 key to determine if key is RSA or DSA");
			}
			DERSequence childSeq = (DERSequence) rootDerTag.getObjectAt(1).getDERObject();
			DERObjectIdentifier derOID = (DERObjectIdentifier) childSeq.getObjectAt(0).getDERObject();
			String keyOID = derOID.getId();

			if (keyOID.equals(EncodedKey.RSAKey_OID)) {
				if (log.isDebugEnabled()) {
					log.debug("Found RSA key in PKCS8.");
				}
				return getRSAPkcs8DerKey();
			} else if (keyOID.equals(EncodedKey.DSAKey_OID)) {
				if (log.isDebugEnabled()) {
					log.debug("Found DSA key in PKCS8.");
				}
				return getDSAPkcs8DerKey();
			} else {
				log.error("Unexpected key type.  Only RSA and DSA keys are supported in PKCS8 format.");
				throw new CredentialFactoryException("Unable to load private key; unexpected key type in PKCS8");
			}
		}

		/**
		 * Gets a private key from a raw RSA PKCS8 formated DER encoded key.
		 * 
		 * @param bytes
		 *            the encoded key
		 * @return the private key
		 * @throws CredentialFactoryException
		 *             thrown if the private key can not be read
		 */
		private PrivateKey getRSAPkcs8DerKey() throws CredentialFactoryException {

			if (log.isDebugEnabled()) {
				log.debug("Constructing PrivateKey from PKCS8 encoded RSA key data");
			}
			try {
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(getKeyBytes());
				return keyFactory.generatePrivate(keySpec);

			} catch (Exception e) {
				log.error("Unable to load private key: " + e);
				throw new CredentialFactoryException("Unable to load private key.");
			}
		}

		/**
		 * Gets a private key from a raw DSA PKCS8 formated DER encoded key.
		 * 
		 * @param bytes
		 *            the encoded key
		 * @return the private key
		 * @throws CredentialFactoryException
		 *             thrown if the private key can not be read
		 */
		private PrivateKey getDSAPkcs8DerKey() throws CredentialFactoryException {

			if (log.isDebugEnabled()) {
				log.debug("Constructing PrivateKey from PKCS8 encoded DSA key data");
			}

			try {
				KeyFactory keyFactory = KeyFactory.getInstance("DSA");
				PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(getKeyBytes());
				return keyFactory.generatePrivate(keySpec);

			} catch (Exception e) {
				log.error("Unable to load private key: " + e);
				throw new CredentialFactoryException("Unable to load private key.");
			}
		}

		/**
		 * Converts a raw RSA key encoded in DER format into a private key object.
		 * 
		 * @param key
		 *            the DER encoded key
		 * @return the private key
		 * @throws CredentialFactoryException
		 *             thrown if a key can not be constructed from the input
		 */
		private PrivateKey getRSARawDerKey() throws CredentialFactoryException {

			if (log.isDebugEnabled()) {
				log.debug("Constructing PrivateKey from raw RSA key data");
			}
			try {
				RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(((DERInteger) rootDerTag.getObjectAt(1))
						.getValue(), ((DERInteger) rootDerTag.getObjectAt(2)).getValue(), ((DERInteger) rootDerTag
						.getObjectAt(3)).getValue(), ((DERInteger) rootDerTag.getObjectAt(4)).getValue(),
						((DERInteger) rootDerTag.getObjectAt(5)).getValue(), ((DERInteger) rootDerTag.getObjectAt(6))
								.getValue(), ((DERInteger) rootDerTag.getObjectAt(7)).getValue(),
						((DERInteger) rootDerTag.getObjectAt(8)).getValue());

				KeyFactory keyFactory = KeyFactory.getInstance("RSA");

				return keyFactory.generatePrivate(keySpec);

			} catch (GeneralSecurityException e) {
				log.error("Unable to marshall private key: " + e);
				throw new CredentialFactoryException("Unable to load private key.");
			}
		}

		/**
		 * Converts a raw DSA key encoded in DER format into a private key object.
		 * 
		 * @param derKey
		 *            DER encoded DSA key
		 * @return the private key
		 * @throws CredentialFactoryException
		 *             thrown if a key can not be constructed from the input
		 */
		private PrivateKey getDSARawDerKey() throws CredentialFactoryException {

			if (log.isDebugEnabled()) {
				log.debug("Constructing PrivateKey from raw DSA key data");
			}

			try {
				DSAPrivateKeySpec keySpec = new DSAPrivateKeySpec(((DERInteger) rootDerTag.getObjectAt(5)).getValue(),
						((DERInteger) rootDerTag.getObjectAt(1)).getValue(), ((DERInteger) rootDerTag.getObjectAt(2))
								.getValue(), ((DERInteger) rootDerTag.getObjectAt(3)).getValue());

				KeyFactory keyFactory = KeyFactory.getInstance("DSA");

				return keyFactory.generatePrivate(keySpec);
			} catch (GeneralSecurityException e) {
				log.error("Unable to marshall private key: " + e);
				throw new CredentialFactoryException("Unable to load private key.");
			}
		}
	}
}

/**
 * Loads a credential from a Java keystore.
 * 
 * @author Walter Hoehn
 */

class KeystoreCredentialResolver implements CredentialResolver {

	private static Logger log = Logger.getLogger(KeystoreCredentialResolver.class.getName());

	public Credential loadCredential(Element e) throws CredentialFactoryException {

		if (!e.getLocalName().equals("KeyStoreResolver")) {
			log.error("Invalid Credential Resolver configuration: expected <KeyStoreResolver> .");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		String keyStoreType = e.getAttribute("storeType");
		if (keyStoreType == null || keyStoreType.equals("")) {
			log.debug("Using default store type for credential.");
			keyStoreType = "JKS";
		}

		String path = loadPath(e);
		String alias = loadAlias(e);
		String certAlias = loadCertAlias(e, alias);
		String keyPassword = loadKeyPassword(e);
		String keyStorePassword = loadKeyStorePassword(e);

		try {
			KeyStore keyStore = KeyStore.getInstance(keyStoreType);

			keyStore.load(new ShibResource(path, this.getClass()).getInputStream(), keyStorePassword.toCharArray());

			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyPassword.toCharArray());

			if (privateKey == null) { throw new CredentialFactoryException("No key entry was found with an alias of ("
					+ alias + ")."); }

			Certificate[] certificates = keyStore.getCertificateChain(certAlias);
			if (certificates == null) { throw new CredentialFactoryException(
					"An error occurred while reading the java keystore: No certificate found with the specified alias ("
							+ certAlias + ")."); }

			X509Certificate[] x509Certs = new X509Certificate[certificates.length];
			for (int i = 0; i < certificates.length; i++) {
				if (certificates[i] instanceof X509Certificate) {
					x509Certs[i] = (X509Certificate) certificates[i];
				} else {
					throw new CredentialFactoryException(
							"The KeyStore Credential Resolver can only load X509 certificates.  Found an unsupported certificate of type ("
									+ certificates[i] + ").");
				}
			}

			return new Credential(x509Certs, privateKey);

		} catch (KeyStoreException kse) {
			throw new CredentialFactoryException("An error occurred while accessing the java keystore: " + kse);
		} catch (NoSuchAlgorithmException nsae) {
			throw new CredentialFactoryException("Appropriate JCE provider not found in the java environment: " + nsae);
		} catch (CertificateException ce) {
			throw new CredentialFactoryException("The java keystore contained a certificate that could not be loaded: "
					+ ce);
		} catch (IOException ioe) {
			throw new CredentialFactoryException("An error occurred while reading the java keystore: " + ioe);
		} catch (UnrecoverableKeyException uke) {
			throw new CredentialFactoryException(
					"An error occurred while attempting to load the key from the java keystore: " + uke);
		}

	}

	private String loadPath(Element e) throws CredentialFactoryException {

		NodeList pathElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "Path");
		if (pathElements.getLength() < 1) {
			log.error("KeyStore path not specified.");
			throw new CredentialFactoryException("KeyStore Credential Resolver requires a <Path> specification.");
		}
		if (pathElements.getLength() > 1) {
			log.error("Multiple KeyStore path specifications, using first.");
		}
		Node tnode = pathElements.item(0).getFirstChild();
		String path = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			path = tnode.getNodeValue();
		}
		if (path == null || path.equals("")) {
			log.error("KeyStore path not specified.");
			throw new CredentialFactoryException("KeyStore Credential Resolver requires a <Path> specification.");
		}
		return path;
	}

	private String loadAlias(Element e) throws CredentialFactoryException {

		NodeList aliasElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "KeyAlias");
		if (aliasElements.getLength() < 1) {
			log.error("KeyStore key alias not specified.");
			throw new CredentialFactoryException("KeyStore Credential Resolver requires an <KeyAlias> specification.");
		}
		if (aliasElements.getLength() > 1) {
			log.error("Multiple key alias specifications, using first.");
		}
		Node tnode = aliasElements.item(0).getFirstChild();
		String alias = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			alias = tnode.getNodeValue();
		}
		if (alias == null || alias.equals("")) {
			log.error("KeyStore key alias not specified.");
			throw new CredentialFactoryException("KeyStore Credential Resolver requires an <KeyAlias> specification.");
		}
		return alias;
	}

	private String loadCertAlias(Element e, String defaultAlias) throws CredentialFactoryException {

		NodeList aliasElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "CertAlias");
		if (aliasElements.getLength() < 1) {
			log.debug("KeyStore cert alias not specified, defaulting to key alias.");
			return defaultAlias;
		}

		if (aliasElements.getLength() > 1) {
			log.error("Multiple cert alias specifications, using first.");
		}

		Node tnode = aliasElements.item(0).getFirstChild();
		String alias = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			alias = tnode.getNodeValue();
		}
		if (alias == null || alias.equals("")) {
			log.debug("KeyStore cert alias not specified, defaulting to key alias.");
			return defaultAlias;
		}
		return alias;
	}

	private String loadKeyStorePassword(Element e) throws CredentialFactoryException {

		NodeList passwordElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "StorePassword");
		if (passwordElements.getLength() < 1) {
			log.error("KeyStore password not specified.");
			throw new CredentialFactoryException(
					"KeyStore Credential Resolver requires an <StorePassword> specification.");
		}
		if (passwordElements.getLength() > 1) {
			log.error("Multiple KeyStore password specifications, using first.");
		}
		Node tnode = passwordElements.item(0).getFirstChild();
		String password = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			password = tnode.getNodeValue();
		}
		if (password == null || password.equals("")) {
			log.error("KeyStore password not specified.");
			throw new CredentialFactoryException(
					"KeyStore Credential Resolver requires an <StorePassword> specification.");
		}
		return password;
	}

	private String loadKeyPassword(Element e) throws CredentialFactoryException {

		NodeList passwords = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "KeyPassword");
		if (passwords.getLength() < 1) {
			log.error("KeyStore key password not specified.");
			throw new CredentialFactoryException(
					"KeyStore Credential Resolver requires an <KeyPassword> specification.");
		}
		if (passwords.getLength() > 1) {
			log.error("Multiple KeyStore key password specifications, using first.");
		}
		Node tnode = passwords.item(0).getFirstChild();
		String password = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			password = tnode.getNodeValue();
		}
		if (password == null || password.equals("")) {
			log.error("KeyStore key password not specified.");
			throw new CredentialFactoryException(
					"KeyStore Credential Resolver requires an <KeyPassword> specification.");
		}
		return password;
	}
}

/**
 * Uses implementation specified in the configuration to load a credential.
 * 
 * @author Walter Hoehn
 */

class CustomCredentialResolver implements CredentialResolver {

	private static Logger log = Logger.getLogger(CustomCredentialResolver.class.getName());

	public Credential loadCredential(Element e) throws CredentialFactoryException {

		if (!e.getLocalName().equals("CustomCredResolver")) {
			log.error("Invalid Credential Resolver configuration: expected <CustomCredResolver> .");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		String className = e.getAttribute("Class");
		if (className == null || className.equals("")) {
			log.error("Custom Credential Resolver requires specification of the attribute \"Class\".");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		try {
			return ((CredentialResolver) Class.forName(className).newInstance()).loadCredential(e);

		} catch (Exception loaderException) {
			log
					.error("Failed to load Custom Credential Resolver implementation class: "
							+ loaderException.getMessage());
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

	}

}

class CredentialFactoryException extends Exception {

	CredentialFactoryException(String message) {

		super(message);
	}
}
