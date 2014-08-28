/*
 * Copyright 1999-2010 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS,WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

package org.globus.gsi.stores;

import static org.globus.gsi.util.CertificateIOUtil.writeCertificate;

import org.globus.gsi.CredentialException;
import org.globus.gsi.X509Credential;

import org.globus.gsi.provider.KeyStoreParametersFactory;

import org.apache.commons.logging.LogFactory;

import org.apache.commons.logging.Log;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.Properties;

import org.globus.util.GlobusResource;
import org.globus.util.GlobusPathMatchingResourcePatternResolver;

import org.globus.gsi.util.CertificateIOUtil;

/**
 * This class provides a KeyStore implementation that supports trusted
 * certificates stored in PEM format and proxy certificates stored in PEM
 * format. It reads trusted certificates from multiple directories and a proxy
 * certificate from a file.
 *
 * @version ${version}
 * @since 1.0
 */
public class PEMKeyStore extends KeyStoreSpi {

	// Default trusted certificates directory
	public static final String DEFAULT_DIRECTORY_KEY = "default_directory";
	// List of directory names to load certificates from
	// JGLOBUS-90 : does it take certificate file names in this list?
	public static final String DIRECTORY_LIST_KEY = "directory_list";
	// X.509 Certificate file name, should be set along with KEY_FILENAME
	public static final String CERTIFICATE_FILENAME = "certificateFilename";
	// Key, typically private key, accompanying the certificate
	public static final String KEY_FILENAME = "keyFilename";
	// X.509 PRoxy Cerificate file name
	public static final String PROXY_FILENAME = "proxyFilename";

	private static Log logger = LogFactory.getLog(PEMKeyStore.class
			.getCanonicalName());

	// Map from alias to the object (either key or certificate)
	private Map<String, SecurityObjectWrapper<?>> aliasObjectMap = new Hashtable<String, SecurityObjectWrapper<?>>();
	// Map from trusted certificate to filename
	private Map<Certificate, String> certFilenameMap = new HashMap<Certificate, String>();

	// default directory for trusted certificates
	private File defaultDirectory;
	private ResourceSecurityWrapperStore<ResourceTrustAnchor, TrustAnchor> caDelegate = new ResourceCACertStore();
	private ResourceSecurityWrapperStore<ResourceProxyCredential, X509Credential> proxyDelegate = new ResourceProxyCredentialStore();

	private boolean inMemoryOnly = false;

	public void setCACertStore(
			ResourceSecurityWrapperStore<ResourceTrustAnchor, TrustAnchor> caCertStore) {
		this.caDelegate = caCertStore;
	}

	public void setProxyDelegate(
			ResourceSecurityWrapperStore<ResourceProxyCredential, X509Credential> proxyDelegate) {
		this.proxyDelegate = proxyDelegate;
	}

	private CredentialWrapper getKeyEntry(String alias) {

		SecurityObjectWrapper<?> object = this.aliasObjectMap.get(alias);
		if ((object != null) && (object instanceof CredentialWrapper)) {
			return (CredentialWrapper) object;
		}
		return null;
	}

	private ResourceTrustAnchor getCertificateEntry(String alias) {

		SecurityObjectWrapper<?> object = this.aliasObjectMap.get(alias);
		if ((object != null) && (object instanceof ResourceTrustAnchor)) {
			return (ResourceTrustAnchor) object;
		}
		return null;
	}

	/**
	 * Get the key referenced by the specified alias.
	 *
	 * @param s
	 *            The key's alias.
	 * @param chars
	 *            The key's password.
	 * @return The key reference by the alias or null.
	 * @throws NoSuchAlgorithmException
	 *             If the key is encoded with an invalid algorithm.
	 * @throws UnrecoverableKeyException
	 *             If the key can not be retrieved.
	 */
	@Override
	public Key engineGetKey(String s, char[] chars)
			throws NoSuchAlgorithmException, UnrecoverableKeyException {

		CredentialWrapper credential = getKeyEntry(s);
		Key key = null;
		if (credential != null) {
			try {
				String password = null;
				if (chars != null) {
					password = new String(chars);
				}
				key = credential.getCredential().getPrivateKey(password);
			} catch (ResourceStoreException e) {
				throw new UnrecoverableKeyException(e.getMessage());
			} catch (CredentialException e) {
				throw new UnrecoverableKeyException(e.getMessage());
			}
		}
		return key;
	}

	/**
	 * Does the supplied alias refer to a key in this key store.
	 *
	 * @param s
	 *            The alias.
	 * @return True if the alias refers to a key.
	 */
	@Override
	public boolean engineIsKeyEntry(String s) {
		return getKeyEntry(s) != null;
	}

	/**
	 * Persist the security material in this keystore. If the object has a path
	 * associated with it, the object will be persisted to that path. Otherwise
	 * it will be stored in the default certificate directory. As a result, the
	 * parameters of this method are ignored.
	 *
	 * @param outputStream
	 *            This parameter is ignored.
	 * @param chars
	 *            This parameter is ignored.
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 */
	@Override
	public void engineStore(OutputStream outputStream, char[] chars)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		for (SecurityObjectWrapper<?> object : this.aliasObjectMap.values()) {
			if (object instanceof Storable) {
				try {
					((Storable) object).store();
				} catch (ResourceStoreException e) {
					throw new CertificateException(e);
				}
			}
		}
	}

	/**
	 * Get the creation date for the object referenced by the alias.
	 *
	 * @param s
	 *            The alias of the security object.
	 * @return The creation date of the security object.
	 */
	@Override
	public Date engineGetCreationDate(String s) {
		try {
			ResourceTrustAnchor trustAnchor = getCertificateEntry(s);
			if (trustAnchor != null) {
				return trustAnchor.getTrustAnchor().getTrustedCert()
						.getNotBefore();
			} else {
				CredentialWrapper credential = getKeyEntry(s);
				if (credential != null) {
					return credential.getCredential().getNotBefore();
				}
			}
		} catch (ResourceStoreException e) {
			return null;
		}
		return null;
	}

	/**
	 * Get the alias associated with the supplied certificate.
	 *
	 * @param certificate
	 *            The certificate to query
	 * @return The certificate's alias or null if the certificate is not present
	 *         in this keystore.
	 */
	@Override
	public String engineGetCertificateAlias(Certificate certificate) {
		return this.certFilenameMap.get(certificate);
	}

	/**
	 * Get the certificateChain for the key referenced by the alias.
	 *
	 * @param s
	 *            The key alias.
	 * @return The key's certificate chain or a 0 length array if the key is not
	 *         in the keystore.
	 */
	@Override
	public Certificate[] engineGetCertificateChain(String s) {
		CredentialWrapper credential = getKeyEntry(s);
		X509Certificate[] chain = new X509Certificate[0];
		if (credential != null) {
			try {
				chain = credential.getCredential().getCertificateChain();
			} catch (ResourceStoreException e) {
				logger.warn(e.getMessage(), e);
				chain = null;
			}
		}
		return chain;
	}

	/**
	 * Get the certificate referenced by the supplied alias.
	 *
	 * @param s
	 *            The alias.
	 * @return The Certificate or null if the alias does not exist in the
	 *         keyStore.
	 */
	@Override
	public Certificate engineGetCertificate(String s) {
		ResourceTrustAnchor trustAnchor = getCertificateEntry(s);
		if (trustAnchor != null) {
			try {
				return trustAnchor.getTrustAnchor().getTrustedCert();
			} catch (ResourceStoreException e) {
				return null;
			}
		}
		return null;
	}

	/**
	 * Load the keystore based on parameters in the LoadStoreParameter. The
	 * parameter object must be an instance of FileBasedKeyStoreParameters.
	 *
	 * @param loadStoreParameter
	 *            The parameters to load.
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 */
	@Override
	public void engineLoad(KeyStore.LoadStoreParameter loadStoreParameter)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		if (!(loadStoreParameter instanceof KeyStoreParametersFactory.FileStoreParameters)) {
			throw new IllegalArgumentException("Unable to process parameters: "
					+ loadStoreParameter);
		}
		KeyStoreParametersFactory.FileStoreParameters params = (KeyStoreParametersFactory.FileStoreParameters) loadStoreParameter;
		String defaultDirectoryString = (String) params
				.getProperty(DEFAULT_DIRECTORY_KEY);
		String directoryListString = (String) params
				.getProperty(DIRECTORY_LIST_KEY);
		String certFilename = (String) params.getProperty(CERTIFICATE_FILENAME);
		String keyFilename = (String) params.getProperty(KEY_FILENAME);
		String proxyFilename = (String) params.getProperty(PROXY_FILENAME);
		initialize(defaultDirectoryString, directoryListString, proxyFilename,
				certFilename, keyFilename);
	}

	/**
	 * Load the keystore from the supplied input stream. Unlike many other
	 * implementations of keystore (most notably the default JKS
	 * implementation), the input stream does not hold the keystore objects.
	 * Instead, it must be a properties file defining the locations of the
	 * keystore objects. The password is not used.
	 *
	 * @param inputStream
	 *            An input stream to the properties file.
	 * @param chars
	 *            The password is not used.
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 */
	@Override
	public void engineLoad(InputStream inputStream, char[] chars)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		try {
			Properties properties = new Properties();
			if(inputStream != null){
				properties.load(inputStream);
				if (properties.size() == 0) {
					throw new CertificateException(
							"Properties file for configuration was empty?");
				}
			}else{
				if(chars == null){
					// keyStore.load(null,null) -> in memory only keystore
					inMemoryOnly = true;
				}
			}
			String defaultDirectoryString = properties
					.getProperty(DEFAULT_DIRECTORY_KEY);
			String directoryListString = properties
					.getProperty(DIRECTORY_LIST_KEY);
			String proxyFilename = properties.getProperty(PROXY_FILENAME);
			String certFilename = properties.getProperty(CERTIFICATE_FILENAME);
			String keyFilename = properties.getProperty(KEY_FILENAME);
			initialize(defaultDirectoryString, directoryListString,
					proxyFilename, certFilename, keyFilename);
		} finally {
			if(inputStream != null){
				try {
					inputStream.close();
				} catch (IOException e) {
					logger.info("Error closing inputStream", e);
				}
			}
		}
	}

	/**
	 * Initialize resources from filename, proxyfile name
	 *
	 * @param defaultDirectoryString
	 *            Name of the default directory name as:
	 *            "file: directory name"
	 * @param directoryListString
	 * @param proxyFilename
	 * @param certFilename
	 * @param keyFilename
	 *
	 * @throws IOException
	 * @throws CertificateException
	 */
	private void initialize(String defaultDirectoryString,
			String directoryListString, String proxyFilename,
			String certFilename, String keyFilename) throws IOException,
			CertificateException {

		if (defaultDirectoryString != null) {
			defaultDirectory = new GlobusPathMatchingResourcePatternResolver().getResource(defaultDirectoryString).getFile();
			if (!defaultDirectory.exists()) {
				boolean directoryMade = defaultDirectory.mkdirs();
				if (!directoryMade) {
					throw new IOException(
							"Unable to create default certificate directory");
				}
			}
			loadDirectories(defaultDirectoryString);
		}
		if (directoryListString != null) {
			loadDirectories(directoryListString);
		}
		try {
			if (proxyFilename != null && proxyFilename.length() > 0) {
				loadProxyCertificate(proxyFilename);
			}
			if ((certFilename != null && certFilename.length() > 0)
					&& (keyFilename != null && keyFilename.length() > 0)) {
				loadCertificateKey(certFilename, keyFilename);
			}
		} catch (ResourceStoreException e) {
			throw new CertificateException(e);
		} catch (CredentialException e) {
			e.printStackTrace();
			throw new CertificateException(e);
		}
	}

	private void loadProxyCertificate(String proxyFilename)
			throws ResourceStoreException {

		if (proxyFilename == null) {
			return;
		}

		proxyDelegate.loadWrappers(proxyFilename);
		Map<String, ResourceProxyCredential> wrapperMap = proxyDelegate
				.getWrapperMap();
		for (ResourceProxyCredential credential : wrapperMap.values()) {
			this.aliasObjectMap.put(proxyFilename, credential);
		}
	}

    private void loadCertificateKey(String userCertFilename,
                                    String userKeyFilename) throws CredentialException,
            ResourceStoreException {
        GlobusPathMatchingResourcePatternResolver resolver = new GlobusPathMatchingResourcePatternResolver();

        if ((userCertFilename == null) || (userKeyFilename == null)) {
            return;
        }
        // File certFile = new File(userCertFilename);
        // File keyFile = new File(userKeyFilename);
        GlobusResource certResource = resolver.getResource(userCertFilename);
        GlobusResource keyResource = resolver.getResource(userKeyFilename);
        CertKeyCredential credential = new CertKeyCredential(certResource,
                keyResource);
        // What do we name this alias?
        String alias = userCertFilename + ":" + userKeyFilename;
        this.aliasObjectMap.put(alias, credential);
    }

	private void loadDirectories(String directoryList)
			throws CertificateException {

		try {
			caDelegate.loadWrappers(directoryList);
			Map<String, ResourceTrustAnchor> wrapperMap = caDelegate
					.getWrapperMap();
            Set<String> knownCerts = new HashSet<String>();
			// The alias hashing merits explanation.  Loading all the files in a directory triggers a
			// deadlock bug for old jglobus clients if the directory contains repeated CAs (like the
			// modern IGTF bundle does).  So, we ignore the cert if the alias is incorrect or already seen.
			// However, we track all the certs we ignore and load any that were completely ignored due to
			// aliases.  So, non-hashed directories will still work.
			Map<String, String> ignoredAlias = new HashMap<String, String>();
			Map<String, ResourceTrustAnchor> ignoredAnchor = new HashMap<String, ResourceTrustAnchor>();
			Map<String, X509Certificate> ignoredCert = new HashMap<String, X509Certificate>();
			for (ResourceTrustAnchor trustAnchor : wrapperMap.values()) {
				String alias = trustAnchor.getResourceURL().toExternalForm();
				TrustAnchor tmpTrustAnchor = trustAnchor.getTrustAnchor();
				X509Certificate trustCert = tmpTrustAnchor.getTrustedCert();
                String hash = CertificateIOUtil.nameHash(trustCert.getSubjectX500Principal());
                if (this.aliasObjectMap == null) {
                    System.out.println("Alias Map Null");
                }
				boolean hash_in_alias = !alias.contains(hash);
				if (knownCerts.contains(hash) || !hash_in_alias) {
					if (!hash_in_alias) {
						ignoredAlias.put(hash, alias);
						ignoredAnchor.put(hash, trustAnchor);
						ignoredCert.put(hash, trustCert);
					}
                    continue;
                }
                knownCerts.add(hash);
                this.aliasObjectMap.put(alias, trustAnchor);
                certFilenameMap.put(trustCert, alias);
			}
			// Add any CA we skipped above.
			for (String hash : ignoredAlias.keySet()) {
				if (knownCerts.contains(hash)) {
					continue;
				}
				String alias = ignoredAlias.get(hash);
				this.aliasObjectMap.put(alias, ignoredAnchor.get(hash));
				certFilenameMap.put(ignoredCert.get(hash), alias);
			}
		} catch (ResourceStoreException e) {
			throw new CertificateException("",e);
		}
	}

	/**
	 * Delete a security object from this keystore.
	 *
	 * @param s
	 *            The alias of the object to delete.
	 * @throws KeyStoreException
	 */
	@Override
	public void engineDeleteEntry(String s) throws KeyStoreException {

		SecurityObjectWrapper<?> object = this.aliasObjectMap.remove(s);
		if (object != null) {
			if (object instanceof ResourceTrustAnchor) {

				ResourceTrustAnchor descriptor = (ResourceTrustAnchor) object;
				Certificate cert;
				try {
					cert = descriptor.getTrustAnchor().getTrustedCert();
				} catch (ResourceStoreException e) {
					throw new KeyStoreException(e);
				}
				this.certFilenameMap.remove(cert);
				boolean success = descriptor.getFile().delete();
				if (!success) {
					// JGLOBUS-91 : warn? throw error?
					logger.info("Unable to delete certificate");
				}
			} else if (object instanceof ResourceProxyCredential) {

				ResourceProxyCredential proxy = (ResourceProxyCredential) object;
				try {
					proxy.getCredential();
				} catch (ResourceStoreException e) {
					throw new KeyStoreException(e);
				}
				boolean success = proxy.getFile().delete();
				if (!success) {
					// JGLOBUS-91 : warn? throw error?
					logger.info("Unable to delete credential");
				}
			}
		}
	}

	/**
	 * Get an enumertion of all of the aliases in this keystore.
	 *
	 * @return An enumeration of the aliases in this keystore.
	 */
	@Override
	public Enumeration<String> engineAliases() {

		return Collections.enumeration(this.aliasObjectMap.keySet());
	}

	/**
	 * Add a new private key to the keystore.
	 *
	 * @param s
	 *            The alias for the object.
	 * @param key
	 *            The private key.
	 * @param chars
	 *            The password.
	 * @param certificates
	 *            The key's certificate chain.
	 * @throws KeyStoreException
	 */
	@Override
	public void engineSetKeyEntry(String s, Key key, char[] chars,
			Certificate[] certificates) throws KeyStoreException {

		if (!(key instanceof PrivateKey)) {
			throw new KeyStoreException("PrivateKey expected");
		}

		if (!(certificates instanceof X509Certificate[])) {
			throw new KeyStoreException(
					"Certificate chain of X509Certificate expected");
		}
		CredentialWrapper wrapper;
		X509Credential credential = new X509Credential((PrivateKey) key,
				(X509Certificate[]) certificates);
		if (credential.isEncryptedKey()) {
			wrapper = createCertKeyCredential(s, credential);
		} else {
			wrapper = createProxyCredential(s, credential);
		}
		storeWrapper(wrapper);
		this.aliasObjectMap.put(wrapper.getAlias(), wrapper);
	}

	@SuppressWarnings("rawtypes")
	private CredentialWrapper createProxyCredential(String s,
			X509Credential credential) throws KeyStoreException {
		CredentialWrapper wrapper;
		CredentialWrapper proxyCredential = getKeyEntry(s);
		File file;
		if (proxyCredential != null
				&& proxyCredential instanceof AbstractResourceSecurityWrapper) {
			AbstractResourceSecurityWrapper proxyWrapper = (AbstractResourceSecurityWrapper) proxyCredential;
			file = proxyWrapper.getFile();
		} else {
			// JGLOBUS-91 : should alias be file name? or generate?
			file = new File(defaultDirectory, s + "-key.pem");
		}
		try {
			wrapper = new ResourceProxyCredential(inMemoryOnly, new GlobusResource(file.getAbsolutePath()),
					credential);
		} catch (ResourceStoreException e) {
			throw new KeyStoreException(e);
		}
		return wrapper;
	}

    private CredentialWrapper createCertKeyCredential(String s,
                                                      X509Credential credential) throws KeyStoreException {
        GlobusResource certResource;
        GlobusResource keyResource;
        CredentialWrapper wrapper;
        CredentialWrapper credentialWrapper = getKeyEntry(s);
        if (credentialWrapper != null
                && credentialWrapper instanceof CertKeyCredential) {
            CertKeyCredential certKeyCred = (CertKeyCredential) credentialWrapper;
            certResource = certKeyCred.getCertificateFile();
            keyResource = certKeyCred.getKeyFile();
        } else {
            certResource = new GlobusResource(new File(defaultDirectory, s
                    + ".0").getAbsolutePath());
            keyResource = new GlobusResource(new File(defaultDirectory, s
                    + "-key.pem").getAbsolutePath());
        }
        try {
            wrapper = new CertKeyCredential(certResource, keyResource,
                    credential);
        } catch (ResourceStoreException e) {
            throw new KeyStoreException(e);
        }
        return wrapper;
    }

	private void storeWrapper(CredentialWrapper wrapper)
			throws KeyStoreException {
		if(!inMemoryOnly){
			try {
				wrapper.store();
			} catch (ResourceStoreException e) {
				throw new KeyStoreException("Error storing credential", e);
			}
		}
	}

	/**
	 * currently unsupported.
	 *
	 * @param s
	 *            The key's alias
	 * @param bytes
	 *            The encoded private key.
	 * @param certificates
	 *            The key's certificate chain.
	 * @throws KeyStoreException
	 */
	@Override
	public void engineSetKeyEntry(String s, byte[] bytes,
			Certificate[] certificates) throws KeyStoreException {
		throw new UnsupportedOperationException();
		// JGLOBUS-91
	}

	/**
	 * Does the specified alias exist in this keystore?
	 *
	 * @param s
	 *            The alias.
	 * @return True if the alias refers to a security object in the keystore.
	 */
	@Override
	public boolean engineContainsAlias(String s) {
		return this.aliasObjectMap.containsKey(s);
	}

	/**
	 * Get the number of security objects stored in this keystore.
	 *
	 * @return The number of security objects.
	 */
	@Override
	public int engineSize() {
		return this.aliasObjectMap.size();
	}

	/**
	 * Does the supplied alias refer to a certificate in this keystore?
	 *
	 * @param s
	 *            The alias.
	 * @return True if this store contains a certificate with the specified
	 *         alias.
	 */
	@Override
	public boolean engineIsCertificateEntry(String s) {
		return getCertificateEntry(s) != null;
	}

	/**
	 * Add a certificate to the keystore.
	 *
	 * @param alias
	 *            The certificate alias.
	 * @param certificate
	 *            The certificate to store.
	 * @throws KeyStoreException
	 */
	@Override
	public void engineSetCertificateEntry(String alias, Certificate certificate)
			throws KeyStoreException {

		if (!(certificate instanceof X509Certificate)) {
			throw new KeyStoreException(
					"Certificate must be instance of X509Certificate");
		}
		File file;
		ResourceTrustAnchor trustAnchor = getCertificateEntry(alias);
		if (trustAnchor != null) {
			file = trustAnchor.getFile();
		} else {
			file = new File(defaultDirectory, alias);
		}
		X509Certificate x509Cert = (X509Certificate) certificate;
		try {
			if(!inMemoryOnly){
				writeCertificate(x509Cert, file);
			}
			ResourceTrustAnchor anchor = new ResourceTrustAnchor(inMemoryOnly,
					new GlobusResource(file.getAbsolutePath()), new TrustAnchor(x509Cert,
							null));
			this.aliasObjectMap.put(alias, anchor);
			this.certFilenameMap.put(x509Cert, alias);
		} catch (ResourceStoreException e) {
			throw new KeyStoreException(e);
		} catch (IOException e) {
			throw new KeyStoreException(e);
		} catch (CertificateEncodingException e) {
			throw new KeyStoreException(e);
		}
	}

}
