/*
 * Copyright 1999-2010 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS,WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */
package org.globus.gsi.jsse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.globus.gsi.stores.Stores;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;

/**
 * This is a utility class designed to simplify common tasks required for
 * configuring the globus ssl support.
 *
 * @version 1.0
 * @since 1.0
 */
// TODO: support custom classloader
public final class GlobusSSLHelper {

	private GlobusSSLHelper() {
		// Should not be instantiated.
	}

	/**
	 * Create a trust store using the supplied details. Java SSL requires the
	 * trust store to be supplied as a java.security.KeyStore, so this will
	 * create a KeyStore containing all of the Trust Anchors.
	 *
	 * @param provider
	 *            The Java security provider to use.
	 * @param trustAnchorStoreType
	 *            The type of key store to be constructed.
	 * @param trustAnchorStoreLocation
	 *            The location of the trust store file
	 * @param trustAnchorStorePassword
	 *            The password for the trust store.
	 * @return A configured Keystore which holds TrustAnchors. Note that this
	 *         holds trusted certificates, not keys/credentials
	 * @throws GlobusSSLConfigurationException
	 *             If unable to construct the TrustStore.
	 */
	public static KeyStore buildTrustStore(String provider,
			String trustAnchorStoreType, String trustAnchorStoreLocation,
			String trustAnchorStorePassword)
			throws GlobusSSLConfigurationException {
		try {
			KeyStore trustAnchorStore;
			if (provider == null) {
				trustAnchorStore = KeyStore.getInstance(trustAnchorStoreType);
			} else {
				trustAnchorStore = KeyStore.getInstance(trustAnchorStoreType,
						provider);
			}
			InputStream keyStoreInput = getStream(trustAnchorStoreLocation);
                        try {
                            trustAnchorStore.load(new BufferedInputStream(keyStoreInput),
					trustAnchorStorePassword == null ? null
							: trustAnchorStorePassword.toCharArray());
                        } finally {
                            keyStoreInput.close();
                        }
			return trustAnchorStore;
		} catch (KeyStoreException e) {
			throw new GlobusSSLConfigurationException(e);
		} catch (IOException e) {
			throw new GlobusSSLConfigurationException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new GlobusSSLConfigurationException(e);
		} catch (CertificateException e) {
			throw new GlobusSSLConfigurationException(e);
		} catch (NoSuchProviderException e) {
			throw new GlobusSSLConfigurationException(e);
		}
	}

	/**
	 * Create a configured CredentialStore using the supplied parameters. The
	 * credential store is a java.security.KeyStore.
	 *
	 * @param provider
	 *            The Java security provider to use.
	 * @param credentialStoreType
	 *            The type of key store to be constructed.
	 * @param credentialStoreLocation
	 *            The location of the credential store file
	 * @param credentialStorePassword
	 *            The password for the credential store.
	 * @return A configured Keystore which holds credentials defined by these
	 *         parameters.
	 * @throws GlobusSSLConfigurationException
	 *             If unable to construct the Credential Store.
	 */
	public static KeyStore findCredentialStore(String provider,
			String credentialStoreType, String credentialStoreLocation,
			String credentialStorePassword)
			throws GlobusSSLConfigurationException {
		try {
			KeyStore credentialStore;
			if (provider == null) {
				credentialStore = KeyStore.getInstance(credentialStoreType);
			} else {
				credentialStore = KeyStore.getInstance(credentialStoreType,
						provider);
			}
			InputStream keyStoreInput = getStream(credentialStoreLocation);
                        try {
                            credentialStore.load(new BufferedInputStream(keyStoreInput),
					credentialStorePassword == null ? null
							: credentialStorePassword.toCharArray());
                        } finally {
                            keyStoreInput.close();
                        }
			return credentialStore;
		} catch (KeyStoreException e) {
			throw new GlobusSSLConfigurationException(e);
		} catch (IOException e) {
			throw new GlobusSSLConfigurationException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new GlobusSSLConfigurationException(e);
		} catch (CertificateException e) {
			throw new GlobusSSLConfigurationException(e);
		} catch (NoSuchProviderException e) {
			throw new GlobusSSLConfigurationException(e);
		}
	}

	private static InputStream getStream(String url)
			throws MalformedURLException, IOException {
		if (url.startsWith("classpath:")) {
			String resource = url.substring(10);
			URL u = ClassLoader.class.getResource(resource);
			if (u == null) {
				throw new MalformedURLException();
			}
			return u.openStream();
		} else if (url.startsWith("file:")) {
			URL u = new URL(url);
			File f;
			try {
				f = new File(u.toURI());
			} catch (URISyntaxException e) {
				f = new File(u.getPath());
			}
			return new FileInputStream(f);
		} else {
			return new URL(url).openStream();
		}

	}

	/**
	 * Create a store of Certificate Revocation Lists. Java requires that this
	 * be a java.security.certificates.CertStore. As such, the store can hold
	 * both CRL's and non-trusted certs. For the purposes of this method, we
	 * assume that only crl's will be loaded. This can only be used with the
	 * Globus provided Certificate Store.
	 *
	 * @param crlPattern
	 *            The pattern which defines the locations of the CRL's
	 * @return A configured Java CertStore containing the specified CRL's
	 * @throws GlobusSSLConfigurationException
	 *             if the store cannot be loaded.
	 */
	public static CertStore findCRLStore(String crlPattern)
			throws GlobusSSLConfigurationException {
		try {
			return Stores.getCRLStore(crlPattern);
		} catch (InvalidAlgorithmParameterException e) {
			throw new GlobusSSLConfigurationException(e);
		} catch (NoSuchAlgorithmException e) {
			Log logger = LogFactory.getLog(GlobusSSLHelper.class.getCanonicalName());
			logger.warn("Error Loading CRL store", e);
			throw new GlobusSSLConfigurationException(e);
		} catch (GeneralSecurityException e) {
			Log logger = LogFactory.getLog(GlobusSSLHelper.class.getCanonicalName());
			logger.warn("Error Loading CRL store", e);
			throw new GlobusSSLConfigurationException(e);
		}
	}
}
