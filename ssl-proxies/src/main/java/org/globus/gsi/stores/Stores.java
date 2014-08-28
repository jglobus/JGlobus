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

package org.globus.gsi.stores;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.util.HashMap;

import org.globus.common.CoGProperties;
import org.globus.gsi.provider.GlobusProvider;
import org.globus.gsi.provider.KeyStoreParametersFactory;

/**
 * @author Jerome Revillard
 *
 */
public class Stores {
	private static String defaultCAFilesPattern = "*.0";
	private static String defaultCRLFilesPattern = "*.r*";
	private static String defaultSigningPolicyFilesPattern = "*.signing_policy";

	private static final HashMap<String, ReloadableTrustStore> TRUST_STORES = new HashMap<String, ReloadableTrustStore>();
	private static final HashMap<String, ReloadableCrlStore> CRL_STORES = new HashMap<String, ReloadableCrlStore>();
	private static final HashMap<String, ReloadableCaCertStore> CA_CERT_STORES = new HashMap<String, ReloadableCaCertStore>();
	private static final HashMap<String, ResourceSigningPolicyStore> SIGNING_POLICY_STORES = new HashMap<String, ResourceSigningPolicyStore>();
	private final static long CACHE_TIME_MILLIS = 3600 * 1000;

	public static KeyStore getDefaultTrustStore() throws GeneralSecurityException, IOException {
		String pattern = "file:" + CoGProperties.getDefault().getCaCertLocations() + "/" + defaultCAFilesPattern;
		return getTrustStore(pattern);
	}

	public static KeyStore getTrustStore(String casLocationPattern) throws GeneralSecurityException, IOException {
		synchronized (TRUST_STORES) {
			ReloadableTrustStore reloadableKeystore = TRUST_STORES.get(casLocationPattern);
			if (reloadableKeystore != null) {
				return reloadableKeystore.getTrustStore();
			}
			reloadableKeystore = new ReloadableTrustStore(casLocationPattern);
			TRUST_STORES.put(casLocationPattern, reloadableKeystore);
			return reloadableKeystore.getTrustStore();
		}
	}

	public static CertStore getDefaultCACertStore() throws GeneralSecurityException, NoSuchAlgorithmException {
		String pattern = "file:" + CoGProperties.getDefault().getCaCertLocations() + "/" + defaultCAFilesPattern;
		return getCACertStore(pattern);
	}

	public static CertStore getCACertStore(String casLocationPattern) throws GeneralSecurityException,
			NoSuchAlgorithmException {
		synchronized (CA_CERT_STORES) {
			ReloadableCaCertStore reloadableCaCertStore = CA_CERT_STORES.get(casLocationPattern);
			if (reloadableCaCertStore == null) {
				reloadableCaCertStore = new ReloadableCaCertStore(casLocationPattern);
				CA_CERT_STORES.put(casLocationPattern, reloadableCaCertStore);
			}
			return reloadableCaCertStore.getCaCertStore();
		}
	}

	public static CertStore getDefaultCRLStore() throws GeneralSecurityException, NoSuchAlgorithmException {
		String pattern = "file:" + CoGProperties.getDefault().getCaCertLocations() + "/" + defaultCRLFilesPattern;
		return getCRLStore(pattern);
	}

	public static CertStore getCRLStore(String crlsLocationPattern) throws GeneralSecurityException,
			NoSuchAlgorithmException {
		synchronized (CRL_STORES) {
			ReloadableCrlStore reloadableCrlStore = CRL_STORES.get(crlsLocationPattern);
			if (reloadableCrlStore == null) {
				reloadableCrlStore = new ReloadableCrlStore(crlsLocationPattern);
				CRL_STORES.put(crlsLocationPattern, reloadableCrlStore);
			}
			return reloadableCrlStore.getCrlStore();
		}
	}

	public static ResourceSigningPolicyStore getDefaultSigningPolicyStore() throws GeneralSecurityException {
		String pattern = "file:" + CoGProperties.getDefault().getCaCertLocations() + "/"
				+ defaultSigningPolicyFilesPattern;
		return getSigningPolicyStore(pattern);
	}

	public static ResourceSigningPolicyStore getSigningPolicyStore(String signingPolicyLocationPattern)
			throws GeneralSecurityException {
		synchronized (SIGNING_POLICY_STORES) {
			ResourceSigningPolicyStore signingPolicyStore = SIGNING_POLICY_STORES.get(signingPolicyLocationPattern);
			if (signingPolicyStore == null) {
				signingPolicyStore = new ResourceSigningPolicyStore(new ResourceSigningPolicyStoreParameters(
						signingPolicyLocationPattern));
				SIGNING_POLICY_STORES.put(signingPolicyLocationPattern, signingPolicyStore);
			}
			return signingPolicyStore;
		}
	}

	public static String getDefaultCAFilesPattern() {
		return defaultCAFilesPattern;
	}

	public static void setDefaultCAFilesPattern(String defaultCAFilesPattern) {
		synchronized (TRUST_STORES) {
			synchronized (CA_CERT_STORES) {
				if (defaultCAFilesPattern == null || Stores.defaultCAFilesPattern.equals(defaultCAFilesPattern)) {
					return;
				}
				Stores.defaultCAFilesPattern = defaultCAFilesPattern;
				// Clear if we change the default pattern to prevent potential
				// memory issue;
				TRUST_STORES.clear();
				CA_CERT_STORES.clear();
			}
		}
	}

	public static String getDefaultCRLFilesPattern() {
		return defaultCRLFilesPattern;
	}

	public static void setDefaultCRLFilesPattern(String defaultCRLFilesPattern) {
		synchronized (CRL_STORES) {
			if (defaultCRLFilesPattern == null || Stores.defaultCRLFilesPattern.equals(defaultCRLFilesPattern)) {
				return;
			}
			Stores.defaultCRLFilesPattern = defaultCRLFilesPattern;
			// Clear if we change the default pattern to prevent potential
			// memory issue;
			CRL_STORES.clear();
		}
	}

	public static String getDefaultSigningPolicyFilesPattern() {
		return defaultSigningPolicyFilesPattern;
	}

	public static void setDefaultSigningPolicyFilesPattern(String defaultSigningPolicyFilesPattern) {
		synchronized (SIGNING_POLICY_STORES) {
			if (defaultSigningPolicyFilesPattern == null
					|| Stores.defaultSigningPolicyFilesPattern.equals(defaultSigningPolicyFilesPattern)) {
				return;
			}
			Stores.defaultSigningPolicyFilesPattern = defaultSigningPolicyFilesPattern;
			// Clear if we change the default pattern to prevent potential
			// memory issue;
			SIGNING_POLICY_STORES.clear();
		}
	}

	private static class ReloadableTrustStore {
		private final String casLocationPattern;
		private final KeyStore keyStore;
		private long lastUpdateTime;

		protected ReloadableTrustStore(String casLocationPattern) throws KeyStoreException, NoSuchProviderException,
				NoSuchAlgorithmException, CertificateException, IOException {
			this.casLocationPattern = casLocationPattern;
			keyStore = KeyStore.getInstance(GlobusProvider.KEYSTORE_TYPE, GlobusProvider.PROVIDER_NAME);
			reload();
		}

		private void reload() throws NoSuchAlgorithmException, CertificateException, IOException {
			keyStore.load(KeyStoreParametersFactory.createTrustStoreParameters(casLocationPattern));
			lastUpdateTime = System.currentTimeMillis();
		}

		protected boolean isStillValid() {
			return lastUpdateTime + CACHE_TIME_MILLIS > System.currentTimeMillis();
		}

		protected KeyStore getTrustStore() throws NoSuchAlgorithmException, CertificateException, IOException {
			if (!isStillValid()) {
				reload();
			}
			return keyStore;
		}
	}

	private static class ReloadableCrlStore {
		private final String crlsLocationPattern;
		private CertStore certStore;
		private long lastUpdateTime;

		protected ReloadableCrlStore(String crlsLocationPattern) throws InvalidAlgorithmParameterException,
				NoSuchAlgorithmException {
			this.crlsLocationPattern = crlsLocationPattern;
			load();
		}

		private void load() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
			certStore = CertStore.getInstance(GlobusProvider.CERTSTORE_TYPE, new ResourceCertStoreParameters(null,
					crlsLocationPattern));
			lastUpdateTime = System.currentTimeMillis();
		}

		protected boolean isStillValid() {
			return lastUpdateTime + CACHE_TIME_MILLIS > System.currentTimeMillis();
		}

		protected CertStore getCrlStore() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
			if (!isStillValid()) {
				load();
			}
			return certStore;
		}
	}

	private static class ReloadableCaCertStore {
		private final String casLocationPattern;
		private CertStore certStore;
		private long lastUpdateTime;

		protected ReloadableCaCertStore(String casLocationPattern) throws InvalidAlgorithmParameterException,
				NoSuchAlgorithmException {
			this.casLocationPattern = casLocationPattern;
			load();
		}

		private void load() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
			certStore = CertStore.getInstance(GlobusProvider.CERTSTORE_TYPE, new ResourceCertStoreParameters(
					casLocationPattern, null));
			lastUpdateTime = System.currentTimeMillis();
		}

		protected boolean isStillValid() {
			return lastUpdateTime + CACHE_TIME_MILLIS > System.currentTimeMillis();
		}

		protected CertStore getCaCertStore() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
			if (!isStillValid()) {
				load();
			}
			return certStore;
		}
	}
}
