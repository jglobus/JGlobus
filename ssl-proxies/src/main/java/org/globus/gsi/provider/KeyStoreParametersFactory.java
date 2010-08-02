package org.globus.gsi.provider;

import org.globus.gsi.stores.PEMKeyStore;

import java.security.KeyStore;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.ProtectionParameter;



public class KeyStoreParametersFactory {

	public static KeyStore.LoadStoreParameter createCertKeyParameters(
			String certLocations, String keyLocation) {
		return new CertKeyParameters(certLocations, keyLocation);
	}

	public static KeyStore.LoadStoreParameter createProxyCertParameters(
			String proxyCertLocation) {
		return new ProxyCertParameters(proxyCertLocation);
	}

	public static LoadStoreParameter createTrustStoreParameters(
			String trustedCertificateDirectories) {
		return new TrustStoreParameters(trustedCertificateDirectories, null);
	}

	public static LoadStoreParameter createTrustStoreParameters(
			String trustedCertificateDirectories, String defaultDirectory) {
		return new TrustStoreParameters(trustedCertificateDirectories,
				defaultDirectory);
	}

	private static class TrustStoreParameters implements FileStoreParameters {
		private String trustedCertificateDirectories;
		private String defaultCertificateDirectory;

		public TrustStoreParameters(String trustedCertificateDirectories,
				String defaultCertificateDirectory) {
			super();
			this.trustedCertificateDirectories = trustedCertificateDirectories;
			this.defaultCertificateDirectory = defaultCertificateDirectory;
		}

		public Object getProperty(String key) {
			if (key.equals(PEMKeyStore.DIRECTORY_LIST_KEY)) {
				return trustedCertificateDirectories;
			} else if (key.equals(PEMKeyStore.DEFAULT_DIRECTORY_KEY)) {
				return defaultCertificateDirectory;
			}
			return null;
		}

		public ProtectionParameter getProtectionParameter() {
			// TODO Auto-generated method stub
			return null;
		}

	}

	private static class ProxyCertParameters implements FileStoreParameters {

		private String proxyLocation;

		public ProxyCertParameters(String proxyLocation) {
			super();
			this.proxyLocation = proxyLocation;
		}

		public Object getProperty(String key) {
			if (key.equals(PEMKeyStore.PROXY_FILENAME)) {
				return this.proxyLocation;
			} else {
				return null;
			}
		}

		public ProtectionParameter getProtectionParameter() {
			// TODO Auto-generated method stub
			return null;
		}

	}

	private static class CertKeyParameters implements FileStoreParameters {
		private String certLocations;
		private String keyLocation;
		private ProtectionParameter param;

		public CertKeyParameters(String certLocations, String keyLocation) {
			super();
			this.certLocations = certLocations;
			this.keyLocation = keyLocation;
		}

		public ProtectionParameter getProtectionParameter() {
			return param;
		}

		public Object getProperty(String key) {
			if (key.equals(PEMKeyStore.KEY_FILENAME)) {
				return this.keyLocation;
			} else if (key.equals(PEMKeyStore.CERTIFICATE_FILENAME)) {
				return this.certLocations;
			} else {
				return null;
			}
		}

	}

	public static interface FileStoreParameters extends LoadStoreParameter {
		public Object getProperty(String key);
	}
}
