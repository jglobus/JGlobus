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
package org.globus.gsi.provider;

import org.globus.gsi.trustmanager.PKITrustManagerFactory;
import org.globus.gsi.trustmanager.X509ProxyCertPathValidator;
import org.globus.gsi.stores.PEMKeyStore;
import org.globus.gsi.stores.ResourceCertStore;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;


/**
 * This is a security provider for the Globus SSL support. This supplies a
 * CertStore, CertValidator and KeyStore implementation
 *
 * @version ${version}
 * @since 1.0
 */
public final class GlobusProvider extends Provider {

	public static final String PROVIDER_NAME = "Globus";
	public static final String CERTSTORE_TYPE = "PEMFilebasedCertStore";
	public static final String CERT_PATH_VALIDATOR_TYPE = "X509ProxyPath";
	public static final String KEYSTORE_TYPE = "PEMFilebasedKeyStore";
	public static final String TRUSTMANAGER_TYPE = "GlobusTrustManager";

	private static final long serialVersionUID = -6275241207604782362L;

	/**
	 * Create Provider and add Components to the java security framework.
	 */
	public GlobusProvider() {

		super(PROVIDER_NAME, 1.0, "Globus Security Providers");
		AccessController.doPrivileged(new PrivilegedAction<Object>() {
			public Object run() {
				put("CertStore.PEMFilebasedCertStore", ResourceCertStore.class
						.getName());
				put("CertPathValidator.X509ProxyPath",
						X509ProxyCertPathValidator.class.getName());
				put("KeyStore.PEMFilebasedKeyStore", PEMKeyStore.class
						.getName());
				put("TrustManagerFactory.GSI",
						PKITrustManagerFactory.class.getCanonicalName());
				return null;
			}
		});

	}

}
