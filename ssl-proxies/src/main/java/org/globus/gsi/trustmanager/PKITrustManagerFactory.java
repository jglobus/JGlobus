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

package org.globus.gsi.trustmanager;

import org.globus.gsi.X509ProxyCertPathParameters;

import org.globus.gsi.provider.GlobusTrustManagerFactoryParameters;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Collection;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;


/**
 * This factory creates trust managers which support the Globus SSL library.
 *
 * @version ${version}
 * @since 1.0
 */
public class PKITrustManagerFactory extends TrustManagerFactorySpi {

	private Collection<TrustManager> trustManagers = new ArrayList<TrustManager>();

	/**
	 * Initializes this factory with a source of certificate authorities and
	 * related trust material.
	 *
	 * @param keyStore
	 *            The key store or null
	 * @throws KeyStoreException
	 *             if the initialization fails.
	 */
	@Override
	protected void engineInit(KeyStore keyStore) throws KeyStoreException {
		try {
			this
					.engineInit(new CertPathTrustManagerParameters(
							new X509ProxyCertPathParameters(keyStore, null,
									null, false)));
		} catch (InvalidAlgorithmParameterException e) {
			throw new KeyStoreException(e);
		}
	}

	/**
	 * Initializes this factory with a source of provider-specific key material.
	 * In some cases, initialization parameters other than a keystore may be
	 * needed by a provider. Users of that particular provider are expected to
	 * pass an implementation of the appropriate ManagerFactoryParameters as
	 * defined by the provider. The provider can then call the specified methods
	 * in the ManagerFactoryParameters implementation to obtain the needed
	 * information.
	 * <p>
	 * This implementation requires X509ProxyCertPathParameters.
	 *
	 * @param managerFactoryParameters
	 *            The X509ProxyCertPathParameters which are used to create
	 *            TrustManagers.
	 * @throws InvalidAlgorithmParameterException
	 *             If the Parameters are invalid
	 */
	@Override
	protected void engineInit(ManagerFactoryParameters managerFactoryParameters)
			throws InvalidAlgorithmParameterException {
		if (managerFactoryParameters instanceof GlobusTrustManagerFactoryParameters) {
			GlobusTrustManagerFactoryParameters ptmfp = (GlobusTrustManagerFactoryParameters) managerFactoryParameters;
			trustManagers.add(new PKITrustManager(
					new X509ProxyCertPathValidator(), ptmfp
							.getCertPathParameters()));
		} else {
			throw new InvalidAlgorithmParameterException(
					"Factory cannot accept parameters of type: "
							+ managerFactoryParameters.getClass()
									.getCanonicalName());
		}
	}

	/**
	 * Returns one trust manager for each type of trust material.
	 *
	 * @return The collection of TrustManagers
	 */
	@Override
	protected TrustManager[] engineGetTrustManagers() {
		return trustManagers.toArray(new TrustManager[trustManagers.size()]);
	}
}
