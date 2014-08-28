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
package org.globus.gsi.testutils.container;

import java.security.Security;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.globus.gsi.jsse.SSLConfigurator;
import org.globus.gsi.provider.GlobusProvider;
import org.globus.gsi.stores.ResourceSigningPolicyStore;
import org.globus.gsi.stores.Stores;
import org.junit.Test;
import static org.junit.Assert.fail;

import javax.net.ssl.SSLPeerUnverifiedException;

public abstract class ClientTest {

	static{
		Security.addProvider(new GlobusProvider());
	}

	public static int getPort() {
		return 5082;
	}

	/**
	 * Test client with invalid credentials.
	 *
	 * @throws Exception
	 *             This should happen.
	 */
	@Test
	public void testInvalid() throws Exception {
		SSLConfigurator config = getConfig("classpath:/invalidkeystore.properties");
		SSLSocketFactory fac = new SSLSocketFactory(config.getSSLContext());
		fac.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
		DefaultHttpClient httpclient = new DefaultHttpClient();
		Scheme scheme = new Scheme("https", fac, getPort());
		httpclient.getConnectionManager().getSchemeRegistry().register(scheme);
		HttpGet httpget = new HttpGet("https://localhost/");
		System.out.println("executing request" + httpget.getRequestLine());
		try {
			httpclient.execute(httpget);
			fail();
		} catch (SSLPeerUnverifiedException ex) {
			// this better happen
		}
	}

	// This creates the client ssl configuration. it uses the default trust
	// store, signing policy store
	// and crl store. Then it applies the users credentials.

	private SSLConfigurator getConfig(String credStoreLocation) throws Exception {
		SSLConfigurator config = new SSLConfigurator();
		config.setCrlLocationPattern(null);
		config.setCrlStoreType(GlobusProvider.CERTSTORE_TYPE);

		config.setCredentialStoreLocation(credStoreLocation);
		config.setCredentialStorePassword("password");
		config.setCredentialStoreType(GlobusProvider.KEYSTORE_TYPE);

		config.setTrustAnchorStoreLocation("classpath:/mytruststore.properties");
		config.setTrustAnchorStorePassword("password");
		config.setTrustAnchorStoreType(GlobusProvider.KEYSTORE_TYPE);

		ResourceSigningPolicyStore policyStore = Stores.getSigningPolicyStore("classpath:/globus_ca.signing_policy");
		config.setPolicyStore(policyStore);
		return config;
	}

	/**
	 * Test a client using valid credentials
	 *
	 * @throws Exception
	 *             if this happens, the test fails.
	 */
	@Test
	public void testValid() throws Exception {
		SSLConfigurator config = getConfig("classpath:/mykeystore.properties");
		SSLSocketFactory fac = new SSLSocketFactory(config.getSSLContext());
		fac.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
		DefaultHttpClient httpclient = new DefaultHttpClient();
		Scheme scheme = new Scheme("https", fac, getPort());
		httpclient.getConnectionManager().getSchemeRegistry().register(scheme);
		HttpGet httpget = new HttpGet("https://localhost/");
		System.out.println("executing request" + httpget.getRequestLine());

		HttpResponse response = httpclient.execute(httpget);
		HttpEntity entity = response.getEntity();
		System.out.println("----------------------------------------");
		System.out.println(response.getStatusLine());
		if (entity != null) {
			System.out.println("Response content length: " + entity.getContentLength());
		}
		if (entity != null) {
			entity.consumeContent();
		}

		// When HttpClient instance is no longer needed,
		// shut down the connection manager to ensure
		// immediate deallocation of all system stores
		httpclient.getConnectionManager().shutdown();
	}
}
