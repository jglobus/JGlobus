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

package org.globus.gsi.tomcat;

import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.jsse.JSSESocketFactory;
import org.globus.gsi.X509ProxyCertPathParameters;
import org.globus.gsi.jsse.GlobusSSLHelper;
import org.globus.gsi.provider.GlobusProvider;
import org.globus.gsi.trustmanager.PKITrustManager;
import org.globus.gsi.trustmanager.X509ProxyCertPathValidator;
import org.globus.gsi.stores.ResourceSigningPolicyStore;
import org.globus.gsi.stores.Stores;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertStore;

/**
 * This extends the standard JSSE to support the globus trust manager and all of the associated properties:
 * CRLs, SigningPolicies, proxy certificates.
 *
 * @version 1.0
 * @since 1.0
 */
public class GlobusSSLSocketFactory extends JSSESocketFactory {

    static {
        Security.addProvider(new GlobusProvider());
    }

    protected Object crlLocation;
    protected Object signingPolicyLocation;
    protected Object rejectLimitedProxyEntry;

    public GlobusSSLSocketFactory(AbstractEndpoint endpoint) {
        super(endpoint);
        crlLocation = endpoint.getAttribute("crlLocation");
        signingPolicyLocation = endpoint.getAttribute("signingPolicyLocation");
        rejectLimitedProxyEntry = endpoint.getAttribute("rejectLimitedProxy");
    }

    /**
     * Create a Globus trust manager which supports proxy certificates.  This requires that the CRL store, and
     * signing policy store be configured.
     *
     * @param keystoreType     The type of keystore to create.
     * @param keystoreProvider The keystore provider to use.
     * @param algorithm        The keystore algorithm.
     * @return A set of configured TrustManagers.
     * @throws Exception If we cannot create the trust managers.
     */
    @Override
    protected TrustManager[] getTrustManagers(String keystoreType, String keystoreProvider, String algorithm)
            throws Exception {
        KeyStore trustStore = getTrustStore(keystoreType, keystoreProvider);

        CertStore crlStore = null;
        if (crlLocation != null) {
            crlStore = GlobusSSLHelper.findCRLStore((String) crlLocation);
        }

        ResourceSigningPolicyStore policyStore = null;
        if (signingPolicyLocation != null) {
            policyStore = Stores.getSigningPolicyStore((String) signingPolicyLocation);
        }

        boolean rejectLimitedProxy = rejectLimitedProxyEntry != null &&
            Boolean.parseBoolean((String) rejectLimitedProxyEntry);

        X509ProxyCertPathParameters parameters = new X509ProxyCertPathParameters(trustStore, crlStore, policyStore,
                rejectLimitedProxy);
        TrustManager trustManager = new PKITrustManager(new X509ProxyCertPathValidator(), parameters);
        return new TrustManager[]{trustManager};
    }


	@Override
	protected Object clone() throws CloneNotSupportedException {
		// TODO Auto-generated method stub
		return super.clone();
	}


	@Override
	public ServerSocket createSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
		return new GlobusSSLSocketWrapper((SSLServerSocket) super.createSocket(port, backlog, ifAddress));
	}


	@Override
	public ServerSocket createSocket(int port, int backlog) throws IOException {
		return createSocket(port, backlog, null);
	}


	@Override
	public ServerSocket createSocket(int port) throws IOException {
		return createSocket(port, 50);
	}
}
