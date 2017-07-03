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
package org.globus.gsi;

import org.globus.gsi.provider.SigningPolicyStore;

import java.security.KeyStore;
import java.security.cert.CertPathParameters;
import java.security.cert.CertStore;
import java.util.Map;
import org.globus.gsi.proxy.ProxyPolicyHandler;

/**
 * Refactor to have an interface that retuns trusted certificates, crls,
 * keys and policy. Manage stores within parameters. PKITrustManager can take
 * that interface and the validator can also be agnostic of this implementation
 * (can support say CertStore or KeyStore for trsuted certs).
 *
 * @author ranantha@mcs.anl.gov
 */
public class X509ProxyCertPathParameters implements CertPathParameters {

    // For trusted CAs
    private KeyStore trustStore;
    // For CRLs
    private CertStore crlStore;
    // For signing policy
    private SigningPolicyStore policyStore;
    private boolean rejectLimitedProxy;
    private Map<String, ProxyPolicyHandler> handlers;

    public X509ProxyCertPathParameters(KeyStore initTrustStore, CertStore initCRLStore,
                                       SigningPolicyStore initPolicyStore, boolean initRejectLimitedProxy) {
        this(initTrustStore, initCRLStore, initPolicyStore, initRejectLimitedProxy, null);
    }


    public X509ProxyCertPathParameters(KeyStore initTrustStore, CertStore initCRLStore,
                                       SigningPolicyStore initPolicyStore, boolean initRejectLimitedProxy,
                                       Map<String, ProxyPolicyHandler> initHandlers) {

        if ((initTrustStore == null) || (initCRLStore == null) || (initPolicyStore == null)) {
            throw new IllegalArgumentException();
        }
        this.trustStore = initTrustStore;
        this.crlStore = initCRLStore;
        this.policyStore = initPolicyStore;
        this.rejectLimitedProxy = initRejectLimitedProxy;
        this.handlers = initHandlers;
    }

    public KeyStore getTrustStore() {
        return this.trustStore;
    }

    public CertStore getCrlStore() {
        return this.crlStore;
    }

    public SigningPolicyStore getSigningPolicyStore() {
        return this.policyStore;
    }

    public boolean isRejectLimitedProxy() {
        return this.rejectLimitedProxy;
    }

    public Map<String, ProxyPolicyHandler> getPolicyHandlers() {
        return this.handlers;
    }

    /**
     * Makes a copy of this <code>CertPathParameters</code>. Changes to the copy
     * will not affect the original and vice versa.
     *
     * @return a copy of this <code>CertPathParameters</code>
     */
    public Object clone() {
        try {
            return super.clone();
        } catch (CloneNotSupportedException e) {
            throw new InternalError(e.toString());
        }
    }
}
