package org.globus.gsi.provider;

import org.globus.gsi.X509ProxyCertPathParameters;

import java.security.KeyStore;
import java.security.cert.CertStore;
import java.util.Map;

import javax.net.ssl.ManagerFactoryParameters;

import org.globus.gsi.proxy.ProxyPolicyHandler;

public class GlobusTrustManagerFactoryParameters implements
		ManagerFactoryParameters {

	private KeyStore initTrustStore;
	private CertStore initCRLStore;
	private SigningPolicyStore initPolicyStore;
	private boolean initRejectLimitedProxy;
	private Map<String, ProxyPolicyHandler> handlers;

	public GlobusTrustManagerFactoryParameters(KeyStore initTrustStore,
			CertStore initCRLStore, SigningPolicyStore initPolicyStore,
			boolean initRejectLimitedProxy) {
		this.initTrustStore = initTrustStore;
		this.initCRLStore = initCRLStore;
		this.initPolicyStore = initPolicyStore;
		this.initRejectLimitedProxy = initRejectLimitedProxy;
	}

	public GlobusTrustManagerFactoryParameters(KeyStore initTrustStore,
			CertStore initCRLStore, SigningPolicyStore initPolicyStore,
			boolean initRejectLimitedProxy,
			Map<String, ProxyPolicyHandler> handlers) {
		super();
		this.initTrustStore = initTrustStore;
		this.initCRLStore = initCRLStore;
		this.initPolicyStore = initPolicyStore;
		this.initRejectLimitedProxy = initRejectLimitedProxy;
		this.handlers = handlers;
	}

	public X509ProxyCertPathParameters getCertPathParameters() {
		if (this.handlers == null) {
			return new X509ProxyCertPathParameters(this.initTrustStore,
					this.initCRLStore, this.initPolicyStore,
					this.initRejectLimitedProxy);
		} else {
			return new X509ProxyCertPathParameters(this.initTrustStore,
					this.initCRLStore, this.initPolicyStore,
					this.initRejectLimitedProxy, this.handlers);
		}
	}

}
