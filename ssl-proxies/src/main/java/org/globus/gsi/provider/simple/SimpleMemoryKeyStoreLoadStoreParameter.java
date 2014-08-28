package org.globus.gsi.provider.simple;

import java.security.cert.X509Certificate;

import java.security.KeyStore.ProtectionParameter;

import java.security.KeyStore.LoadStoreParameter;

/**
 * @deprecated
 */
public class SimpleMemoryKeyStoreLoadStoreParameter implements LoadStoreParameter {

    private X509Certificate[] certs;

    public X509Certificate[] getCerts() {
        return certs;
    }

    public void setCerts(X509Certificate[] certs) {
        this.certs = certs;
    }

    public ProtectionParameter getProtectionParameter() {
        return null;
    }

}
