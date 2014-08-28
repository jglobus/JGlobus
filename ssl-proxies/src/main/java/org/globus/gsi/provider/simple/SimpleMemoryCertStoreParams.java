package org.globus.gsi.provider.simple;

import java.security.cert.X509CRL;

import java.security.cert.X509Certificate;

import java.security.cert.CertStoreParameters;

/**
 * @deprecated
 */
public class SimpleMemoryCertStoreParams implements CertStoreParameters {

    private X509Certificate[] certs;
    private X509CRL[] crls;

    public SimpleMemoryCertStoreParams(X509Certificate[] certs, X509CRL[] crls) {
        this.certs = certs;
        this.crls = crls;
    }


    public X509Certificate[] getCerts() {
        return certs;
    }


    public void setCerts(X509Certificate[] certs) {
        this.certs = certs;
    }


    public X509CRL[] getCrls() {
        return crls;
    }


    public void setCrls(X509CRL[] crls) {
        this.crls = crls;
    }


    public Object clone() {
        try {
            return super.clone();
        } catch (CloneNotSupportedException e) {
            throw new InternalError(e.toString());
        }
    }

}
