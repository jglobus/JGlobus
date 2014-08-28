package org.globus.gsi.provider.simple;

import java.security.cert.X509CertSelector;

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertStoreParameters;
import java.security.cert.CRL;
import java.security.cert.CRLSelector;
import java.security.cert.CertSelector;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertStoreSpi;

/**
 * @deprecated
 */
public class SimpleMemoryCertStore extends CertStoreSpi {

    private List<X509CRL> crlStore;
    private List<X509Certificate> certStore;

    public SimpleMemoryCertStore(CertStoreParameters params) throws InvalidAlgorithmParameterException {

        super(params);
        if (params == null) {
            throw new InvalidAlgorithmParameterException();
        }
        crlStore = new LinkedList<X509CRL>();
        certStore = new LinkedList<X509Certificate>();
        if (! (params instanceof SimpleMemoryCertStoreParams)) {
            throw new IllegalArgumentException("wrong parameter type");
        }
        SimpleMemoryCertStoreParams pms = (SimpleMemoryCertStoreParams) params;
        X509Certificate[] certs = pms.getCerts();
        X509CRL[] crls = pms.getCrls();
        if (certs != null) {
            for (X509Certificate cert : certs) {
                if(cert != null) {
                    certStore.add(cert);
                }
            }
        }
        if (crls != null) {
            for (X509CRL crl : crls) {
                if(crl != null) {
                    crlStore.add(crl);
                }
            }
        }
    }


    @Override
    public Collection<? extends CRL> engineGetCRLs(CRLSelector selector) throws CertStoreException {
       List<X509CRL> l = new LinkedList<X509CRL>();
       for (X509CRL crl : crlStore) {
           if (selector.match(crl)) {
               l.add(crl);
           }
       }
       return l;
    }

    @Override
    public Collection<? extends Certificate> engineGetCertificates(CertSelector selector) throws CertStoreException {
        List<X509Certificate> l = new LinkedList<X509Certificate>();
        X509CertSelector select = (X509CertSelector) selector;
        for (X509Certificate cert : certStore) {
            if (selector.match(cert)) {
                l.add(cert);
            }
        }
        return l;
    }

}
