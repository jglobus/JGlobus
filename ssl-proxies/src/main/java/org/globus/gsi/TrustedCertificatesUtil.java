package org.globus.gsi;

import org.globus.gsi.stores.ResourceCertStoreParameters;
import org.globus.gsi.stores.Stores;

import org.globus.gsi.provider.GlobusProvider;

import org.globus.gsi.provider.simple.SimpleMemoryCertStoreParams;
import org.globus.gsi.provider.simple.SimpleMemoryProvider;

import java.security.cert.CertStore;

import org.globus.common.CoGProperties;



import java.security.Security;

/**
 * This is a helper class to create convert TrustCertificates
 * @deprecated
 */
public class TrustedCertificatesUtil {

    static {
        Security.addProvider(new GlobusProvider());
        Security.addProvider(new SimpleMemoryProvider());
    }

    /**
     * Create a CertStore object from TrustedCertificates.
     * The store only loads  trusted certificates, no signing policies
     */
    public static CertStore createCertStore(TrustedCertificates tc) throws Exception {

        CertStore store = null;
        if (tc == null) {
            String caCertPattern = "file:" + CoGProperties.getDefault().getCaCertLocations() + "/*.0";
            store = Stores.getCACertStore(caCertPattern);
        } else {
            SimpleMemoryCertStoreParams params = new SimpleMemoryCertStoreParams(tc.getCertificates(), null);
            params.setCerts(tc.getCertificates());
            store = CertStore.getInstance(SimpleMemoryProvider.CERTSTORE_TYPE, params, SimpleMemoryProvider.PROVIDER_NAME);
        }
        return store;
    }
}
