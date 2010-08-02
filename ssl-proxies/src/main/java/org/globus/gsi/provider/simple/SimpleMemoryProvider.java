package org.globus.gsi.provider.simple;

import java.security.PrivilegedAction;

import java.security.AccessController;

import java.security.Provider;

/**
 * @deprecated
 */
public final class SimpleMemoryProvider extends Provider {

    public static final String PROVIDER_NAME = "Simple";
    public static final String CERTSTORE_TYPE = "SimpleMemoryCertStore";
    public static final String KEYSTORE_TYPE = "SimpleMemoryKeyStore";
    private static final long serialVersionUID = -6275241207604782364L;

    /**
     * Create Provider and add Components to the java security framework.
     */
    public SimpleMemoryProvider() {

        super(PROVIDER_NAME, 1.0, "Simple Memory Security Provider");
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            public Object run() {
                put("CertStore.SimpleMemoryCertStore", SimpleMemoryCertStore.class.getName());
                put("KeyStore.SimpleMemoryKeyStore", SimpleMemoryKeyStore.class.getName());
                return null;
            }
        });

    }
}
