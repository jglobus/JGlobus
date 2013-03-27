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
package org.globus.gsi.util;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Vector;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public final class KeyStoreUtil {

    private KeyStoreUtil() {
        //Should not be constructed
    }

    /**
     * Returns the list of certificates in the KeyStore. Return object will not
     * be null.
     *
     * @param keyStore
     * @param selector
     * @return the list of certificates in the KeyStore
     * @throws KeyStoreException
     */
    public static Collection<? extends Certificate> getTrustedCertificates(KeyStore keyStore, X509CertSelector selector)
            throws KeyStoreException {

        Vector<X509Certificate> certificates = new Vector<X509Certificate>();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isCertificateEntry(alias)) {
                // If a specific impl of keystore requires refresh, this would be a
                // good place to add it.
                Certificate certificate = keyStore.getCertificate(alias);
                if (certificate instanceof X509Certificate) {
                    X509Certificate x509Cert = (X509Certificate) certificate;
                    if (selector.match(certificate)) {
                        certificates.add(x509Cert);
                    }
                }
            }
        }
        return certificates;
    }

}
