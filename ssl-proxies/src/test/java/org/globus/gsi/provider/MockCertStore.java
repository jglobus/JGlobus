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
package org.globus.gsi.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CRL;
import java.security.cert.CRLSelector;
import java.security.cert.CertSelector;
import java.security.cert.CertStoreException;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertStoreSpi;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Vector;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class MockCertStore extends CertStoreSpi {

    private Vector<X509Certificate> certificate = new Vector();
    private Vector<X509CRL> crl = new Vector();

    public MockCertStore(CertStoreParameters param)
            throws InvalidAlgorithmParameterException {
        super(param);

        if (param != null) {
            if (param instanceof TestProxyPathValidator.TestCertParameters) {
                TestProxyPathValidator.TestCertParameters parameters
                        = (TestProxyPathValidator.TestCertParameters) param;
                X509Certificate[] certs = parameters.getCertificates();
                if (certs != null) {

                    for (int i = 0; i < certs.length; i++) {
                        this.certificate.add(certs[i]);
                    }
                }
                X509CRL[] crls = parameters.getCRLs();
                if (crls != null) {
                    for (int i = 0; i < crls.length; i++) {
                        this.crl.add(crls[i]);
                    }
                }
            }
        }
    }

    /**
     * Returns a <code>Collection</code> of <code>Certificate</code>s that match
     * the specified selector. If no <code>Certificate</code>s match the
     * selector, an empty <code>Collection</code> will be returned.
     * <p>
     * For some <code>CertStore</code> types, the resulting
     * <code>Collection</code> may not contain <b>all</b> of the
     * <code>Certificate</code>s that match the selector. For instance, an LDAP
     * <code>CertStore</code> may not search all entries in the directory.
     * Instead, it may just search entries that are likely to contain the
     * <code>Certificate</code>s it is looking for.
     * <p>
     * Some <code>CertStore</code> implementations (especially LDAP
     * <code>CertStore</code>s) may throw a <code>CertStoreException</code>
     * unless a non-null <code>CertSelector</code> is provided that includes
     * specific criteria that can be used to find the certificates. Issuer
     * and/or subject names are especially useful criteria.
     *
     * @param selector A <code>CertSelector</code> used to select which
     *                 <code>Certificate</code>s should be returned. Specify
     *                 <code>null</code> to return all <code>Certificate</code>s
     *                 (if supported).
     * @return A <code>Collection</code> of <code>Certificate</code>s that match
     *         the specified selector (never <code>null</code>)
     * @throws java.security.cert.CertStoreException
     *          if an exception occurs
     */
    public Collection<? extends Certificate> engineGetCertificates(
            CertSelector selector) throws CertStoreException {

        // For test, unsupported
        throw new UnsupportedOperationException();
    }

    /**
     * Returns a <code>Collection</code> of <code>CRL</code>s that match the
     * specified selector. If no <code>CRL</code>s match the selector, an empty
     * <code>Collection</code> will be returned.
     * <p>
     * For some <code>CertStore</code> types, the resulting
     * <code>Collection</code> may not contain <b>all</b> of the
     * <code>CRL</code>s that match the selector. For instance, an LDAP
     * <code>CertStore</code> may not search all entries in the directory.
     * Instead, it may just search entries that are likely to contain the
     * <code>CRL</code>s it is looking for.
     * <p>
     * Some <code>CertStore</code> implementations (especially LDAP
     * <code>CertStore</code>s) may throw a <code>CertStoreException</code>
     * unless a non-null <code>CRLSelector</code> is provided that includes
     * specific criteria that can be used to find the CRLs. Issuer names and/or
     * the certificate to be checked are especially useful.
     *
     * @param selector A <code>CRLSelector</code> used to select which
     *                 <code>CRL</code>s should be returned. Specify
     *                 <code>null</code> to return all <code>CRL</code>s (if
     *                 supported).
     * @return A <code>Collection</code> of <code>CRL</code>s that match the
     *         specified selector (never <code>null</code>)
     * @throws java.security.cert.CertStoreException
     *          if an exception occurs
     */
    public Collection<? extends CRL> engineGetCRLs(CRLSelector selector)
            throws CertStoreException {

        if (selector == null) {
            return this.crl;
        }

        List<X509CRL> crlList = new Vector<X509CRL>();
        for (X509CRL aCrl : this.crl) {
            if (selector.match(aCrl)) {
                crlList.add(aCrl);
            }
        }
        return crlList;
    }
}