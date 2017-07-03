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

package org.globus.gsi.trustmanager;

import org.globus.gsi.util.CertificateUtil;
import org.globus.gsi.util.KeyStoreUtil;

import java.util.Iterator;

import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Jan 20, 2010
 * Time: 4:51:38 PM
 * To change this template use File | Settings | File Templates.
 */
public final class TrustedCertPathFinder {
    private static Log logger = LogFactory.getLog(TrustedCertPathFinder.class.getCanonicalName());

    private TrustedCertPathFinder() {
        //this should not be instantiated.
    }

    private static CertPath isTrustedCert(KeyStore keyStore, X509Certificate x509Certificate, List<X509Certificate> trustedCertPath) throws CertPathValidatorException {
        X509CertSelector certSelector = new X509CertSelector();
        certSelector.setCertificate(x509Certificate);
        Collection<? extends Certificate> caCerts;
        try {
            caCerts = KeyStoreUtil.getTrustedCertificates(keyStore, certSelector);
        } catch (KeyStoreException e) {
            throw new CertPathValidatorException(
                    "Error accessing trusted certificate store", e);
        }
        if ((caCerts.size() > 0)&&(x509Certificate.getBasicConstraints() != -1)) {

            trustedCertPath.add(x509Certificate);
            // JGLOBUS-92
            try {
                CertificateFactory certFac = CertificateFactory.getInstance("X.509");
                return certFac.generateCertPath(trustedCertPath);
            } catch (CertificateException e) {
                throw new CertPathValidatorException(
                        "Error generating trusted certificate path", e);
            }
        }
        return null;
    }

    /**
     * Method that validates the provided cert path to find a trusted certificate in the certificate store.
     * <p>
     * For each certificate i in certPath, it is expected that the i+1 certificate is the issuer of the certificate
     * path. See CertPath.
     * <p>
     * For each certificate i in certpath, validate signature of certificate i get issuer of certificate i get
     * certificate i+i ensure that the certificate i+1 is issuer of certificate i If not, throw an exception for
     * illegal argument validate signature of i+1 Throw exception if it does not validate check if i+1 is a trusted
     * certificate in the trust store. If so return certpath until i+1 If not, continue; If all certificates in the
     * certpath have been checked and none exisits in trust store, check if trust store has certificate of issuer of
     * last certificate in CertPath. If so, return certPath + trusted certificate from trust store If not, throw
     * an exception for lack of valid trust root.
     *
     * @param keyStore The key store containing CA trust root certificates
     * @param certPath The certpath from which to extract a valid cert path to a trusted certificate.
     * @return The valid CertPath.
     * @throws CertPathValidatorException If the CertPath is invalid.
     */
    public static CertPath findTrustedCertPath(KeyStore keyStore, CertPath certPath) throws CertPathValidatorException {

        // This will be the cert path to return
        List<X509Certificate> trustedCertPath = new ArrayList<X509Certificate>();
        // This is the certs to validate
        List<? extends Certificate> certs = certPath.getCertificates();

        X509Certificate x509Certificate;
        int index = 0;
        int certsSize = certs.size();

        Certificate certificate = certs.get(index);
        if (!(certificate instanceof X509Certificate)) {
            throw new CertPathValidatorException("Certificate of type " + X509Certificate.class.getName() + " required");
        }
        x509Certificate = (X509Certificate) certificate;

        while (index < certsSize) {
            CertPath finalCertPath = isTrustedCert(keyStore, x509Certificate, trustedCertPath);
            if (finalCertPath != null) {
                return finalCertPath;
            }

            if (index + 1 >= certsSize) {
                break;
            }

            index++;
            Certificate issuerCertificate = certs.get(index);
            x509Certificate = checkCertificate(trustedCertPath, x509Certificate, issuerCertificate);
        }

        X509CertSelector selector = new X509CertSelector();
        selector.setSubject(x509Certificate.getIssuerX500Principal());
        Collection<? extends Certificate> caCerts;
        try {
            caCerts = KeyStoreUtil.getTrustedCertificates(keyStore, selector);
        } catch (KeyStoreException e) {
            throw new CertPathValidatorException(e);
        }
        if (caCerts.size() < 1) {
            throw new CertPathValidatorException("No trusted path can be constructed");
        }

        boolean foundTrustRoot = false;

        for (Certificate caCert : caCerts) {
            if (! (caCert instanceof X509Certificate)) {
                logger.warn("Skipped a certificate: not an X509Certificate");
                continue;
            }
            try {
                trustedCertPath.add(checkCertificate(trustedCertPath,
                        x509Certificate, caCert));
                // currently the caCert self-signature is not checked
                // to be consistent with the isTrustedCert() method
                foundTrustRoot = true;
                // we found a CA cert that signed the certificate
                // so we don't need to check any more
                break;
            } catch (CertPathValidatorException e) {
                // fine, just move on to check the next potential CA cert
                // after the loop we'll check whether any were successful
                logger.warn("Failed to validate signature of certificate with "
                          + "subject DN '" + x509Certificate.getSubjectDN()
                          + "' against a CA certificate with issuer DN '"
                          + ((X509Certificate)caCert).getSubjectDN() + "'");
            }
        }

        if (! foundTrustRoot) {
            throw new CertPathValidatorException(
                    "No trusted path can be constructed");
        }

        try {
            CertificateFactory certFac = CertificateFactory.getInstance("X.509");
            return certFac.generateCertPath(trustedCertPath);
        } catch (CertificateException e) {
            throw new CertPathValidatorException("Error generating trusted certificate path", e);
        }
    }

    private static X509Certificate checkCertificate(List<X509Certificate> trustedCertPath,
                                                    X509Certificate x509Certificate, Certificate issuerCertificate)
            throws CertPathValidatorException {
        X509Certificate x509IssuerCertificate = (X509Certificate) issuerCertificate;

        // check that the next one is indeed issuer, normalizing to Globus DN format
        String issuerDN = CertificateUtil.toGlobusID(
                x509Certificate.getIssuerX500Principal());
        String issuerCertDN = CertificateUtil.toGlobusID(
                x509IssuerCertificate.getSubjectX500Principal());

        if (!(issuerDN.equals(issuerCertDN))) {
            throw new IllegalArgumentException("Incorrect certificate path, certificate in chain can only "
                    + "be issuer of previous certificate");
        }

        // validate integrity of signature
        PublicKey publicKey = x509IssuerCertificate.getPublicKey();
        try {
            x509Certificate.verify(publicKey);
        } catch (CertificateException e) {
            throw new CertPathValidatorException(
                    "Signature validation on the certificate " + x509Certificate.getSubjectDN(), e);
        } catch (NoSuchAlgorithmException e) {
            throw new CertPathValidatorException(
                    "Signature validation on the certificate " + x509Certificate.getSubjectDN(), e);
        } catch (InvalidKeyException e) {
            throw new CertPathValidatorException(
                    "Signature validation on the certificate " + x509Certificate.getSubjectDN(), e);
        } catch (NoSuchProviderException e) {
            throw new CertPathValidatorException(
                    "Signature validation on the certificate " + x509Certificate.getSubjectDN(), e);
        } catch (SignatureException e) {
            throw new CertPathValidatorException(
                    "Signature validation on the certificate " + x509Certificate.getSubjectDN(), e);
        }

        trustedCertPath.add(x509Certificate);
        return x509IssuerCertificate;
    }
}
