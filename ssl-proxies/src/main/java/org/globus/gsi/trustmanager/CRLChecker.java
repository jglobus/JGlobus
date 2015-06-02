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

import org.globus.gsi.util.KeyStoreUtil;
import org.globus.gsi.CertificateRevocationLists;

import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.globus.gsi.GSIConstants;

/**
 * This checks to see if the certificate is in a CRL.
 *
 * @version ${version}
 * @since 1.0
 */
public class CRLChecker implements CertificateChecker {
    private CertificateRevocationLists crlsList;
    private CertStore certStore;
    private KeyStore keyStore;
    private boolean checkDateValidity;

    /**
     * Creates a CRLChecker where the CRL's are in the supplied stores.
     *
     * @param crlsList          The object containing the CRL's
     * @param keyStore          The store used to get trusted certs.
     * @param checkDateValidity Should we check if the CRL date is valid.
     */
    public CRLChecker(CertificateRevocationLists crlsList, KeyStore keyStore, boolean checkDateValidity) {
        this.crlsList = crlsList;
        this.certStore = null;
        this.keyStore = keyStore;
        this.checkDateValidity = checkDateValidity;
    }

    /**
     * Creates a CRLChecker where the CRL's are in the supplied stores.
     *
     * @param certStore         The store containing the CRL's
     * @param keyStore          The store used to get trusted certs.
     * @param checkDateValidity Should we check if the CRL date is valid.
     */
    public CRLChecker(CertStore certStore, KeyStore keyStore, boolean checkDateValidity) {
        this.crlsList = null;
        this.certStore = certStore;
        this.keyStore = keyStore;
        this.checkDateValidity = checkDateValidity;
    }

    /**
     * Method that checks the if the certificate is in a CRL, if CRL is
     * available If no CRL is found, then no error is thrown If an expired CRL
     * is found, an error is thrown
     *
     * @throws CertPathValidatorException If CRL or CA certificate could not be
     *                                    loaded from store, CRL is not valid or
     *                                    expired, certificate is revoked.
     */
    public void invoke(X509Certificate cert, GSIConstants.CertificateType certType) throws CertPathValidatorException {
        X500Principal certIssuer = cert.getIssuerX500Principal();

        X509CRLSelector crlSelector = new X509CRLSelector();
        crlSelector.addIssuer(certIssuer);

        Collection<? extends CRL> crls;
        if (crlsList != null) {
            crls = crlsList.getCRLs(crlSelector);
        } else {
            try {
                crls = this.certStore.getCRLs(crlSelector);
            } catch (CertStoreException e) {
                throw new CertPathValidatorException(
                    "Error accessing CRL from certificate store: " + e.getMessage(), e);
            }
        }

        if (crls.size() < 1) {
            return;
        }

        // Get CA certificate for these CRLs
        X509CertSelector certSelector = new X509CertSelector();
        certSelector.setSubject(certIssuer);
        Collection<? extends Certificate> caCerts;
        try {
            caCerts = KeyStoreUtil
                    .getTrustedCertificates(this.keyStore, certSelector);
        } catch (KeyStoreException e) {
            throw new CertPathValidatorException(
                    "Error accessing CA certificate from certificate store for CRL validation",
                    e);
        }

        if (caCerts.size() < 1) {

            // if there is no trusted certs from that CA, then
            // the chain cannot contain a cert from that CA,
            // which implies not checking this CRL should be fine.
            return;
        }
        Certificate caCert = caCerts.iterator().next();

        for (CRL o : crls) {

            X509CRL crl = (X509CRL) o;

            // if expired, will throw error.
            if (checkDateValidity) {
                checkCRLDateValidity(crl);
            }

            // validate CRL
            verifyCRL(caCert, crl);

            if (crl.isRevoked(cert)) {
                throw new CertPathValidatorException(
                    "Certificate " + cert.getSubjectDN() + " has been revoked");
            }
        }
    }

    private void verifyCRL(Certificate caCert, X509CRL crl) throws CertPathValidatorException {
        try {
            crl.verify(caCert.getPublicKey());
        } catch (CRLException e) {
            throw new CertPathValidatorException(
                    "Error validating CRL from CA " + crl.getIssuerDN(), e);
        } catch (NoSuchAlgorithmException e) {
            throw new CertPathValidatorException(
                    "Error validating CRL from CA " + crl.getIssuerDN(), e);
        } catch (InvalidKeyException e) {
            throw new CertPathValidatorException(
                    "Error validating CRL from CA " + crl.getIssuerDN(), e);
        } catch (NoSuchProviderException e) {
            throw new CertPathValidatorException(
                    "Error validating CRL from CA " + crl.getIssuerDN(), e);
        } catch (SignatureException e) {
            throw new CertPathValidatorException(
                    "Error validating CRL from CA " + crl.getIssuerDN(), e);
        }
    }

    /*
     * Method to check the CRL validity for current time.
     *
     * @param crl
     * @throws CertPathValidatorException
     */

    protected void checkCRLDateValidity(X509CRL crl)
            throws CertPathValidatorException {

        Date now = new Date();
        boolean valid = crl.getThisUpdate().before(now) && ((crl.getNextUpdate() != null)
                && (crl.getNextUpdate().after(now)));
        if (!valid) {
            throw new CertPathValidatorException("CRL issued by " + crl.getIssuerDN() + " has expired");
        }
    }

}
