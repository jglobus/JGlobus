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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.globus.gsi.GSIConstants;
import org.globus.gsi.X509ProxyCertPathParameters;
import org.globus.gsi.X509ProxyCertPathValidatorResult;
import org.globus.gsi.CertificateRevocationLists;

import org.globus.gsi.provider.SigningPolicyStore;
import org.globus.gsi.proxy.ProxyPolicyHandler;
import org.globus.gsi.proxy.ext.ProxyCertInfo;
import org.globus.gsi.proxy.ext.ProxyPolicy;
import org.globus.gsi.util.CertificateUtil;
import org.globus.gsi.util.KeyUsage;
import org.globus.gsi.util.ProxyCertificateUtil;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

/**
 * Implementation of the CertPathValidatorSpi and the logic for X.509 Proxy Path Validation.
 *
 * @version ${version}
 * @since 1.0
 */
public class X509ProxyCertPathValidator extends CertPathValidatorSpi {

    public static final String BASIC_CONSTRAINT_OID = "2.5.29.19";
    public static final String KEY_USAGE_OID = "2.5.29.15";

    protected KeyStore keyStore;
    protected CertStore certStore;
    protected SigningPolicyStore policyStore;

    private X509Certificate identityCert;
    private boolean limited;
    private boolean rejectLimitedProxy;
    private Map<String, ProxyPolicyHandler> policyHandlers;

    /**
     * Validates the specified certification path using the specified algorithm parameter set.
     * <p>
     * The <code>CertPath</code> specified must be of a type that is supported by the validation algorithm, otherwise
     * an <code>InvalidAlgorithmParameterException</code> will be thrown. For example, a <code>CertPathValidator</code>
     * that implements the PKIX algorithm validates <code>CertPath</code> objects of type X.509.
     *
     * @param certPath the <code>CertPath</code> to be validated
     * @param params   the algorithm parameters
     * @return the result of the validation algorithm
     * @throws java.security.cert.CertPathValidatorException
     *          if the <code>CertPath</code> does not validate
     * @throws java.security.InvalidAlgorithmParameterException
     *          if the specified parameters or the type of the
     *          specified <code>CertPath</code> are inappropriate for this <code>CertPathValidator</code>
     */
    @SuppressWarnings("unchecked")
        public CertPathValidatorResult engineValidate(CertPath certPath, CertPathParameters params)
            throws CertPathValidatorException, InvalidAlgorithmParameterException {

        if (certPath == null) {
            throw new IllegalArgumentException(
                    "Certificate path cannot be null");
        }

                List list = certPath.getCertificates();
        if (list.size() < 1) {
            throw new IllegalArgumentException(
                    "Certificate path cannot be empty");
        }

        parseParameters(params);

        // find the root trust anchor. Validate signatures and see if the
        // chain ends in one of the trust root certificates
        CertPath trustedCertPath = TrustedCertPathFinder.findTrustedCertPath(this.keyStore, certPath);

        // rest of the validation
        return validate(trustedCertPath);
    }

    /**
     * Dispose of the current validation state.
     */
    public void clear() {
        this.identityCert = null;
        this.limited = false;
    }

    protected void parseParameters(CertPathParameters params) throws InvalidAlgorithmParameterException {

        if (!(params instanceof X509ProxyCertPathParameters)) {
            throw new IllegalArgumentException("Parameter of type " + X509ProxyCertPathParameters.class.getName()
                    + " required");
        }
        X509ProxyCertPathParameters parameters = (X509ProxyCertPathParameters) params;
        this.keyStore = parameters.getTrustStore();
        this.certStore = parameters.getCrlStore();
        this.policyStore = parameters.getSigningPolicyStore();
        this.rejectLimitedProxy = parameters.isRejectLimitedProxy();
        this.policyHandlers = parameters.getPolicyHandlers();
    }

    /**
     * Validates the certificate path and does the following for each certificate in the chain: method
     * checkCertificate() In addition: a) Validates if the issuer type of each certificate is correct b) CA path
     * constraints c) Proxy path constraints
     * <p>
     * If it is of type proxy, check following: a) proxy constraints b) restricted proxy else if certificate, check the
     * following: a) keyisage
     *
     * @param certPath The CertPath to validate.
     * @return The results of the validation.
     * @throws CertPathValidatorException If the CertPath is invalid.
     */
    protected CertPathValidatorResult validate(CertPath certPath) throws CertPathValidatorException {

        List<? extends Certificate> certificates = certPath.getCertificates();
        if (certificates.size() == 0) {
            return null;
        }

        X509Certificate cert;
        TBSCertificateStructure tbsCert;
        GSIConstants.CertificateType certType;

        X509Certificate issuerCert;
        TBSCertificateStructure issuerTbsCert;
        GSIConstants.CertificateType issuerCertType;

        int proxyDepth = 0;

        cert = (X509Certificate) certificates.get(0);

        try {
            tbsCert = getTBSCertificateStructure(cert);

            certType = getCertificateType(tbsCert);
            // validate the first certificate in chain
            checkCertificate(cert, certType);

            boolean isProxy = ProxyCertificateUtil.isProxy(certType);
            if (isProxy) {
                proxyDepth++;
            }
        } catch (CertPathValidatorException e) {
            throw new CertPathValidatorException("Path validation failed for " + cert.getSubjectDN() + ": " + e.getMessage(),
                    e, certPath, 0);
        }


        for (int i = 1; i < certificates.size(); i++) {
            boolean certIsProxy = ProxyCertificateUtil.isProxy(certType);
            issuerCert = (X509Certificate) certificates.get(i);
            issuerTbsCert = getTBSCertificateStructure(issuerCert);

            issuerCertType = getCertificateType(issuerTbsCert);

            proxyDepth = validateCert(cert, certType, issuerCert, issuerTbsCert, issuerCertType, proxyDepth, i,
                    certIsProxy);

            if (certIsProxy) {
                try {
                    checkProxyConstraints(certPath, cert, tbsCert, certType, issuerTbsCert, i);
                } catch (CertPathValidatorException e) {
                    throw new CertPathValidatorException("Path validation failed for " + cert.getSubjectDN() + ": " + e.getMessage(),
                            e, certPath, i - 1);
                }
            } else {
                try {
                    checkKeyUsage(issuerTbsCert);
                } catch (IOException e) {
                    throw new CertPathValidatorException("Key usage check failed on " + issuerCert.getSubjectDN() + ": " + e.getMessage(),
                            e, certPath, i);
                } catch (CertPathValidatorException e) {
                    throw new CertPathValidatorException("Path validation failed for " + issuerCert.getSubjectDN() + ": " + e.getMessage(),
                            e, certPath, i);
                }
            }

            try {
                checkCertificate(issuerCert, issuerCertType);
            } catch (CertPathValidatorException e) {
                throw new CertPathValidatorException("Path validation failed for " + issuerCert.getSubjectDN() + ": " + e.getMessage(),
                        e, certPath, i);
            }

            cert = issuerCert;
            certType = issuerCertType;
            tbsCert = issuerTbsCert;
        }

        return new X509ProxyCertPathValidatorResult(this.identityCert,
                this.limited);

    }

    private GSIConstants.CertificateType getCertificateType(TBSCertificateStructure issuerTbsCert) throws CertPathValidatorException {
        GSIConstants.CertificateType issuerCertType;
        try {

            issuerCertType = CertificateUtil.getCertificateType(issuerTbsCert);
        } catch (CertificateException e) {
            throw new CertPathValidatorException(
                    "Error obtaining certificate type", e);
        } catch (IOException e) {
            throw new CertPathValidatorException(
                    "Error obtaining certificate type", e);
        }
        return issuerCertType;
    }

    private TBSCertificateStructure getTBSCertificateStructure(X509Certificate issuerCert) throws CertPathValidatorException {
        TBSCertificateStructure issuerTbsCert;
        try {
            issuerTbsCert = CertificateUtil.getTBSCertificateStructure(issuerCert);
        } catch (CertificateException e) {
            throw new CertPathValidatorException("Error converting certificate", e);
        } catch (IOException e) {
            throw new CertPathValidatorException("Error converting certificate", e);
        }
        return issuerTbsCert;
    }

    private int validateCert(X509Certificate cert, GSIConstants.CertificateType certType, X509Certificate issuerCert,
                             TBSCertificateStructure issuerTbsCert, GSIConstants.CertificateType issuerCertType,
                             int proxyDepth, int i, boolean certIsProxy) throws CertPathValidatorException {
        if (issuerCertType == GSIConstants.CertificateType.CA) {
            validateCACert(cert, issuerCert, issuerTbsCert, proxyDepth, i, certIsProxy);
        } else if (ProxyCertificateUtil.isGsi3Proxy(issuerCertType)
                || ProxyCertificateUtil.isGsi4Proxy(issuerCertType)) {
            return validateGsiProxyCert(cert, certType, issuerCert, issuerTbsCert,
                    issuerCertType, proxyDepth);
        } else if (ProxyCertificateUtil.isGsi2Proxy(issuerCertType)) {
            return validateGsi2ProxyCert(cert, certType, issuerCert, proxyDepth);
        } else if (issuerCertType == GSIConstants.CertificateType.EEC) {
            validateEECCert(cert, certType, issuerCert);
        } else {
            // this should never happen?
            throw new CertPathValidatorException("UNknown issuer type " + issuerCertType
                    + " for certificate " + issuerCert.getSubjectDN());
        }
        return proxyDepth;
    }

    private void checkProxyConstraints(CertPath certPath, X509Certificate cert,
                                       TBSCertificateStructure tbsCert, GSIConstants.CertificateType certType,
                                       TBSCertificateStructure issuerTbsCert, int i)
            throws CertPathValidatorException {

        // check all the proxy & issuer constraints
        if (ProxyCertificateUtil.isGsi3Proxy(certType)
                || ProxyCertificateUtil.isGsi4Proxy(certType)) {
            try {
                checkProxyConstraints(tbsCert, issuerTbsCert, cert);
            } catch (IOException e) {
                throw new CertPathValidatorException("Proxy constraint check failed on " + cert.getSubjectDN(), e);
            }
            if ((certType == GSIConstants.CertificateType.GSI_3_RESTRICTED_PROXY)
                    || (certType == GSIConstants.CertificateType.GSI_4_RESTRICTED_PROXY)) {
                try {
                    checkRestrictedProxy(tbsCert, certPath, i);
                } catch (IOException e) {
                    throw new CertPathValidatorException("Restricted proxy check failed on " + cert.getSubjectDN(), e);
                }
            }
        }
    }

    private void validateEECCert(X509Certificate cert, GSIConstants.CertificateType certType,
                                 X509Certificate issuerCert) throws CertPathValidatorException {
        if (!ProxyCertificateUtil.isProxy(certType)) {
            throw new CertPathValidatorException("EEC can only sign another proxy certificate. Violated by "
                    + issuerCert.getSubjectDN() + " issuing " + cert.getSubjectDN());
        }
    }


    private int validateGsi2ProxyCert(X509Certificate cert, GSIConstants.CertificateType certType,
                                      X509Certificate issuerCert, int proxyDepth) throws CertPathValidatorException {
        // PC can sign EEC or another PC only
        if (!ProxyCertificateUtil.isGsi2Proxy(certType)) {
            throw new CertPathValidatorException(
                    "Proxy certificate can only sign another proxy certificate of same type. Violated by "
                            + issuerCert.getSubjectDN() + " issuing " + cert.getSubjectDN());
        }
        return proxyDepth + 1;
    }

    private int validateGsiProxyCert(X509Certificate cert, GSIConstants.CertificateType certType,
                                     X509Certificate issuerCert, TBSCertificateStructure issuerTbsCert,
                                     GSIConstants.CertificateType issuerCertType, int proxyDepth)
            throws CertPathValidatorException {
        if (ProxyCertificateUtil.isGsi3Proxy(issuerCertType)) {
            if (!ProxyCertificateUtil.isGsi3Proxy(certType)) {
                throw new CertPathValidatorException(
                        "Proxy certificate can only sign another proxy certificate of same type. Violated by "
                                + issuerCert.getSubjectDN() + " issuing " + cert.getSubjectDN());
            }
        } else if (ProxyCertificateUtil.isGsi4Proxy(issuerCertType) && !ProxyCertificateUtil.isGsi4Proxy(certType)) {
            throw new CertPathValidatorException(
                    "Proxy certificate can only sign another proxy certificate of same type. Violated by "
                            + issuerCert.getSubjectDN() + " issuing " + cert.getSubjectDN());
        }
        int pathLen;
        try {
            pathLen = ProxyCertificateUtil.getProxyPathConstraint(issuerTbsCert);
        } catch (IOException e) {
            throw new CertPathValidatorException("Error obtaining proxy path constraint", e);
        }
        if (pathLen == 0) {
            throw new CertPathValidatorException(
                    "Proxy path length constraint violated of certificate " + issuerCert.getSubjectDN());
        }
        if (pathLen < Integer.MAX_VALUE
                && proxyDepth > pathLen) {
            throw new CertPathValidatorException(
                    "Proxy path length constraint violated of certificate " + issuerCert.getSubjectDN());
        }
        return proxyDepth + 1;
    }

    private void validateCACert(
            X509Certificate cert, X509Certificate issuerCert,
            TBSCertificateStructure issuerTbsCert, int proxyDepth, int i,
            boolean certIsProxy) throws CertPathValidatorException {
        // PC can only be signed by EEC or PC
        if (certIsProxy) {
            throw new CertPathValidatorException(
                    "Proxy certificate can be signed only by EEC or Proxy "
                            + "Certificate. Certificate " + cert.getSubjectDN() + " violates this.");
        }

        try {
            int pathLen =
                    CertificateUtil.getCAPathConstraint(issuerTbsCert);
            if (pathLen < Integer.MAX_VALUE
                    && (i - proxyDepth - 1) > pathLen) {
                throw new CertPathValidatorException("Path length constraint of certificate "
                        + issuerCert.getSubjectDN() + " violated");
            }
        } catch (IOException e) {
            throw new CertPathValidatorException("Error obtaining CA Path constraint", e);
        }
    }


//    private X509Certificate checkCertificate(List<X509Certificate> trustedCertPath, X509Certificate x509Certificate,
//                                             Certificate issuerCertificate) throws CertPathValidatorException {
//        X509Certificate x509IssuerCertificate = (X509Certificate) issuerCertificate;
//
//        // check that the next one is indeed issuer
//        Principal issuerDN = x509Certificate.getIssuerDN();
//        Principal issuerCertDN = x509IssuerCertificate.getSubjectDN();
//        if (!(issuerDN.equals(issuerCertDN))) {
//            throw new IllegalArgumentException("Incorrect certificate path, certificate in chain can only "
//                    + "be issuer of previous certificate");
//        }
//
//        // validate integrity of signature
//        PublicKey publicKey = x509IssuerCertificate.getPublicKey();
//        try {
//            x509Certificate.verify(publicKey);
//        } catch (CertificateException e) {
//            throw new CertPathValidatorException(
//                    "Signature validation on the certificate " + x509Certificate.getSubjectDN(), e);
//        } catch (NoSuchAlgorithmException e) {
//            throw new CertPathValidatorException(
//                    "Signature validation on the certificate " + x509Certificate.getSubjectDN(), e);
//        } catch (InvalidKeyException e) {
//            throw new CertPathValidatorException(
//                    "Signature validation on the certificate " + x509Certificate.getSubjectDN(), e);
//        } catch (NoSuchProviderException e) {
//            throw new CertPathValidatorException(
//                    "Signature validation on the certificate " + x509Certificate.getSubjectDN(), e);
//        } catch (SignatureException e) {
//            throw new CertPathValidatorException(
//                    "Signature validation on the certificate " + x509Certificate.getSubjectDN(), e);
//        }
//
//        trustedCertPath.add(x509Certificate);
//        return x509IssuerCertificate;
//    }

    protected void checkRestrictedProxy(TBSCertificateStructure proxy, CertPath certPath, int index)
            throws CertPathValidatorException, IOException {


        ProxyCertInfo info = ProxyCertificateUtil.getProxyCertInfo(proxy);
        ProxyPolicy policy = info.getProxyPolicy();

        String pl = policy.getPolicyLanguage().getId();

        ProxyPolicyHandler handler = null;
        if (this.policyHandlers != null) {
            handler = this.policyHandlers.get(pl);
        }

        if (handler == null) {
            throw new CertPathValidatorException("Unknown policy, no handler registered to validate policy " + pl);

        }

        handler.validate(info, certPath, index);

    }

    protected void checkKeyUsage(TBSCertificateStructure issuer)
            throws CertPathValidatorException, IOException {

        EnumSet<KeyUsage> issuerKeyUsage = CertificateUtil.getKeyUsage(issuer);
        if (issuerKeyUsage != null && !issuerKeyUsage.contains(KeyUsage.KEY_CERTSIGN)) {
            throw new CertPathValidatorException("Certificate " + issuer.getSubject() + " violated key usage policy.");
        }
    }


    // COMMENT enable the checkers again when ProxyPathValidator starts working!
    protected List<CertificateChecker> getCertificateCheckers() {
        List<CertificateChecker> checkers = new ArrayList<CertificateChecker>();
        checkers.add(new DateValidityChecker());
        checkers.add(new UnsupportedCriticalExtensionChecker());
        checkers.add(new IdentityChecker(this));
        // NOTE: the (possible) refresh of the CRLs happens when we call getDefault.
        // Hence, we must recreate crlsList for each call to checkCertificate
        // Sadly, this also means that the amount of work necessary for checkCertificate
        // can be arbitrarily large (if the CRL is indeed refreshed).
        //
        // Note we DO NOT use this.certStore by default!  TODO: This differs from the unit test
        CertificateRevocationLists crlsList = CertificateRevocationLists.getDefaultCertificateRevocationLists();
        checkers.add(new CRLChecker(crlsList, this.keyStore, true));
        checkers.add(new SigningPolicyChecker(this.policyStore));
        return checkers;
    }

    /*
     * Method to check following for any given certificate
     *
     * a) Date validity, is it valid for the curent time (see DateValidityChecker)
     * b) Any unsupported critical extensions (see UnsupportedCriticalExtensionChecker)
     * c) Identity of certificate (see IdentityChecker)
     * d) Revocation (see CRLChecker)
     * e) Signing policy (see SigningPolicyChecker)
     *
     */

    private void checkCertificate(X509Certificate cert, GSIConstants.CertificateType certType)
            throws CertPathValidatorException {
        for (CertificateChecker checker : getCertificateCheckers()) {
            checker.invoke(cert, certType);
        }
    }

    @SuppressWarnings("unused")
    protected void checkProxyConstraints(TBSCertificateStructure proxy, TBSCertificateStructure issuer,
                                         X509Certificate checkedProxy)
            throws CertPathValidatorException, IOException {

        X509Extensions extensions;
        ASN1ObjectIdentifier oid;
        X509Extension proxyExtension;

        X509Extension proxyKeyUsage = null;

        extensions = proxy.getExtensions();
        if (extensions != null) {
            Enumeration e = extensions.oids();
            while (e.hasMoreElements()) {
                oid = (ASN1ObjectIdentifier) e.nextElement();
                proxyExtension = extensions.getExtension(oid);
                if (oid.equals(X509Extension.subjectAlternativeName)
                        || oid.equals(X509Extension.issuerAlternativeName)) {
                    // No Alt name extensions - 3.2 & 3.5
                    throw new CertPathValidatorException(
                            "Proxy violation: no Subject or Issuer Alternative Name");
                } else if (oid.equals(X509Extension.basicConstraints)) {
                    // Basic Constraint must not be true - 3.8
                    BasicConstraints basicExt =
                            CertificateUtil.getBasicConstraints(proxyExtension);
                    if (basicExt.isCA()) {
                        throw new CertPathValidatorException(
                                "Proxy violation: Basic Constraint CA is set to true");
                    }
                } else if (oid.equals(X509Extension.keyUsage)) {
                    proxyKeyUsage = proxyExtension;
                }
            }
        }

        extensions = issuer.getExtensions();

        if (extensions != null) {
            Enumeration e = extensions.oids();
            while (e.hasMoreElements()) {
                oid = (ASN1ObjectIdentifier) e.nextElement();
                proxyExtension = extensions.getExtension(oid);
                checkExtension(oid, proxyExtension, proxyKeyUsage);
            }
        }

    }

    private void checkExtension(ASN1ObjectIdentifier oid, X509Extension proxyExtension, X509Extension proxyKeyUsage) throws CertPathValidatorException {
        if (oid.equals(X509Extension.keyUsage)) {
            // If issuer has it then proxy must have it also
            if (proxyKeyUsage == null) {
                throw new CertPathValidatorException(
                        "Proxy violation: Issuer has key usage, but proxy does not");
            }
            // If issuer has it as critical so does the proxy
            if (proxyExtension.isCritical() && !proxyKeyUsage.isCritical()) {
                throw new CertPathValidatorException(
                        "Proxy voilation: issuer key usage is critical, but proxy certificate's is not");
            }
        }
    }

    public X509Certificate getIdentityCertificate() {
        return this.identityCert;
    }

    public void setLimited(boolean limited) {
        this.limited = limited;
    }

    // COMMENT: added a way to get 'limited'
    public boolean isLimited() {
        return this.limited;
    }

    public void setIdentityCert(X509Certificate identityCert) {
        this.identityCert = identityCert;
    }

    public boolean isRejectLimitedProxy() {
        return this.rejectLimitedProxy;
    }
}

