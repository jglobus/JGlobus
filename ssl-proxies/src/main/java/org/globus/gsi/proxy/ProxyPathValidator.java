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
package org.globus.gsi.proxy;

import org.globus.gsi.util.CertificateUtil;

import org.globus.gsi.trustmanager.X509ProxyCertPathValidator;

import org.globus.gsi.X509ProxyCertPathParameters;

import org.globus.gsi.provider.simple.SimpleMemoryCertStoreParams;
import org.globus.gsi.provider.simple.SimpleMemoryKeyStoreLoadStoreParameter;
import org.globus.gsi.provider.simple.SimpleMemoryProvider;
import org.globus.gsi.provider.simple.SimpleMemorySigningPolicyStore;

import java.security.Security;
import java.util.Map;
import java.util.HashMap;
import java.util.Hashtable;
import java.security.KeyStore;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import org.globus.gsi.TrustedCertificates;
import org.globus.gsi.SigningPolicy;
import org.globus.gsi.CertificateRevocationLists;
import org.globus.gsi.bc.BouncyCastleUtil;
import org.globus.util.I18n;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Performs certificate/proxy path validation. It supports both old
 * style Globus proxy as well as the new proxy certificate format.  It
 * checks BasicConstraints, KeyUsage, and ProxyCertInfo (if
 * applicable) extensions. It also checks for presence in CRLs and
 * signing policy compliance. This validator requires that each CA be
 * installed with signing policy. It also provides a callback interface
 * for custom policy checking of restricted proxies. <BR> Currently,
 * does <B>not</B> perform the following checks for the new proxy
 * certificates: <OL> <LI> Check if proxy serial number is unique (and
 * the version number) <LI> Check for empty subject names </OL>
 */

public class ProxyPathValidator {

    static {
        Security.addProvider(new SimpleMemoryProvider());
    }

    private static I18n i18n = I18n.getI18n("org.globus.gsi.proxy.errors",
                         ProxyPathValidator.class.getClassLoader());

    private static Log logger =
    LogFactory.getLog(ProxyPathValidator.class.getName());

    private X509ProxyCertPathValidator validator = new X509ProxyCertPathValidator();
    private boolean rejectLimitedProxyCheck = false;
    private boolean limited = false;
    private X509Certificate identityCert = null;
    private Hashtable proxyPolicyHandlers = null;

    /**
     * Returns if the validated proxy path is limited. A proxy path
     * is limited when a limited proxy is present anywhere after the
     * first non-impersonation proxy certificate.
     *
     * @return true if the validated path is limited
     */
    public boolean isLimited() {
    return this.limited;
    }

    /**
     * Returns the identity certificate. The first certificates in the
     * path that is not an impersonation proxy, e.g. it could be a
     * restricted proxy or end-entity certificate
     *
     * @return <code>X509Certificate</code> the identity certificate
     */
    public X509Certificate getIdentityCertificate() {
    return this.identityCert;
    }

    /**
     * Returns the subject name of the identity certificate (in the
     * Globus format)
     * @see #getIdentityCertificate
     * @return the subject name of the identity certificate in the
     *         Globus format
     */
    public String getIdentity() {
    return BouncyCastleUtil.getIdentity(this.identityCert);
    }

    /**
     * Removes a restricted proxy policy handler.
     *
     * @param id the Oid of the policy handler to remove.
     * @return <code>ProxyPolicyHandler</code> the removed handler, or
     *         null if there is no handler registered under that
     *         id.
     */
    public ProxyPolicyHandler removeProxyPolicyHandler(String id) {
    return (id != null && this.proxyPolicyHandlers != null) ?
        (ProxyPolicyHandler)this.proxyPolicyHandlers.remove(id) :
        null;
    }

    /**
     * Sets a restricted proxy policy handler.
     *
     * @param id the Oid of the proxy policy to install the handler for.
     * @param handler the proxy policy handler.
     * @return <code>ProxyPolicyHandler</code> the previous handler
     *        installed under the specified id. Usually, will be null.
     */
    public ProxyPolicyHandler setProxyPolicyHandler(String id,
                            ProxyPolicyHandler handler) {
    if (id == null) {
        throw new IllegalArgumentException(i18n.getMessage("proxyPolicyId"));
    }
    if (handler == null) {
        throw new IllegalArgumentException(i18n.
                getMessage("proxyPolicyHandler"));
    }
    if (this.proxyPolicyHandlers == null) {
        this.proxyPolicyHandlers = new Hashtable();
    }
    return (ProxyPolicyHandler)this.proxyPolicyHandlers.put(id, handler);
    }

    /**
     * Retrieves a restricted proxy policy handler for a given policy id.
     *
     * @param id the Oid of the proxy policy to get the handler for.
     * @return <code>ProxyPolicyHandler</code> the policy handler
     *         registered for the given id or null if none is
     *         registered.
     */
    public ProxyPolicyHandler getProxyPolicyHandler(String id) {
    return (id != null && this.proxyPolicyHandlers != null) ?
        (ProxyPolicyHandler)this.proxyPolicyHandlers.get(id) :
        null;
    }

    /**
     * Resets the internal state. Useful for reusing the same
     * instance for validating multiple certificate paths.
     */
    public void reset() {
    this.rejectLimitedProxyCheck= false;
    this.limited = false;
    this.identityCert = null;
    }

    /**
     * If set, the validate rejects certificate chain if limited proxy if found
     */
    public void setRejectLimitedProxyCheck(boolean rejectLimProxy) {
    this.rejectLimitedProxyCheck = rejectLimProxy;
    }

    /**
     * Performs <B>all</B> certificate path validation including
     * checking of the signatures, validity of the certificates,
     * extension checking, etc.<BR>
     * It uses the PureTLS code to do basic cert signature checking
     * checking and then calls {@link #validate(X509Certificate[],
     * TrustedCertificates) validate} for further checks.
     *
     * @param certPath the certificate path to validate.
     * @param trustedCerts the trusted (CA) certificates.
     * @exception ProxyPathValidatorException if certificate
     *            path validation fails.
     */
    public void validate(X509Certificate[] certPath,
             X509Certificate[] trustedCerts)
    throws ProxyPathValidatorException {
    validate(certPath, trustedCerts, null);
    }

    public void validate(X509Certificate[] certPath,
             X509Certificate[] trustedCerts,
             CertificateRevocationLists crls)
    throws ProxyPathValidatorException {
        validate(certPath, trustedCerts, crls, null);
    }

    public void validate(X509Certificate[] certPath,
             X509Certificate[] trustedCerts,
                         CertificateRevocationLists crls,
                         SigningPolicy[] signingPolicies)
    throws ProxyPathValidatorException {

        validate(certPath, trustedCerts, crls, signingPolicies, null);
    }

    public void validate(X509Certificate[] certPath,
             X509Certificate[] trustedCerts,
             CertificateRevocationLists crls,
                         SigningPolicy[] signingPolicies,
                         Boolean enforceSigningPolicy)
    throws ProxyPathValidatorException {

    if (certPath == null) {
        throw new IllegalArgumentException(i18n.getMessage("certsNull"));
    }

        // If trusted certificates is not null, but signing policy is,
        // then this might fail down the line.
    TrustedCertificates trustedCertificates = null;
    if (trustedCerts != null) {
        trustedCertificates = new TrustedCertificates(trustedCerts,
                                                          signingPolicies);
    }

    validate(certPath, trustedCertificates, crls, enforceSigningPolicy);
    }

    /**
     * Performs certificate path validation. Does <B>not</B> check
     * the cert signatures but it performs all other checks like
     * the extension checking, validity checking, restricted policy
     * checking, CRL checking, etc.
     *
     * @param certPath the certificate path to validate.
     * @exception ProxyPathValidatorException if certificate
     *            path validation fails.
     */
    protected void validate(X509Certificate [] certPath)
    throws ProxyPathValidatorException {
    validate(certPath,
         (TrustedCertificates)null,
         (CertificateRevocationLists)null);
    }

    /**
     * Performs certificate path validation. Does <B>not</B> check
     * the cert signatures but it performs all other checks like
     * the extension checking, validity checking, restricted policy
     * checking, CRL checking, etc.
     *
     * @param certPath the certificate path to validate.
     * @param trustedCerts the trusted (CA) certificates. If null,
     *            the default trusted certificates will be used.
     * @exception ProxyPathValidatorException if certificate
     *            path validation fails.
     */
    protected void validate(X509Certificate [] certPath,
                TrustedCertificates trustedCerts)
    throws ProxyPathValidatorException {
    validate(certPath, trustedCerts, null);
    }

    protected void validate(X509Certificate [] certPath,
                TrustedCertificates trustedCerts,
                CertificateRevocationLists crlsList)
    throws ProxyPathValidatorException {

    validate(certPath, trustedCerts, crlsList, null);
    }

    /**
     * Performs certificate path validation. Does <B>not</B> check
     * the cert signatures but it performs all other checks like
     * the extension checking, validity checking, restricted policy
     * checking, CRL checking, etc.
     *
     * @param certPath the certificate path to validate.
     * @param trustedCerts the trusted (CA) certificates. If null,
     *            the default trusted certificates will be used.
     * @param crlsList the certificate revocation list. If null,
     *            the default certificate revocation list will be used.
     * @exception ProxyPathValidatorException if certificate
     *            path validation fails.
     */
    protected synchronized void validate(X509Certificate [] certPath,
                TrustedCertificates trustedCerts,
                CertificateRevocationLists crlsList,
                Boolean enforceSigningPolicy)
    throws ProxyPathValidatorException {

        if (certPath == null) {
            throw new IllegalArgumentException(i18n.getMessage("certsNull"));
        }

        if (crlsList == null) {
            crlsList = CertificateRevocationLists.getDefaultCertificateRevocationLists();
        }

        if (trustedCerts == null) {
            trustedCerts = TrustedCertificates.getDefault();
        }

        try {
           SimpleMemoryKeyStoreLoadStoreParameter ksParams = new SimpleMemoryKeyStoreLoadStoreParameter();
           SimpleMemoryCertStoreParams csParams = new SimpleMemoryCertStoreParams(null, crlsList.getCrls());
           ksParams.setCerts(trustedCerts.getCertificates());
           Map<String,ProxyPolicyHandler> initHandlers = new HashMap<String,ProxyPolicyHandler>();
           if (this.proxyPolicyHandlers != null) {
               initHandlers.putAll(proxyPolicyHandlers);
           }
           KeyStore ks = KeyStore.getInstance(SimpleMemoryProvider.KEYSTORE_TYPE, SimpleMemoryProvider.PROVIDER_NAME);
           CertStore cs = CertStore.getInstance(SimpleMemoryProvider.CERTSTORE_TYPE, csParams, SimpleMemoryProvider.PROVIDER_NAME);
           SimpleMemorySigningPolicyStore spStore = new SimpleMemorySigningPolicyStore(trustedCerts.getSigningPolicies());
           ks.load(ksParams);
           X509ProxyCertPathParameters params = new X509ProxyCertPathParameters(ks, cs,
               spStore, this.rejectLimitedProxyCheck, initHandlers);
           validator.engineValidate(CertificateUtil.getCertPath(certPath), params);
           this.identityCert = validator.getIdentityCertificate();
           this.limited = validator.isLimited();
        } catch (Exception e) {
            throw new ProxyPathValidatorException(
              ProxyPathValidatorException.FAILURE,
              e);
        }
    }

    protected synchronized void setValidator(X509ProxyCertPathValidator validator) {
        this.validator = validator;
    }

}
