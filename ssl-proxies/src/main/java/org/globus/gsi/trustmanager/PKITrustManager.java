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

import org.globus.gsi.util.CertificateLoadUtil;
import org.globus.gsi.util.CertificateUtil;

import org.globus.gsi.X509ProxyCertPathParameters;

import org.apache.commons.logging.Log;

import org.apache.commons.logging.LogFactory;


import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Vector;


import javax.net.ssl.X509TrustManager;


/**
 * This is an implementation of an X509TrustManager which supports the validation of proxy certificates.
 * It uses the Globus CertPathValidator.
 * <p>
 * JGLOBUS-97 : ability to accept anonymous connections?
 *
 * @version ${version}
 * @since 1.0
 */
public class PKITrustManager implements X509TrustManager {

    private CertPathValidatorSpi validator;
    private X509ProxyCertPathParameters parameters;
    private CertPathValidatorResult result;
    private Log logger = LogFactory.getLog(getClass().getCanonicalName());


    /**
     * Create a trust manager with the pre-configured cert path validator and proxy parameters.
     *
     * @param initValidator  A cert path validator to be used by this trust manager.
     * @param initParameters The proxy cert parameters, populated with trust store, cert store, etc.
     */
    public PKITrustManager(CertPathValidatorSpi initValidator, X509ProxyCertPathParameters initParameters) {

        if (initValidator == null) {
            throw new IllegalArgumentException("Validator cannot be null");
        }

        if (initParameters == null) {
            throw new IllegalArgumentException("Parameter cannot be null");
        }

        this.validator = initValidator;
        this.parameters = initParameters;
    }

    /**
     * Test if the client is trusted based on the certificate chain. Does not currently support anonymous clients.
     *
     * @param x509Certificates The certificate chain to test for validity.
     * @param authType         The authentication type based on the client certificate.
     * @throws CertificateException If the path validation fails.
     */
    public void checkClientTrusted(X509Certificate[] x509Certificates, String authType)
            throws CertificateException {
        // JGLOBUS-97 : anonymous clients?
        CertPath certPath = CertificateUtil.getCertPath(x509Certificates);
        try {
            this.result = this.validator.engineValidate(certPath, parameters);
        } catch (CertPathValidatorException exception) {
            throw new CertificateException("Path validation failed: " + exception.getMessage(), exception);
        } catch (InvalidAlgorithmParameterException exception) {
            throw new CertificateException("Path validation failed: " + exception.getMessage(), exception);
        }
    }

    /**
     * Test if the server is trusted based on the certificate chain.
     *
     * @param x509Certificates The certificate chain to test for validity.
     * @param authType         The authentication type based on the server certificate.
     * @throws CertificateException If the path validation fails.
     */
    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType)
            throws CertificateException {
        CertPath certPath = CertificateUtil.getCertPath(x509Certificates);
        try {
            this.result = this.validator.engineValidate(certPath, parameters);
        } catch (CertPathValidatorException exception) {
            throw new CertificateException("Path validation failed. " + exception.getMessage(), exception);
        } catch (InvalidAlgorithmParameterException exception) {
            throw new CertificateException("Path validation failed. " + exception.getMessage(), exception);
        }
    }

    /**
     * Get the collection of trusted certificate issuers.
     *
     * @return The trusted certificate issuers.
     */
    public X509Certificate[] getAcceptedIssuers() {
        try {
            Collection<X509Certificate> trusted = CertificateLoadUtil.getTrustedCertificates(
                    this.parameters.getTrustStore(), null);
            return trusted.toArray(new X509Certificate[trusted.size()]);
        } catch (KeyStoreException e) {
            logger.warn("Unable to load trusted Certificates.  Authentication will fail.",e);
            return new X509Certificate[]{};
        }
    }

    /**
     * Return the result of the last certificate validation.
     *
     * @return The validation result.
     */
    public CertPathValidatorResult getValidationResult() {
        return this.result;
    }

}
