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

import org.globus.gsi.util.ProxyCertificateUtil;

import org.globus.gsi.provider.SigningPolicyStore;

import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStoreException;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.globus.gsi.GSIConstants;
import org.globus.gsi.SigningPolicy;

/**
 * This checks to make sure the Distinguished Name in the certificate is valid according to the signing policy.
 */
public class SigningPolicyChecker implements CertificateChecker {
    private SigningPolicyStore policyStore;

    public SigningPolicyChecker(SigningPolicyStore policyStore) {
        this.policyStore = policyStore;
    }

    /**
     * Validate DN against the signing policy
     *
     * @param cert     The certificate to check.
     * @param certType The type of certificate to check.
     * @throws CertPathValidatorException if the certificate is invalid according to the signing policy.
     */
    public void invoke(X509Certificate cert, GSIConstants.CertificateType certType) throws CertPathValidatorException {
        if (!requireSigningPolicyCheck(certType)) {
            return;
        }
        X500Principal caPrincipal = cert.getIssuerX500Principal();
        SigningPolicy policy;
        try {
            policy = this.policyStore.getSigningPolicy(caPrincipal);
        } catch (CertStoreException e) {
            throw new CertPathValidatorException(e);
        }

        if (policy == null) {
            throw new CertPathValidatorException("No signing policy for " + cert.getIssuerDN());
        }

        boolean valid = policy.isValidSubject(cert.getSubjectX500Principal());

        if (!valid) {
            throw new CertPathValidatorException("Certificate " + cert.getSubjectDN()
                    + " violates signing policy for CA " + caPrincipal.getName());
        }
    }

    /**
     * if a certificate is not a CA or if it is not a proxy, return true.
     *
     * @param certType The type of Certificate being queried.
     * @return True if the CertificateType requires a Signing Policy check.
     */
    private boolean requireSigningPolicyCheck(GSIConstants.CertificateType certType) {

        return !ProxyCertificateUtil.isProxy(certType) && certType != GSIConstants.CertificateType.CA;
    }
}
