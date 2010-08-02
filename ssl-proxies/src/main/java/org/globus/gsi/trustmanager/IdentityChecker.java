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

import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;

import org.globus.gsi.GSIConstants;

/**
 * Checks to see if a limited proxy is acceptable (if the chain has a limited proxy).
 * Also, sets the identity certificate in the certificate path validator.
 */
public class IdentityChecker implements CertificateChecker {
    private X509ProxyCertPathValidator proxyCertValidator;

    public IdentityChecker(X509ProxyCertPathValidator proxyCertPathValidator) {
        this.proxyCertValidator = proxyCertPathValidator;
    }


    /**
     * Method that sets the identity of the certificate path. Also checks if
     * limited proxy is acceptable.
     *
     * @throws CertPathValidatorException If limited proxies are not accepted
     *                                    and the chain has a limited proxy.
     */

    public void invoke(X509Certificate cert, GSIConstants.CertificateType certType) throws CertPathValidatorException {
        if (proxyCertValidator.getIdentityCertificate() == null) {
            // check if limited
            if (ProxyCertificateUtil.isLimitedProxy(certType)) {
                proxyCertValidator.setLimited(true);

                if (proxyCertValidator.isRejectLimitedProxy()) {
                    throw new CertPathValidatorException(
                            "Limited proxy not accepted");
                }
            }

            // set the identity cert
            if (!ProxyCertificateUtil.isImpersonationProxy(certType)) {
                proxyCertValidator.setIdentityCert(cert);
            }
        }
    }
}
