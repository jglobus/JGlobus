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

import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import org.globus.gsi.GSIConstants;

/**
 * Checks if the certificate has expried or is not yet valid.
 *
 * @version ${version}
 * @since 1.0
 */
public class DateValidityChecker implements CertificateChecker {

    /**
     * Method that checks the time validity. Uses the standard Certificate.checkValidity method.
     *
     * @throws CertPathValidatorException If certificate has expired or is not yet valid.
     */

    public void invoke(X509Certificate cert, GSIConstants.CertificateType certType) throws CertPathValidatorException {
        try {
            cert.checkValidity();
        } catch (CertificateExpiredException e) {
            throw new CertPathValidatorException(
                    "Certificate " + cert.getSubjectDN() + " expired", e);
        } catch (CertificateNotYetValidException e) {
            throw new CertPathValidatorException(
                    "Certificate " + cert.getSubjectDN() + " not yet valid.", e);
        }
    }
}
