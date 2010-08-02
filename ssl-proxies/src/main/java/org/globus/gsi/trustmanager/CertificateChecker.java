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
import java.security.cert.X509Certificate;

import org.globus.gsi.GSIConstants;

/**
 * Implementations of this interface will provide some validation logic of certificates.
 *
 * @version ${version}
 * @since 1.0
 */
public interface CertificateChecker {
    /**
     * Validate the certificate.
     *
     * @param cert     The certificate to validate.
     * @param certType The type of certificate to validate.
     * @throws CertPathValidatorException If validation fails.
     */
    void invoke(X509Certificate cert, GSIConstants.CertificateType certType) throws CertPathValidatorException;
}
