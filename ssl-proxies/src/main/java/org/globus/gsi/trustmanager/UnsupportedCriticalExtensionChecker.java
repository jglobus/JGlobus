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

import org.globus.gsi.proxy.ext.ProxyCertInfo;

import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;
import java.util.Set;

import org.globus.gsi.GSIConstants;

/**
 * Checks if the certificate includes unsupported critical extensions.
 *
 * @version ${version}
 * @since 1.0
 */
public class UnsupportedCriticalExtensionChecker implements CertificateChecker {
    /**
     * Method that checks if there are unsupported critical extension. Supported
     * ones are only BasicConstrains, KeyUsage, Proxy Certificate (old and new)
     *
     * @param cert     The certificate to validate.
     * @param certType The type of certificate to validate.
     * @throws CertPathValidatorException If any critical extension that is not supported is in the certificate.
     *                                    Anything other than those listed above will trigger the exception.
     */
    public void invoke(X509Certificate cert, GSIConstants.CertificateType certType) throws CertPathValidatorException {
        Set<String> criticalExtensionOids =
                cert.getCriticalExtensionOIDs();
        if (criticalExtensionOids == null) {
            return;
        }
        for (String criticalExtensionOid : criticalExtensionOids) {
            isUnsupported(certType, criticalExtensionOid);
        }
    }

    private void isUnsupported(GSIConstants.CertificateType certType, String criticalExtensionOid)
            throws CertPathValidatorException {
        boolean unsupportedCritExtention = criticalExtensionOid.equals(X509ProxyCertPathValidator.BASIC_CONSTRAINT_OID);
        unsupportedCritExtention = unsupportedCritExtention || criticalExtensionOid.equals(X509ProxyCertPathValidator.KEY_USAGE_OID);
        unsupportedCritExtention = unsupportedCritExtention
                || (criticalExtensionOid.equals(ProxyCertInfo.OID.toString())
                && ProxyCertificateUtil.isGsi4Proxy(certType));
        unsupportedCritExtention = unsupportedCritExtention
                || (criticalExtensionOid.equals(ProxyCertInfo.OLD_OID.toString())
                && ProxyCertificateUtil.isGsi3Proxy(certType));

        if (unsupportedCritExtention) {
            return;
        }
//        if (criticalExtensionOid.equals(X509ProxyCertPathValidator.BASIC_CONSTRAINT_OID)
//                || criticalExtensionOid.equals(X509ProxyCertPathValidator.KEY_USAGE_OID)
//                || (criticalExtensionOid.equals(Constants.PROXY_OID.toString())
//                && ProxyCertificateUtil.isGsi4Proxy(certType))
//                || (criticalExtensionOid.equals(Constants.PROXY_OLD_OID.toString())
//                && ProxyCertificateUtil.isGsi3Proxy(certType))) {
//            return;
//        }
        throw new CertPathValidatorException("Critical extension with unsupported OID " + criticalExtensionOid);
    }
}
