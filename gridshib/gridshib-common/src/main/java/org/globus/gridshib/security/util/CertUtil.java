/*
 * Copyright 1999-2007 University of Chicago
 * Copyright 2007-2009 University of Illinois
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.globus.gridshib.security.util;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.security.auth.Subject;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.security.SecurityContext;
import org.globus.gridshib.security.SecurityContextFactory;

import org.globus.gsi.GSIConstants;
import org.globus.gsi.bc.BouncyCastleUtil;
import org.globus.gsi.util.ProxyCertificateUtil;

/**
 * GridShib certificate utilities
 */
public class CertUtil {

    static Log logger = LogFactory.getLog(CertUtil.class.getName());

    /**
     * @return true if and only if the given certificate is an
     *         impersonation proxy
     * @see org.globus.gsi.util.ProxyCertificateUtil#isImpersonationProxy(org.globus.gsi.GSIConstants.CertificateType)
     */
    public static boolean isImpersonationProxy(X509Certificate cert)
                                        throws CertificateException {

        if (cert == null) {
            String msg = "Null X509Certificate argument";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }

        GSIConstants.CertificateType certType =
                BouncyCastleUtil.getCertificateType(cert);
        String msg = "Certificate is " +
                ProxyCertificateUtil.getProxyTypeAsString(certType);
        logger.debug(msg);
        return ProxyCertificateUtil.isImpersonationProxy(certType);
    }

    /**
     * Retrieves the X.509 certificate chain of the authenticated user.
     *
     * @param subject a non-null Subject argument
     * @return the certificate chain, possibly null
     */
    public static X509Certificate[] getCertificateChain(Subject subject) {

        if (subject == null) {
            String msg = "Subject is null";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }

        SecurityContext secCtx = SecurityContextFactory.getInstance(subject);
        assert (secCtx != null);

        return secCtx.getCertificateChain();
    }

    /**
     * Gets the certificate chain from the security context
     * associated with the given subject and then calls
     * {@link #getEEC(X509Certificate[])}.
     *
     * @param subject the authenticated subject
     * @return an end entity certificate, possibly null
     *
     * @exception java.security.cert.CertificateException
     *            If unable to determine if a certificate is
     *            an impersonation proxy
     */
    public static X509Certificate getEEC(Subject subject)
                                  throws CertificateException {

        X509Certificate[] certs = getCertificateChain(subject);
        if (certs == null) {
            logger.warn("No certificate chain found");
            return null;
        }

        return getEEC(certs);
    }

    /**
     * Gets the End Entity Certificate (EEC) from the given
     * certificate chain.  Actually, this is somewhat of a
     * misnomer since this method returns the first
     * non-impersonation proxy in the chain, which is either
     * an EEC, an independent proxy, or a restricted proxy.
     *
     * @param certs a certificate chain
     * @return an end entity certificate, possibly null
     *
     * @exception java.security.cert.CertificateException
     *            If unable to determine if a certificate is
     *            an impersonation proxy
     */
    public static X509Certificate getEEC(X509Certificate[] certs)
                                  throws CertificateException {

        if (certs == null) {
            String msg = "X509Certificate[] is null";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }

        for (int i = 0; i < certs.length; i++) {
            logger.debug("Checking certs[" + i + "]");
            if (!CertUtil.isImpersonationProxy(certs[i])) {
                logger.debug("EEC index is " + i);
                return certs[i];
            }
        }
        logger.warn("Certificate chain did not contain a " +
                    "non-impersonation proxy");
        return null;
    }
}


