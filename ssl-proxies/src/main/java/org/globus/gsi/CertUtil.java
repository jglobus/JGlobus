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
package org.globus.gsi;

import org.globus.gsi.util.CertificateIOUtil;
import org.globus.gsi.util.CertificateLoadUtil;
import org.globus.gsi.util.CertificateUtil;
import org.globus.gsi.util.ProxyCertificateUtil;




import java.security.Security;
import java.security.Provider;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import java.security.Principal;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import org.globus.util.I18n;
import org.globus.common.CoGProperties;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


/**
 * Contains various security-related utility methods.
 * @deprecated Use the various utils that are used here.
 */
public class CertUtil {

    /**
     * A no-op function that can be used to force the class
     * to load and initialize.
     */
    public static void init() {
        CertificateUtil.init();
        CertificateLoadUtil.init();
    }

    /**
     * Installs SecureRandom provider.
     * This function is automatically called when this class is loaded.
     */
    public static void installSecureRandomProvider() {
        CertificateUtil.installSecureRandomProvider();
    }

    /**
     * Sets a provider name to use for loading certificates
     * and for generating key pairs.
     *
     * @param providerName provider name to use.
     */
    public static void setProvider(String providerName) {
        CertificateUtil.setProvider(providerName);
        CertificateLoadUtil.setProvider(providerName);
    }

    /**
     * Loads a X509 certificate from the specified input stream.
     * Input stream must contain DER-encoded certificate.
     *
     * @param in the input stream to read the certificate from.
     * @return <code>X509Certificate</code> the loaded certificate.
     * @exception GeneralSecurityException if certificate failed to load.
     */
    public static X509Certificate loadCertificate(InputStream in)
        throws GeneralSecurityException {
        return CertificateLoadUtil.loadCertificate(in);
    }

    /**
     * Loads an X.509 certificate from the specified file.
     * The certificate file must be in PEM/Base64 format and start with
     * "BEGIN CERTIFICATE" and end with "END CERTIFICATE" line.
     *
     * @param file the file to load the certificate from.
     * @return <code>java.security.cert.X509Certificate</code>
     *         the loaded certificate.
     * @exception IOException if I/O error occurs
     * @exception GeneralSecurityException if security problems occurs.
     */
    public static X509Certificate loadCertificate(String file)
        throws IOException, GeneralSecurityException {
        return CertificateLoadUtil.loadCertificate(file);
    }

    /**
     * Loads multiple X.509 certificates from the specified file.
     * Each certificate must be in PEM/Base64 format and start with
     * "BEGIN CERTIFICATE" and end with "END CERTIFICATE" line.
     *
     * @param file the certificate file to load the certificate from.
     * @return an array of certificates loaded from the file.
     * @exception IOException if I/O error occurs
     * @exception GeneralSecurityException if security problems occurs.
     */
    public static X509Certificate[] loadCertificates(String file)
        throws IOException, GeneralSecurityException {
        return CertificateLoadUtil.loadCertificates(file);
    }

    /**
     * Loads a X.509 certificate from the specified reader.
     * The certificate contents must start with "BEGIN CERTIFICATE" line
     * and end with "END CERTIFICATE" line, and be in PEM/Base64 format.
     *
     * This function does not close the input stream.
     *
     * @param reader the stream from which load the certificate.
     * @return the loaded certificate or null if there was no certificate
     *         in the stream or the stream is closed.
     * @exception IOException if I/O error occurs
     * @exception GeneralSecurityException if security problems occurs.
     */
    public static X509Certificate readCertificate(BufferedReader reader)
        throws IOException, GeneralSecurityException {
        return CertificateLoadUtil.readCertificate(reader);
    }

    /**
     * Writes certificate to the specified output stream in PEM format.
     */
    public static void writeCertificate(OutputStream out,
                                        X509Certificate cert)
        throws IOException, CertificateEncodingException {
        CertificateIOUtil.writeCertificate(out, cert);
    }

    /**
     * Converts DN of the form "CN=A, OU=B, O=C" into Globus
     * format "/CN=A/OU=B/O=C".<BR>
     * This function might return incorrect Globus-formatted ID when one of
     * the RDNs in the DN contains commas.
     * @see #toGlobusID(String, boolean)
     *
     * @param dn the DN to convert to Globus format.
     * @return the converted DN in Globus format.
     */
    public static String toGlobusID(String dn) {
        return CertificateUtil.toGlobusID(dn);
    }

    /**
     * Converts DN of the form "CN=A, OU=B, O=C" into Globus
     * format "/CN=A/OU=B/O=C" or "/O=C/OU=B/CN=A" depending on the
     * <code>noreverse</code> option. If <code>noreverse</code> is true
     * the order of the DN components is not reveresed - "/CN=A/OU=B/O=C" is
     * returned. If <code>noreverse</code> is false, the order of the
     * DN components is reversed - "/O=C/OU=B/CN=A" is returned. <BR>
     * This function might return incorrect Globus-formatted ID when one of
     * the RDNs in the DN contains commas.
     *
     * @param dn the DN to convert to Globus format.
     * @param noreverse the direction of the conversion.
     * @return the converted DN in Globus format.
     */
    public static String toGlobusID(String dn, boolean noreverse) {
        return CertificateUtil.toGlobusID(dn, noreverse);
    }

    /**
     * Converts the specified principal into Globus format.
     * If the principal is of unrecognized type a simple string-based
     * conversion is made using the {@link #toGlobusID(String) toGlobusID()}
     * function.
     *
     * @see #toGlobusID(String)
     *
     * @param name the principal to convert to Globus format.
     * @return the converted DN in Globus format.
     */
    public static String toGlobusID(Principal name) {
        return CertificateUtil.toGlobusID(name);
    }

    // proxy utilies

    /**
     * Determines if a specified certificate type indicates a GSI-2,
     * GSI-3 or GSI-4proxy certificate.
     *
     * @param certType the certificate type to check.
     * @return true if certType is a GSI-2 or GSI-3 or GSI-4 proxy, false
     *         otherwise.
     */
    public static boolean isProxy(int certType) {
        return ProxyCertificateUtil.isProxy(GSIConstants.CertificateType.get(certType));
    }

    /**
     * Determines if a specified certificate type indicates a
     * GSI-4 proxy certificate.
     *
     * @param certType the certificate type to check.
     * @return true if certType is a GSI-4 proxy, false
     *         otherwise.
     */
    public static boolean isGsi4Proxy(int certType) {
        return ProxyCertificateUtil.isGsi4Proxy(GSIConstants.CertificateType.get(certType));
    }

    /**
     * Determines if a specified certificate type indicates a
     * GSI-3 proxy certificate.
     *
     * @param certType the certificate type to check.
     * @return true if certType is a GSI-3 proxy, false
     *         otherwise.
     */
    public static boolean isGsi3Proxy(int certType) {
        return ProxyCertificateUtil.isGsi3Proxy(GSIConstants.CertificateType.get(certType));
    }

    /**
     * Determines if a specified certificate type indicates a
     * GSI-2 proxy certificate.
     *
     * @param certType the certificate type to check.
     * @return true if certType is a GSI-2 proxy, false
     *         otherwise.
     */
    public static boolean isGsi2Proxy(int certType) {
        return ProxyCertificateUtil.isGsi2Proxy(GSIConstants.CertificateType.get(certType));
    }

    /**
     * Determines if a specified certificate type indicates a
     * GSI-2 or GSI-3 or GSI=4 limited proxy certificate.
     *
     * @param certType the certificate type to check.
     * @return true if certType is a GSI-2 or GSI-3 or GSI-4 limited proxy,
     *         false otherwise.
     */
    public static boolean isLimitedProxy(int certType) {
        return ProxyCertificateUtil.isLimitedProxy(GSIConstants.CertificateType.get(certType));
    }

    /**
     * Determines if a specified certificate type indicates a
     *  GSI-3 or GS-4 limited proxy certificate.
     *
     * @param certType the certificate type to check.
     * @return true if certType is a GSI-3 or GSI-4 independent proxy,
     *         false otherwise.
     */
    public static boolean isIndependentProxy(int certType) {
        return ProxyCertificateUtil.isIndependentProxy(GSIConstants.CertificateType.get(certType));
    }

    /**
     * Determines if a specified certificate type indicates a
     * GSI-2 or GSI-3 or GSI-4 impersonation proxy certificate.
     *
     * @param certType the certificate type to check.
     * @return true if certType is a GSI-2 or GSI-3 or GSI-4
     *         impersonation proxy, false otherwise.
     */
    public static boolean isImpersonationProxy(int certType) {
        return ProxyCertificateUtil.isImpersonationProxy(GSIConstants.CertificateType.get(certType));
    }

    /**
     * Returns a string description of a specified proxy
     * type.
     *
     * @param proxyType the proxy type to get the string
     *        description of.
     * @return the string description of the proxy type.
     */
    public static String getProxyTypeAsString(int proxyType) {
        return ProxyCertificateUtil.getProxyTypeAsString(GSIConstants.CertificateType.get(proxyType));
    }

    /**
     * Checks if GSI-3 mode is enabled.
     *
     * @return true if <I>"org.globus.gsi.version"</I> system property
     *         is set to "3". Otherwise, false.
     */
    public static boolean isGsi3Enabled() {
        return VersionUtil.isGsi3Enabled();
    }

    /**
     * Checks if GSI-2 mode is enabled.
     *
     * @return true if <I>"org.globus.gsi.version"</I> system property
     *         is set to "2". Otherwise, false.
     */
    public static boolean isGsi2Enabled() {
        return VersionUtil.isGsi2Enabled();
    }

    // CRL Utilities JGLOBUS-91
    public static X509CRL loadCrl(String file)
        throws IOException, GeneralSecurityException {
        return CertificateLoadUtil.loadCrl(file);
    }

    public static X509CRL loadCrl(InputStream in)
        throws GeneralSecurityException {
        return CertificateLoadUtil.loadCrl(in);
    }

}
