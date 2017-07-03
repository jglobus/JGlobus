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
package org.globus.gsi.util;

import org.apache.commons.logging.Log;

import org.apache.commons.logging.LogFactory;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Vector;



import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

/**
 * Contains various security-related utility methods.
 */
public final class CertificateLoadUtil {

    static {
        Security.addProvider(new BouncyCastleProvider());
        logger = LogFactory.getLog(CertificateLoadUtil.class.getCanonicalName());
        setProvider("BC");
    }

    private static Log logger;
    private static String provider;

    private CertificateLoadUtil() {
        //This should not be created.
    }

    /**
     * A no-op function that can be used to force the class to load and
     * initialize.
     */
    public static void init() {
    }

    /**
     * Sets a provider name to use for loading certificates and for generating
     * key pairs.
     *
     * @param providerName provider name to use.
     */
    public static void setProvider(String providerName) {
        provider = providerName;
        logger.debug("Provider set to : " + providerName);
    }

    /**
     * Returns appropriate <code>CertificateFactory</code>. If <I>provider</I>
     * was set a provider-specific <code>CertificateFactory</code> will be used.
     * Otherwise, a default <code>CertificateFactory</code> will be used.
     *
     * @return <code>CertificateFactory</code>
     */
    protected static CertificateFactory getCertificateFactory()
            throws GeneralSecurityException {
        if (provider == null) {
            return CertificateFactory.getInstance("X.509");
        } else {
            return CertificateFactory.getInstance("X.509", provider);
        }
    }

    /**
     * Loads a X509 certificate from the specified input stream. Input stream
     * must contain DER-encoded certificate.
     *
     * @param in the input stream to read the certificate from.
     * @return <code>X509Certificate</code> the loaded certificate.
     * @throws GeneralSecurityException if certificate failed to load.
     */
    public static X509Certificate loadCertificate(InputStream in)
            throws GeneralSecurityException {
        return (X509Certificate) getCertificateFactory().generateCertificate(in);
    }


    /**
     * Loads an X.509 certificate from the specified file. The certificate file
     * must be in PEM/Base64 format and start with "BEGIN CERTIFICATE" and end
     * with "END CERTIFICATE" line.
     *
     * @param file the file to load the certificate from.
     * @return <code>java.security.cert.X509Certificate</code> the loaded
     *         certificate.
     * @throws IOException              if I/O error occurs
     * @throws GeneralSecurityException if security problems occurs.
     */
    public static X509Certificate loadCertificate(String file)
            throws IOException, GeneralSecurityException {

        if (file == null) {
            throw new IllegalArgumentException("Certificate file is null");
            //i18n
            //  .getMessage("certFileNull"));
        }

        X509Certificate cert = null;

        BufferedReader reader = new BufferedReader(new FileReader(file));
        try {
            cert = readCertificate(reader);
        } finally {
            reader.close();
        }

        if (cert == null) {
            throw new GeneralSecurityException("No certificate data");
            //i18n.getMessage("noCertData"));
        }

        return cert;
    }

    /**
     * Loads multiple X.509 certificates from the specified file. Each
     * certificate must be in PEM/Base64 format and start with "BEGIN
     * CERTIFICATE" and end with "END CERTIFICATE" line.
     *
     * @param file the certificate file to load the certificate from.
     * @return an array of certificates loaded from the file.
     * @throws IOException              if I/O error occurs
     * @throws GeneralSecurityException if security problems occurs.
     */
    public static X509Certificate[] loadCertificates(String file)
            throws IOException, GeneralSecurityException {

        if (file == null) {
            throw new IllegalArgumentException("Certificate file is null");
            //i18n
            //                                 .getMessage("certFileNull"));
        }

        List<X509Certificate> list = new ArrayList<X509Certificate>();
        BufferedReader reader = new BufferedReader(new FileReader(file));
        X509Certificate cert = readCertificate(reader);
        try {
            while (cert != null) {
                list.add(cert);
                cert = readCertificate(reader);
            }
        } finally {
            reader.close();
        }

        if (list.size() == 0) {
            throw new GeneralSecurityException("No certificate data");
            //i18n.getMessage("noCertData"));
        }

        int size = list.size();
        return list.toArray(new X509Certificate[size]);
    }

    /**
     * Loads a X.509 certificate from the specified reader. The certificate
     * contents must start with "BEGIN CERTIFICATE" line and end with "END
     * CERTIFICATE" line, and be in PEM/Base64 format.
     * <p>
     * This function does not close the input stream.
     *
     * @param reader the stream from which load the certificate.
     * @return the loaded certificate or null if there was no certificate in the
     *         stream or the stream is closed.
     * @throws IOException              if I/O error occurs
     * @throws GeneralSecurityException if security problems occurs.
     */
    public static X509Certificate readCertificate(BufferedReader reader)
            throws IOException, GeneralSecurityException {
        String line;
        StringBuffer buff = new StringBuffer();
        boolean isCert = false;
        boolean isKey = false;
        boolean notNull = false;
        while ((line = reader.readLine()) != null) {
            // Skip key info, if any
            if (line.indexOf("BEGIN RSA PRIVATE KEY") != -1 ||
                 line.indexOf("BEGIN PRIVATE KEY") != -1) {
                isKey = true;
                continue;
            } else if (isKey && (line.indexOf("END RSA PRIVATE KEY") != -1 ||
                                 line.indexOf("END PRIVATE KEY") != -1)) {
                isKey = false;
                continue;
            } else if (isKey)
                continue;

            notNull = true;
            if (line.indexOf("BEGIN CERTIFICATE") != -1) {
                isCert = true;
            } else if (isCert && line.indexOf("END CERTIFICATE") != -1) {
                byte[] data = Base64.decode(buff.toString().getBytes());
                return loadCertificate(new ByteArrayInputStream(data));
            } else if (isCert) {
                buff.append(line);
            }
        }
        if (notNull && !isCert) {
            throw new GeneralSecurityException(
                    "Certificate needs to start with "
                            + " BEGIN CERTIFICATE");
        }
        return null;
    }


    public static X509CRL loadCrl(String file)
            throws IOException, GeneralSecurityException {

        if (file == null) {
            throw new IllegalArgumentException("crlFileNull");
            //i18n.getMessage("crlFileNull"));
        }

        boolean isCrl = false;
        X509CRL crl = null;

        BufferedReader reader;

        String line;
        StringBuffer buff = new StringBuffer();

        reader = new BufferedReader(new FileReader(file));

        try {
            while ((line = reader.readLine()) != null) {
                if (line.indexOf("BEGIN X509 CRL") != -1) {
                    isCrl = true;
                } else if (isCrl && line.indexOf("END X509 CRL") != -1) {
                    byte[] data = Base64.decode(buff.toString().getBytes());
                    crl = loadCrl(new ByteArrayInputStream(data));
                } else if (isCrl) {
                    buff.append(line);
                }
            }
        } finally {
            reader.close();
        }

        if (crl == null) {
            throw new GeneralSecurityException("noCrlsData");
            //i18n.getMessage("noCrlData"));
        }

        return crl;
    }

    public static X509CRL loadCrl(InputStream in)
            throws GeneralSecurityException {
        return (X509CRL) getCertificateFactory().generateCRL(in);
    }

    public static Collection<X509Certificate>
    getTrustedCertificates(KeyStore keyStore, X509CertSelector selector)
            throws KeyStoreException {

        Vector<X509Certificate> certificates = new Vector<X509Certificate>();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isCertificateEntry(alias)) {
                // If a specific impl of keystore requires refresh, this would be a
                // good place to add it.
                Certificate certificate =
                        keyStore.getCertificate(alias);
                if (certificate instanceof X509Certificate) {
                    X509Certificate x509Cert =
                            (X509Certificate) certificate;
                    if (selector == null) {
                        certificates.add(x509Cert);
                    } else if (selector.match(certificate)) {
                        certificates.add(x509Cert);
                    }
                }

            }
        }
        return certificates;
    }
}
