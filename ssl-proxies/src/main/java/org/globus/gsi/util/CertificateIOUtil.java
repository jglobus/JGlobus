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

import org.apache.commons.logging.LogFactory;

import org.apache.commons.logging.Log;

import java.io.FileOutputStream;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;



import javax.security.auth.x500.X500Principal;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.x509.X509Name;

/**
 * Fill Me
 */
public final class CertificateIOUtil {

    // for PEM strings
    public static final int LINE_LENGTH = 64;
    public static final String LINE_SEP = "\n";
    public static final String CERT_HEADER = "-----BEGIN CERTIFICATE-----";
    public static final String CERT_FOOTER = "-----END CERTIFICATE-----";
    public static final String KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
    public static final String KEY_FOOTER = "-----END RSA PRIVATE KEY-----";

    private static Log logger = LogFactory.getLog(CertificateIOUtil.class.getCanonicalName());
    private static MessageDigest md5;

    private CertificateIOUtil() {
        //This should not be instantiated
    }

    private static void init() {
        if (md5 == null) {
            try {
                md5 = MessageDigest.getInstance("MD5");
            } catch (NoSuchAlgorithmException e) {
                logger.error("", e);
            }
        }
    }


    /**
     * Returns equivalent of:
     * openssl x509 -in "cert-file" -hash -noout
     *
     * @param subjectDN
     * @return hash for certificate names
     */
    public static String nameHash(X500Principal subjectDN) {
        try {
            return hash(encodePrincipal(subjectDN));
        } catch (Exception e) {
            logger.error("", e);
            return null;
        }
    }

    /**
     * Returns equivalent of: openssl x509 -in "cert-file" -hash -noout
     *
     * @param subjectDN
     * @return hash for certificate names
     */
    public static String nameHash(X509Name subjectDN) {
        try {
            return hash(encodePrincipal(subjectDN));
        } catch (Exception e) {
            logger.error("", e);
            return null;
        }
    }

    public static byte[] encodePrincipal(X500Principal subject) throws IOException {
        return subject.getEncoded();
    }

    public static byte[] encodePrincipal(X509Name subject) throws IOException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        DEROutputStream der = new DEROutputStream(bout);
        der.writeObject(subject.toASN1Primitive());
        return bout.toByteArray();
    }

    private synchronized static String hash(byte[] data) {
        init();
        if (md5 == null) {
            return null;
        }

        md5.reset();
        md5.update(data);

        byte[] md = md5.digest();

        long ret = (fixByte(md[0]) | (fixByte(md[1]) << 8L));
        ret = ret | fixByte(md[2]) << 16L;
        ret = ret | fixByte(md[3]) << 24L;
        ret = ret & 0xffffffffL;

        return Long.toHexString(ret);
    }

    private static long fixByte(byte b) {
        return (b < 0) ? (long) (b + 256) : (long) b;
    }

    public static void writeCertificate(X509Certificate cert, File path)
            throws CertificateEncodingException, IOException {
        FileOutputStream fos = new FileOutputStream(path);
        writeCertificate(fos, cert);
        fos.close();
    }

    /**
     * Creates PEM encoded cert string with line length, header and footer.
     *
     * @param base64Data already encoded into string
     * @return string
     */
    public static String certToPEMString(String base64Data) {
        return toStringImpl(base64Data, false);
    }

    /**
     * Writes certificate to the specified output stream in PEM format.
     */
    public static void writeCertificate(
            OutputStream out,
            X509Certificate cert)
            throws IOException, CertificateEncodingException {
        PEMUtil.writeBase64(out,
                "-----BEGIN CERTIFICATE-----",
                Base64.encode(cert.getEncoded()),
                "-----END CERTIFICATE-----");
    }


    private static String toStringImpl(String base64Data, boolean isKey) {

        int length = LINE_LENGTH;
        int offset = 0;

        final StringBuffer buf = new StringBuffer(2048);

        if (isKey) {
            buf.append(KEY_HEADER);
        } else {
            buf.append(CERT_HEADER);
        }
        buf.append(LINE_SEP);

        final int size = base64Data.length();
        while (offset < size) {
            if (LINE_LENGTH > (size - offset)) {
                length = size - offset;
            }
            buf.append(base64Data.substring(offset, offset + length));
            buf.append(LINE_SEP);
            offset = offset + LINE_LENGTH;
        }

        if (isKey) {
            buf.append(KEY_FOOTER);
        } else {
            buf.append(CERT_FOOTER);
        }
        buf.append(LINE_SEP);

        return buf.toString();
    }
}

