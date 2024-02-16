/*
 * Copyright 2007-2009 University of Illinois
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.globus.gridshib.security.x509;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERUTF8String;

import org.globus.util.Util;

/**
 * An X.509 v3 certificate extension.
 *
 * @see org.globus.gsi.X509Extension
 *
 * @since 0.3.0
 */
public class X509Extension extends org.globus.gsi.X509Extension {

    static Log logger =
        LogFactory.getLog(X509Extension.class.getName());

    /**
     * Creates an X509Extension object with specified oid.
     * The extension has no value and is marked as non-critical
     * (since X.509 extensions are non-critical by default).
     *
     * @param oid the OID of the X.509 extension
     *
     * @see org.globus.gsi.X509Extension#X509Extension(String)
     */
    public X509Extension(String oid) {
        super(oid);
    }

    /**
     * Creates an X509Extension object with specified oid and value.
     * The extension is marked as noncritical (since X.509 extensions
     * are non-critical by default).
     *
     * @param oid the OID of the X.509 extension
     * @param value the (possibly null) value of the extension
     *              (not octet string encoded)
     *
     * @see org.globus.gsi.X509Extension#X509Extension(String, byte[])
     */
    public X509Extension(String oid, byte[] value) {
        super(oid, value);
    }

    /**
     * Creates an X509Extension instance with the specified OID,
     * criticality, and extension value.
     *
     * @param oid the OID of the X.509 extension
     * @param critical the criticality of the X.509 extension
     * @param value the (possibly null) value of the extension
     *              (not octet string encoded)
     *
     * @see org.globus.gsi.X509Extension#X509Extension(String, boolean, byte[])
     */
    public X509Extension(String oid, boolean critical, byte[] value) {
        super(oid, critical, value);
    }

    /**
     * Print the value of this extension to stdout.
     */
    public void printValue() throws IOException {

        System.out.write(this.getValue());
        System.out.flush();
    }

    /**
     * Write the value of this extension to a file with the
     * given filename.
     *
     * @param outputFilename a non-null, platform-dependent filename
     *
     * @return true if and only if this method successfully
     *         sets file permissions on the resulting file
     *
     * @see #writeValueToFile(File)
     */
    public boolean writeValueToFile(String outputFilename)
                             throws SecurityException,
                                    IOException,
                                    FileNotFoundException {

        if (outputFilename == null) {
            String msg = "Null argument: String outputFilename";
            throw new IllegalArgumentException(msg);
        }

        File outputFile = Util.createFile(outputFilename);
        return writeValueToFile(outputFile);
    }

    /**
     * Write the value of this extension to the given file.
     * <p>
     * For security reasons, this method attempts to set
     * permissions on the resulting file.  If this is
     * successful, the method returns true, otherwise it
     * returns false.  On Windows systems, this method
     * always returns false.
     *
     * @param outputFile a non-null, platform-independent
     *                   <code>File</code> instance
     *
     * @return true if and only if this method successfully
     *         sets file permissions on the resulting file
     */
    public boolean writeValueToFile(File outputFile)
                             throws SecurityException,
                                    IOException,
                                    FileNotFoundException {

        if (outputFile == null) {
            String msg = "Null argument: File outputFile";
            throw new IllegalArgumentException(msg);
        }

        String path = outputFile.getPath();
        boolean result = Util.setOwnerAccessOnly(path);
        if (!result) {
            String str = "Unable to set file permissions: " + path;
            logger.warn(str);
        }

        FileOutputStream out = null;
        try {
            out = new FileOutputStream(outputFile);
            out.write(this.getValue());
            out.flush();
        } finally {
            if (out != null) {
                try { out.close(); } catch (IOException e) { }
            }
        }

        return result;
    }

    /**
     * Encode the given string as a DER-encoded UTF8 string.
     * The output of this method is suitable as input to a
     * constructor of this class.
     *
     * @param str the string to be encoded
     *
     * @return a DER-encoded UTF8 string
     *
     * @see #X509Extension(String, byte[])
     * @see #X509Extension(String, boolean, byte[])
     */
    public static byte[] encodeDERUTF8String(String str)
                                      throws IOException {

        DERUTF8String derString = new DERUTF8String(str);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream derOut = new DEROutputStream(bOut);
        derOut.writeObject(derString);
        return bOut.toByteArray();
    }

    /**
     * Determines if the given certificate contains the non-critical
     * extension indicated by the given OID.  If the certificate is
     * not a v3 certificate, this method short-circuits and returns
     * false.
     *
     * @param cert a non-null <code>X509Certificate</code> instance
     * @param oid a non-null OID
     *
     * @return true if and only if the given certificate contains
     *         the non-critical extension indicated by the given OID
     */
    public static boolean hasNonCriticalExtension(X509Certificate cert,
                                                  String oid) {

        if (cert == null) {
            String msg = "Null argument: X509Certificate cert";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }
        if (oid == null) {
            String msg = "Null argument: String oid";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }

        // Method getNonCriticalExtensionOIDs only works for
        // v3 certificates, that is, certificates containing
        // X.509 v3 certificate extensions.  In particular,
        // the method returns null for v1 certificates.

        if (cert.getVersion() < 3) {
            int ver = cert.getVersion();
            String msg = "Ignoring version " + ver + " certificate";
            logger.warn(msg);
            return false;
        }

        Set nonCritSet = cert.getNonCriticalExtensionOIDs();

        if (nonCritSet == null) {
            String msg = "No extensions present";
            logger.debug(msg);
            return false;
        } else if (nonCritSet.isEmpty()) {
            String msg = "No non-critical extension with OID " + oid;
            logger.debug(msg);
            return false;
        }
        logger.debug("Non-critical extension OIDs: " + nonCritSet.toString());

        return nonCritSet.contains(oid);
    }

    /**
     * Determines if the given certificate contains the critical
     * extension indicated by the given OID.  If the certificate is
     * not a v3 certificate, this method short-circuits and returns
     * false.
     *
     * @param cert a non-null <code>X509Certificate</code> instance
     * @param oid a non-null OID
     *
     * @return true if and only if the given certificate contains
     *         the critical extension indicated by the given OID
     */
    public static boolean hasCriticalExtension(X509Certificate cert,
                                               String oid) {

        if (cert == null) {
            String msg = "Null argument: X509Certificate cert";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }
        if (oid == null) {
            String msg = "Null argument: String oid";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }

        // Method getCriticalExtensionOIDs only works for
        // v3 certificates, that is, certificates containing
        // X.509 v3 certificate extensions.  In particular,
        // the method returns null for v1 certificates.

        if (cert.getVersion() < 3) {
            int ver = cert.getVersion();
            String msg = "Ignoring version " + ver + " certificate";
            logger.warn(msg);
            return false;
        }

        Set critSet = cert.getCriticalExtensionOIDs();

        if (critSet == null) {
            String msg = "No extensions present";
            logger.debug(msg);
            return false;
        } else if (critSet.isEmpty()) {
            String msg = "No critical extension with OID " + oid;
            logger.debug(msg);
            return false;
        }
        logger.debug("Critical extension OIDs: " + critSet.toString());

        return critSet.contains(oid);
    }
}
