/*
 * Copyright 2006-2009 University of Illinois
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERUTF8String;

import org.globus.gsi.bc.BouncyCastleUtil;

import org.globus.opensaml11.saml.SAMLAssertion;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLSubjectAssertion;

/**
 * The <em>SAML X.509 extension</em> is a non-critical X.509
 * extension containing a SAML&nbsp;V1.1 subject-based assertion.
 *
 * <p>According to RFC&nbsp;3280, an X.509&nbsp;v3 certificate
 * extension consists of an OID, a boolean flag indicating
 * whether or not the extension is critical, and a DER-encoded
 * extension value:</p>
 *
 * <pre>Extension  ::=  SEQUENCE  {
 *    extnID      OBJECT IDENTIFIER,
 *    critical    BOOLEAN DEFAULT FALSE,
 *    extnValue   OCTET STRING
 *}</pre>
 *
 * <p>In the case of the SAML X.509 Extension, the OID is</p>
 *
 * <pre>1.3.6.1.4.1.3536.1.1.1.12</pre>
 *
 * <p>and the criticality is <code>FALSE</code>.  Moreover, the
 * extension value has the following ASN.1 structure:</p>
 *
 * <pre>SAMLAssertion  ::=  UTF8String (SIZE (1..MAX))</pre>
 *
 * <p>that is, the extension type is defined to be a DER-encoded
 * UTF8 string.</p>
 *
 * <p>For backward compatibility, the static methods of this
 * class distinguish between the <strong>standard</strong> SAML
 * X.509 Extension (represented by a <code>SAMLX509Extension</code>
 * instance) and the <strong>legacy</strong> SAML X.509 Extension.</p>
 *
 * @see org.globus.gridshib.security.x509.NonCriticalX509Extension
 */
public final class SAMLX509Extension extends NonCriticalX509Extension {

    static Log logger =
        LogFactory.getLog(SAMLX509Extension.class.getName());

    /**
     * The OID of the <strong>standard</strong> SAML X.509 Extension.
     * All instances of <code>SAMLX509Extension</code> are associated
     * with this OID.
     *
     * @since 0.3.0
     */
    public static final String OID = "1.3.6.1.4.1.3536.1.1.1.12";

    /**
     * The OID of the <strong>legacy</strong> SAML X.509 Extension.
     *
     * @since 0.3.0
     */
    public static final String LEGACY_OID = "1.3.6.1.4.1.3536.1.1.1.10";

    /**
     * Creates an instance of <code>SAMLX509Extension</code>
     * with the appropriate OID and criticality.  Encodes the
     * given SAML assertion as a DER-encoded UTF8 string.
     *
     * <p>This constructor takes an ordinary <code>SAMLAssertion</code>
     * instance and creates a SAML X.509 Extension.  If the
     * extension is to be consumed by the GridShib Security
     * Framework (i.e., this code library), the assertion MUST be
     * a <code>SAMLSubjectAssertion</code> instance.</p>
     *
     * @param assertion the SAML assertion to bind to
     *        this <code>SAMLX509Extension</code> instance
     */
    public SAMLX509Extension(SAMLAssertion assertion) throws IOException {

        super(OID, encodeDERUTF8String(assertion.toString()));

        if (!(assertion instanceof SAMLSubjectAssertion)) {
            String msg = "The argument to this constructor is not " +
                         "a SAMLSubjectAssertion instance";
            logger.warn(msg);
        }
    }

    /**
     * This method does nothing.  It simply preserves the OID of
     * this <code>SAMLX509Extension</code> instance.
     */
    public void setOid(String oid) { return; }

    /**
     * Gets the value of the <strong>standard</strong>
     * SAML X.509 Extension for the given certificate.
     * <p>
     * Note: Prior to 0.3.0, this method returned the value
     * of the legacy SAML X.509 Extension.  In that sense,
     * this method is new in 0.3.0.
     *
     * @param cert a certificate with a bound SAML assertion
     *
     * @return the DER-encoded octet string for the
     *         extension value (which may be null if the
     *         certificate does not contain a standard
     *         SAML X.509 Extension)
     *
     * @exception java.io.IOException
     *            If unable to get the extension value
     *
     * @see org.globus.gsi.bc.BouncyCastleUtil#getExtensionValue(X509Certificate, String)
     */
    public static byte[] getExtensionValue(X509Certificate cert)
                                    throws IOException {

        byte[] extnValue = BouncyCastleUtil.getExtensionValue(cert, OID);
        if (extnValue != null) {
            String msg = "Standard extension value found for cert " +
                         cert.getSerialNumber().toString();
            logger.debug(msg);
            return extnValue;
        }
        logger.debug("No standard extension value found for cert " +
                     cert.getSerialNumber().toString());
        return null;
    }

    /**
     * Gets the value of the <strong>legacy</strong>
     * SAML X.509 Extension for the given certificate.
     *
     * @param cert a certificate with a bound SAML assertion
     *
     * @return the DER-encoded octet string for the legacy
     *         extension value (which may be null if the
     *         certificate does not contain a legacy SAML
     *         X.509 Extension)
     *
     * @exception java.io.IOException
     *            If unable to get the extension value
     *
     * @see org.globus.gsi.bc.BouncyCastleUtil#getExtensionValue(X509Certificate, String)
     *
     * @since 0.3.0
     */
    public static byte[] getLegacyExtensionValue(X509Certificate cert)
                                          throws IOException {

        byte[] extnValue = BouncyCastleUtil.getExtensionValue(cert, LEGACY_OID);
        if (extnValue != null) {
            String msg = "Legacy extension value found for cert " +
                         cert.getSerialNumber().toString();
            logger.debug(msg);
            return extnValue;
        }
        logger.debug("No legacy extension value found for cert " +
                     cert.getSerialNumber().toString());
        return null;
    }

    /**
     * Gets the certificate extension value from the given
     * certificate and attempts to parse it as a SAML assertion.
     * If the extension does not exist, this method returns
     * null.
     * <p>
     * This method first checks for a non-critical extension
     * at <code>OID</code>.  If the standard extension does
     * not exist, it then checks for a non-critical extension
     * at <code>LEGACY_OID</code>.  If the legacy extension
     * does not exist either, this method returns null.
     *
     * @param cert an X.509 certificate that may or may not
     *             contain an embedded SAML assertion
     * @return a SAML subject assertion (or null if the given
     *         certificate does not contain an embedded SAML
     *         assertion)
     *
     * @exception java.io.IOException
     *            If unable to decode the certificate extension
     * @exception org.globus.opensaml11.saml.SAMLException
     *            If unable to parse the SAML assertion
     *
     * @since 0.3.0
     */
    public static SAMLSubjectAssertion getSAMLAssertion(
            X509Certificate cert) throws IOException, SAMLException {

        // get the DER-encoded extension value (OCTET STRING):
        byte[] bytes = getExtensionValue(cert);
        if (bytes == null) {
            String msg = "No standard SAML extension found in cert";
            logger.debug(msg);
            bytes = getLegacyExtensionValue(cert);
            if (bytes == null) {
                msg = "No legacy SAML extension found in cert";
                logger.debug(msg);
                return null;
            }
            SAMLSubjectAssertion assertion =
                new SAMLSubjectAssertion(new ByteArrayInputStream(bytes));
            msg = "Cert contains the following assertion: ";
            logger.debug(msg + assertion.toString());
            return assertion;
        }

        // The API in jce-jdk13-125.jar does not include constructor
        //
        // org.bouncycastle.asn1.ASN1InputStream(byte[] input);
        //
        // (although the API in jce-jdk13-131.jar does) so convert
        // the bytes to an InputStream.  This works in both versions
        // of the BouncyCastle provider.

        // get the DER-encoded UTF8 string from the octet string:
        ASN1InputStream in =
            new ASN1InputStream(new ByteArrayInputStream(bytes));
        DERUTF8String derString = (DERUTF8String)in.readObject();

        // recover the unencoded string:
        String assertionStr = derString.getString();
        String msg = "Cert contains the following assertion: ";
        logger.debug(msg + assertionStr);

        bytes = assertionStr.getBytes();
        return new SAMLSubjectAssertion(new ByteArrayInputStream(bytes));
    }

    /**
     * Determines if the given certificate contains a
     * non-critical X.509 extension at the appropriate
     * OID.  If the certificate is not a v3 certificate,
     * this method short-circuits and returns false.
     * <p>
     * For backward compatibility, this method checks
     * for a non-critical extension at both
     * <code>LEGACY_OID</code> and <code>OID</code>.
     *
     * @param cert a non-null <code>X509Certificate</code> instance
     *
     * @return true if and only if the given certificate has
     *         a non-critical X.509 extension at <code>OID</code>
     *         or <code>LEGACY_OID</code>
     *
     * @see org.globus.gridshib.security.x509.X509Extension#hasNonCriticalExtension(X509Certificate, String)
     *
     * @since 0.3.0
     */
    public static boolean hasSAMLExtension(X509Certificate cert) {

        boolean hasExtn = hasNonCriticalExtension(cert, OID);
        if (hasExtn) {
            String msg = "Extension found for cert " +
                         cert.getSerialNumber().toString();
            logger.debug(msg);
            return true;
        }
        hasExtn = hasNonCriticalExtension(cert, LEGACY_OID);
        if (hasExtn) {
            String msg = "Legacy extension found for cert " +
                         cert.getSerialNumber().toString();
            logger.debug(msg);
            return true;
        }
        logger.debug("SAML extension not found for cert " +
                     cert.getSerialNumber().toString());
        return false;
    }
}
