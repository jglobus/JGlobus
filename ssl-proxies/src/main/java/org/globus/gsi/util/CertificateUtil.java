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
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.globus.common.CoGProperties;
import org.globus.gsi.GSIConstants;
import org.globus.gsi.bc.X509NameHelper;
import org.globus.gsi.proxy.ext.ProxyCertInfo;
import org.globus.gsi.proxy.ext.ProxyPolicy;

import javax.security.auth.x500.X500Principal;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Principal;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

import static org.globus.gsi.util.Oid.*;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public final class CertificateUtil {

    private static String provider;
    private static Log logger;

    static {
        Security.addProvider(new BouncyCastleProvider());
        setProvider("BC");
        logger = LogFactory.getLog(CertificateLoadUtil.class.getCanonicalName());
        installSecureRandomProvider();
    }

    private static final Map<String, String> KEYWORD_MAP = new HashMap<String, String>();

    private static final Map<String, String> OID_MAP = new HashMap<String, String>();


    static {
        // Taken from BouncyCastle 2.46
        KEYWORD_MAP.put("SN", SERIALNUMBER.oid);
        KEYWORD_MAP.put("E", EmailAddress.oid);
        KEYWORD_MAP.put("EMAIL", EmailAddress.oid);
        KEYWORD_MAP.put("UNSTRUCTUREDADDRESS", UnstructuredAddress.oid);
        KEYWORD_MAP.put("UNSTRUCTUREDNAME", UnstructuredName.oid);
        KEYWORD_MAP.put("UNIQUEIDENTIFIER", UNIQUE_IDENTIFIER.oid);
        KEYWORD_MAP.put("DN", DN_QUALIFIER.oid);
        KEYWORD_MAP.put("PSEUDONYM", PSEUDONYM.oid);
        KEYWORD_MAP.put("POSTALADDRESS", POSTAL_ADDRESS.oid);
        KEYWORD_MAP.put("NAMEOFBIRTH", NAME_AT_BIRTH.oid);
        KEYWORD_MAP.put("COUNTRYOFCITIZENSHIP", COUNTRY_OF_CITIZENSHIP.oid);
        KEYWORD_MAP.put("COUNTRYOFRESIDENCE", COUNTRY_OF_RESIDENCE.oid);
        KEYWORD_MAP.put("GENDER", GENDER.oid);
        KEYWORD_MAP.put("PLACEOFBIRTH", PLACE_OF_BIRTH.oid);
        KEYWORD_MAP.put("DATEOFBIRTH", DATE_OF_BIRTH.oid);
        KEYWORD_MAP.put("POSTALCODE", POSTAL_CODE.oid);
        KEYWORD_MAP.put("BUSINESSCATEGORY", BUSINESS_CATEGORY.oid);
        KEYWORD_MAP.put("TELEPHONENUMBER", TELEPHONE_NUMBER.oid);
        KEYWORD_MAP.put("NAME", NAME.oid);

        // Taken from CANL library
        KEYWORD_MAP.put("S", ST.oid);
        KEYWORD_MAP.put("DNQUALIFIER", DN_QUALIFIER.oid);
        KEYWORD_MAP.put("IP", IP.oid);

        OID_MAP.put(UnstructuredAddress.oid, "unstructuredAddress");
        OID_MAP.put(UnstructuredName.oid, "unstructuredName");
        OID_MAP.put(UNIQUE_IDENTIFIER.oid, "UniqueIdentifier");
        OID_MAP.put(PSEUDONYM.oid, "Pseudonym");
        OID_MAP.put(POSTAL_ADDRESS.oid, "PostalAddress");
        OID_MAP.put(NAME_AT_BIRTH.oid, "NameAtBirth");
        OID_MAP.put(COUNTRY_OF_CITIZENSHIP.oid, "CountryOfCitizenship");
        OID_MAP.put(COUNTRY_OF_RESIDENCE.oid, "CountryOfResidence");
        OID_MAP.put(GENDER.oid, "Fender");
        OID_MAP.put(PLACE_OF_BIRTH.oid, "PlaceOfBirth");
        OID_MAP.put(DATE_OF_BIRTH.oid, "DateOfBirth");
        OID_MAP.put(POSTAL_CODE.oid, "PostalCode");
        OID_MAP.put(BUSINESS_CATEGORY.oid, "BusinessCategory");
        OID_MAP.put(TELEPHONE_NUMBER.oid, "TelephoneNumber");
        OID_MAP.put(NAME.oid, "Name");
        OID_MAP.put(IP.oid, "IP");

        OID_MAP.put(T.oid, "T");
        OID_MAP.put(DN_QUALIFIER.oid, "DNQUALIFIER");
        OID_MAP.put(SURNAME.oid, "SURNAME");
        OID_MAP.put(GIVENNAME.oid, "GIVENNAME");
        OID_MAP.put(INITIALS.oid, "INITIALS");
        OID_MAP.put(GENERATION.oid, "GENERATION");
        OID_MAP.put(EmailAddress.oid, "EMAILADDRESS");
        OID_MAP.put(SERIALNUMBER.oid, "SERIALNUMBER");
    }

    private CertificateUtil() {
        //this should not be constructed;
    }

    /**
     * A no-op function that can be used to force the class
     * to load and initialize.
     */
    public static void init() {
        CertificateLoadUtil.init();
    }

    /**
     * Sets a provider name to use for loading certificates
     * and for generating key pairs.
     *
     * @param providerName provider name to use.
     */
    public static void setProvider(String providerName) {
        provider = providerName;
    }

    /**
     * Installs SecureRandom provider.
     * This function is automatically called when this class is loaded.
     */
    public static void installSecureRandomProvider() {
        CoGProperties props = CoGProperties.getDefault();
        String providerName = props.getSecureRandomProvider();
        try {
            Class providerClass = Class.forName(providerName);
            Security.insertProviderAt( (Provider)providerClass.newInstance(),
                                       1 );
        } catch (Exception e) {
            logger.debug("Unable to install PRNG. Using default PRNG.",e);
        }
    }

    /**
     * Return CA Path constraint
     *
     * @param crt
     * @return the CA path constraint
     * @throws IOException
     */
    public static int getCAPathConstraint(TBSCertificateStructure crt)
            throws IOException {

        X509Extensions extensions = crt.getExtensions();
        if (extensions == null) {
            return -1;
        }
        X509Extension proxyExtension =
                extensions.getExtension(X509Extension.basicConstraints);
        if (proxyExtension != null) {
            BasicConstraints basicExt =
                    getBasicConstraints(proxyExtension);
            if (basicExt.isCA()) {
                BigInteger pathLen = basicExt.getPathLenConstraint();
                return (pathLen == null) ? Integer.MAX_VALUE : pathLen.intValue();
            } else {
                return -1;
            }
        }
        return -1;
    }

    /**
     * Generates a key pair of given algorithm and strength.
     *
     * @param algorithm the algorithm of the key pair.
     * @param bits the strength
     * @return <code>KeyPair</code> the generated key pair.
     * @exception GeneralSecurityException if something goes wrong.
     */
    public static KeyPair generateKeyPair(String algorithm, int bits)
        throws GeneralSecurityException {
        KeyPairGenerator generator = null;
        if (provider == null) {
            generator = KeyPairGenerator.getInstance(algorithm);
        } else {
            generator = KeyPairGenerator.getInstance(algorithm, provider);
        }
        generator.initialize(bits);
        return generator.generateKeyPair();
    }


    /**
     * Returns certificate type of the given TBS certificate. <BR> The
     * certificate type is {@link org.globus.gsi.GSIConstants.CertificateType#CA
     * GSIConstants.CertificateType.CA} <B>only</B> if the certificate contains a
     * BasicConstraints extension and it is marked as CA.<BR> A certificate is a
     * GSI-2 proxy when the subject DN of the certificate ends with
     * <I>"CN=proxy"</I> (certificate type {@link org.globus.gsi.GSIConstants.CertificateType#GSI_2_PROXY
     * GSIConstants.CertificateType.GSI_2_PROXY}) or <I>"CN=limited proxy"</I> (certificate
     * type {@link org.globus.gsi.GSIConstants.CertificateType#GSI_2_LIMITED_PROXY
     * GSIConstants.CertificateType.LIMITED_PROXY}) component and the issuer DN of the
     * certificate matches the subject DN without the last proxy <I>CN</I>
     * component.<BR> A certificate is a GSI-3 proxy when the subject DN of the
     * certificate ends with a <I>CN</I> component, the issuer DN of the
     * certificate matches the subject DN without the last <I>CN</I> component
     * and the certificate contains {@link ProxyCertInfo
     * ProxyCertInfo} critical extension. The certificate type is {@link
     * org.globus.gsi.GSIConstants.CertificateType#GSI_3_IMPERSONATION_PROXY
     * GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY} if the policy language of the
     * {@link ProxyCertInfo ProxyCertInfo}
     * extension is set to {@link ProxyPolicy#IMPERSONATION
     * ProxyPolicy.IMPERSONATION} OID. The certificate type is {@link
     * org.globus.gsi.GSIConstants.CertificateType#GSI_3_LIMITED_PROXY
     * GSIConstants.CertificateType.GSI_3_LIMITED_PROXY} if the policy language of the {@link
     * ProxyCertInfo ProxyCertInfo} extension
     * is set to {@link ProxyPolicy#LIMITED
     * ProxyPolicy.LIMITED} OID. The certificate type is {@link
     * org.globus.gsi.GSIConstants.CertificateType#GSI_3_INDEPENDENT_PROXY
     * GSIConstants.CertificateType.GSI_3_INDEPENDENT_PROXY} if the policy language of the
     * {@link ProxyCertInfo ProxyCertInfo}
     * extension is set to {@link ProxyPolicy#INDEPENDENT
     * ProxyPolicy.INDEPENDENT} OID. The certificate type is {@link
     * org.globus.gsi.GSIConstants.CertificateType#GSI_3_RESTRICTED_PROXY
     * GSIConstants.CertificateType.GSI_3_RESTRICTED_PROXY} if the policy language of the
     * {@link ProxyCertInfo ProxyCertInfo}
     * extension is set to any other OID then the above.<BR> The certificate
     * type is {@link org.globus.gsi.GSIConstants.CertificateType#EEC
     * GSIConstants.CertificateType.EEC} if the certificate is not a CA certificate or a
     * GSI-2 or GSI-3 proxy.
     *
     * @param crt the TBS certificate to get the type of.
     * @return the certificate type. The certificate type is determined by rules
     *         described above.
     * @throws java.io.IOException if something goes wrong.
     * @throws java.security.cert.CertificateException
     *                             for proxy certificates, if the issuer DN of
     *                             the certificate does not match the subject DN
     *                             of the certificate without the last <I>CN</I>
     *                             component. Also, for GSI-3 proxies when the
     *                             <code>ProxyCertInfo</code> extension is not
     *                             marked as critical.
     */
    public static GSIConstants.CertificateType getCertificateType(
            TBSCertificateStructure crt)
            throws CertificateException, IOException {

        X509Extensions extensions = crt.getExtensions();
        X509Extension ext = null;

        if (extensions != null) {
            ext = extensions.getExtension(X509Extension.basicConstraints);
            if (ext != null) {
                BasicConstraints basicExt = getBasicConstraints(ext);
                if (basicExt.isCA()) {
                    return GSIConstants.CertificateType.CA;
                }
            }
        }

        GSIConstants.CertificateType type = GSIConstants.CertificateType.EEC;

        // does not handle multiple AVAs
        X500Name subject = crt.getSubject();

        ASN1Set entry = X509NameHelper.getLastNameEntry(subject);
        ASN1Sequence ava = (ASN1Sequence) entry.getObjectAt(0);
        if (BCStyle.CN.equals(ava.getObjectAt(0))) {
            type = processCN(extensions, type, ava);
        }

        return type;
    }

    private static GSIConstants.CertificateType processCN(
            X509Extensions extensions, GSIConstants.CertificateType type, ASN1Sequence ava) throws CertificateException {
        X509Extension ext;
        String value = ((ASN1String) ava.getObjectAt(1)).getString();
        GSIConstants.CertificateType certType = type;
        if (value.equalsIgnoreCase("proxy")) {
            certType = GSIConstants.CertificateType.GSI_2_PROXY;
        } else if (value.equalsIgnoreCase("limited proxy")) {
            certType = GSIConstants.CertificateType.GSI_2_LIMITED_PROXY;
        } else if (extensions != null) {
            boolean gsi4 = true;
            // GSI_4
            ext = extensions.getExtension(ProxyCertInfo.OID);
            if (ext == null) {
                // GSI_3
                ext = extensions.getExtension(ProxyCertInfo.OLD_OID);
                gsi4 = false;
            }
            if (ext != null) {
                if (ext.isCritical()) {
                    certType = processCriticalExtension(ext, gsi4);
                } else {
                    String err = "proxyCertCritical";
                    throw new CertificateException(err);
                }
            }
        }


        return certType;
    }

    private static GSIConstants.CertificateType processCriticalExtension(X509Extension ext, boolean gsi4) {
        GSIConstants.CertificateType type;
        ProxyCertInfo proxyCertExt =
                ProxyCertificateUtil.getProxyCertInfo(ext);
        ProxyPolicy proxyPolicy =
                proxyCertExt.getProxyPolicy();
        ASN1ObjectIdentifier oid =
                proxyPolicy.getPolicyLanguage();
        if (ProxyPolicy.IMPERSONATION.equals(oid)) {
            if (gsi4) {
                type =
                        GSIConstants.CertificateType.GSI_4_IMPERSONATION_PROXY;
            } else {
                type =
                        GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY;
            }
        } else if (ProxyPolicy.INDEPENDENT.equals(oid)) {
            if (gsi4) {
                type =
                        GSIConstants.CertificateType.GSI_4_INDEPENDENT_PROXY;
            } else {
                type =
                        GSIConstants.CertificateType.GSI_3_INDEPENDENT_PROXY;
            }
        } else if (ProxyPolicy.LIMITED.equals(oid)) {
            if (gsi4) {
                type =
                        GSIConstants.CertificateType.GSI_4_LIMITED_PROXY;
            } else {
                type =
                        GSIConstants.CertificateType.GSI_3_LIMITED_PROXY;
            }
        } else {
            if (gsi4) {
                type =
                        GSIConstants.CertificateType.GSI_4_RESTRICTED_PROXY;
            } else {
                type =
                        GSIConstants.CertificateType.GSI_3_RESTRICTED_PROXY;
            }
        }
        return type;
    }

    /**
     * Creates a <code>BasicConstraints</code> object from given extension.
     *
     * @param ext the extension.
     * @return the <code>BasicConstraints</code> object.
     * @throws IOException if something fails.
     */
    public static BasicConstraints getBasicConstraints(X509Extension ext)
            throws IOException {

        ASN1Object object = X509Extension.convertValueToObject(ext);
        return BasicConstraints.getInstance(object);
    }


    /**
     * Converts the DER-encoded byte array into a <code>DERObject</code>.
     *
     * @param data the DER-encoded byte array to convert.
     * @return the DERObject.
     * @throws IOException if conversion fails
     */
    public static ASN1Primitive toASN1Primitive(byte[] data)
            throws IOException {
        ByteArrayInputStream inStream = new ByteArrayInputStream(data);
        ASN1InputStream derInputStream = new ASN1InputStream(inStream);
        return derInputStream.readObject();
    }


    /**
     * Extracts the TBS certificate from the given certificate.
     *
     * @param cert the X.509 certificate to extract the TBS certificate from.
     * @return the TBS certificate
     * @throws IOException                  if extraction fails.
     * @throws CertificateEncodingException if extraction fails.
     */
    public static TBSCertificateStructure getTBSCertificateStructure(
            X509Certificate cert)
            throws CertificateEncodingException, IOException {
        ASN1Primitive obj = toASN1Primitive(cert.getTBSCertificate());
        return TBSCertificateStructure.getInstance(obj);
    }

    public static EnumSet<KeyUsage> getKeyUsage(TBSCertificateStructure crt)
            throws IOException {
        X509Extensions extensions = crt.getExtensions();
        if (extensions == null) {
            return null;
        }
        X509Extension extension =
                extensions.getExtension(X509Extension.keyUsage);
        return (extension != null) ? getKeyUsage(extension) : null;
    }

    /**
     * Gets a boolean array representing bits of the KeyUsage extension.
     *
     * @throws IOException if failed to extract the KeyUsage extension value.
     * @see java.security.cert.X509Certificate#getKeyUsage
     */
    public static EnumSet<KeyUsage> getKeyUsage(X509Extension ext)
            throws IOException {
        DERBitString bits = (DERBitString) getExtensionObject(ext);
        EnumSet<KeyUsage> keyUsage = EnumSet.noneOf(KeyUsage.class);
        for (KeyUsage bit: KeyUsage.values()) {
            if (bit.isSet(bits)) {
                keyUsage.add(bit);
            }
        }
        return keyUsage;
    }

    /**
     * Extracts the value of a certificate extension.
     *
     * @param ext the certificate extension to extract the value from.
     * @throws IOException if extraction fails.
     */
    public static ASN1Primitive getExtensionObject(X509Extension ext)
            throws IOException {
        return toASN1Primitive(ext.getValue().getOctets());
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
        return toGlobusID(dn, true);
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
        if (dn == null) {
            return null;
        }

        StringBuilder buf = new StringBuilder();

        String[] tokens = dn.split(",");
        if (noreverse) {
            for (int i = 0; i < tokens.length; i++) {
                String token = tokens[i].trim();
                if (!token.isEmpty()) {
                    buf.append("/");
                    buf.append(token.trim());
                }
            }
        } else {
            for (int i = tokens.length - 1; i >= 0; i--) {
                String token = tokens[i].trim();
                if (!token.isEmpty()) {
                    buf.append("/");
                    buf.append(token.trim());
                }
            }
        }

        return buf.toString();
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
        if (name instanceof X509Name) {
            return X509NameHelper.toString((X509Name)name);
        } else if (name instanceof X500Principal) {
            return CertificateUtil.toGlobusID((X500Principal) name);
        } else {
            return CertificateUtil.toGlobusID(name.getName());
        }
    }

    /**
     * Converts DN of the form "CN=A, OU=B, O=C" into Globus format
     * "/O=C/OU=B/CN=A" <BR> This function might return incorrect
     * Globus-formatted ID when one of the RDNs in the DN contains commas.
     *
     * @return the converted DN in Globus format.
     */
    public static String toGlobusID(X500Principal principal) {

        if (principal == null) {
            return null;
        }

        String dn = principal.getName(X500Principal.RFC2253, OID_MAP);

        StringBuilder buf = new StringBuilder();

        final int IDLE = 0;
        final int VALUE = 1;
        final int KEY = 2;

        int state = IDLE;

        int cEnd = 0;
        char[] asChars = dn.toCharArray();
        /*
         * walk in reverse order and merge RDN
         */
        for (int i = asChars.length - 1; i >= 0; i--) {

            char c = asChars[i];
            switch (state) {
                case KEY:
                    if (c == ',') {
                        String s = dn.substring(i + 1, cEnd + 1);
                        buf.append('/').append(s);
                        state = IDLE;
                    }
                    break;
                case VALUE:
                    if (c == '=') {
                        state = KEY;
                    }
                    break;
                case IDLE:
                default:
                    cEnd = i;
                    state = VALUE;
            }
        }

        String s = dn.substring(0, cEnd + 1);
        buf.append('/').append(s);

        // remove comma escaping as some other components may use string comparison.
        return buf.toString().replace("\\,", ",");
    }

    /**
     * Converts Globus DN format "/O=C/OU=B/CN=A" into an X500Principal
     * representation, which accepts RFC 2253 or 1779 formatted DN's and also
     * attribute types as defined in RFC 2459 (e.g. "CN=A,OU=B,O=C"). This
     * method should allow the forward slash, "/", to occur in attribute values
     * (see GFD.125 section 3.2.2 -- RFC 2252 allows "/" in PrintableStrings).
     * @param globusID DN in Globus format
     * @return the X500Principal representation of the given DN
     */
    public static X500Principal toPrincipal(String globusID) {

        if (globusID == null) {
            return null;
        }
        String id = globusID.trim();
        StringBuilder buf = new StringBuilder(id.length());

        if (!id.isEmpty()) {

            final int IDLE = 0;
            final int VALUE = 1;
            final int KEY = 2;

            int state = IDLE;

            int cEnd = 0;
            char[] asChars = id.toCharArray();

            /*
             * walk in reverse order and split into RDN
             */
            for (int i = asChars.length - 1; i >= 0; i--) {

                char c = asChars[i];
                switch (state) {
                    case KEY:
                        if (c == '/' || c == ' ') {
                            /*
                              handle names with comma according rfc1779
                             */
                            String s = id.substring(i + 1, cEnd + 1);
                            int commaIndex = s.indexOf(',');
                            if (commaIndex != -1) {
                                s = s.substring(0, commaIndex) + "\\" + s.substring(commaIndex);
                            }
                            buf.append(s).append(',');
                            state = IDLE;
                        }
                        break;
                    case VALUE:
                        if (c == '=') {
                            state = KEY;
                        }
                        break;
                    case IDLE:
                    default:
                        // idle
                        if (c == '/' || c == ' ') {
                            continue;
                        } else {
                            cEnd = i;
                            state = VALUE;
                        }
                }
            }

            // delete last extra comma
            buf.deleteCharAt(buf.length() - 1);
        }

        String dn = buf.toString();

        return new X500Principal(dn, KEYWORD_MAP);
    }

    // JGLOBUS-91
    public static CertPath getCertPath(X509Certificate[] certs) throws CertificateException {

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return factory.generateCertPath(Arrays.asList(certs));
    }


}
