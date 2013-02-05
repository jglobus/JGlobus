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

import java.security.Provider;



import org.globus.common.CoGProperties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

import java.security.KeyPairGenerator;

import java.security.GeneralSecurityException;

import java.security.KeyPair;

import java.security.Principal;

import org.globus.gsi.bc.X509NameHelper;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.StringTokenizer;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;

import java.security.cert.CertificateFactory;
import java.security.cert.CertPath;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERString;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.globus.gsi.GSIConstants;
import org.globus.gsi.proxy.ext.ProxyCertInfo;
import org.globus.gsi.proxy.ext.ProxyPolicy;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public final class CertificateUtil {

    public static final int DIGITAL_SIGNATURE = 0;
    public static final int NON_REPUDIATION = 1;
    public static final int KEY_ENCIPHERMENT = 2;
    public static final int DATA_ENCIPHERMENT = 3;
    public static final int KEY_AGREEMENT = 4;
    public static final int KEY_CERTSIGN = 5;
    public static final int CRL_SIGN = 6;
    public static final int ENCIPHER_ONLY = 7;
    public static final int DECIPHER_ONLY = 8;
    public static final int DEFAULT_USAGE_LENGTH = 9;

    private static String provider;
    private static Log logger;

    static {
        Security.addProvider(new BouncyCastleProvider());
        setProvider("BC");
        logger = LogFactory.getLog(CertificateLoadUtil.class.getCanonicalName());
        installSecureRandomProvider();
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
     * @return
     * @throws IOException
     */
    public static int getCAPathConstraint(TBSCertificateStructure crt)
            throws IOException {

        X509Extensions extensions = crt.getExtensions();
        if (extensions == null) {
            return -1;
        }
        X509Extension proxyExtension =
                extensions.getExtension(X509Extensions.BasicConstraints);
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
     * certificate type is {@link org.globus.gsi.GSIGSIConstants.CertificateType#CA
     * CertificateType.CA} <B>only</B> if the certificate contains a
     * BasicConstraints extension and it is marked as CA.<BR> A certificate is a
     * GSI-2 proxy when the subject DN of the certificate ends with
     * <I>"CN=proxy"</I> (certificate type {@link org.globus.gsi.GSIGSIConstants.CertificateType#GSI_2_PROXY
     * CertificateType.GSI_2_PROXY}) or <I>"CN=limited proxy"</I> (certificate
     * type {@link org.globus.gsi.GSIGSIConstants.CertificateType#GSI_2_LIMITED_PROXY
     * CertificateType.LIMITED_PROXY}) component and the issuer DN of the
     * certificate matches the subject DN without the last proxy <I>CN</I>
     * component.<BR> A certificate is a GSI-3 proxy when the subject DN of the
     * certificate ends with a <I>CN</I> component, the issuer DN of the
     * certificate matches the subject DN without the last <I>CN</I> component
     * and the certificate contains {@link org.globus.security.proxyExtension.ProxyCertInfo
     * ProxyCertInfo} critical extension. The certificate type is {@link
     * org.globus.gsi.GSIGSIConstants.CertificateType#GSI_3_IMPERSONATION_PROXY
     * CertificateType.GSI_3_IMPERSONATION_PROXY} if the policy language of the
     * {@link org.globus.security.proxyExtension.ProxyCertInfo ProxyCertInfo}
     * extension is set to {@link org.globus.security.proxyExtension.ProxyPolicy#IMPERSONATION
     * ProxyPolicy.IMPERSONATION} OID. The certificate type is {@link
     * org.globus.gsi.GSIGSIConstants.CertificateType#GSI_3_LIMITED_PROXY
     * CertificateType.GSI_3_LIMITED_PROXY} if the policy language of the {@link
     * org.globus.security.proxyExtension.ProxyCertInfo ProxyCertInfo} extension
     * is set to {@link org.globus.security.proxyExtension.ProxyPolicy#LIMITED
     * ProxyPolicy.LIMITED} OID. The certificate type is {@link
     * org.globus.gsi.GSIGSIConstants.CertificateType#GSI_3_INDEPENDENT_PROXY
     * CertificateType.GSI_3_INDEPENDENT_PROXY} if the policy language of the
     * {@link org.globus.security.proxyExtension.ProxyCertInfo ProxyCertInfo}
     * extension is set to {@link org.globus.security.proxyExtension.ProxyPolicy#INDEPENDENT
     * ProxyPolicy.INDEPENDENT} OID. The certificate type is {@link
     * org.globus.gsi.GSIGSIConstants.CertificateType#GSI_3_RESTRICTED_PROXY
     * CertificateType.GSI_3_RESTRICTED_PROXY} if the policy language of the
     * {@link org.globus.security.proxyExtension.ProxyCertInfo ProxyCertInfo}
     * extension is set to any other OID then the above.<BR> The certificate
     * type is {@link org.globus.gsi.GSIGSIConstants.CertificateType#EEC
     * CertificateType.EEC} if the certificate is not a CA certificate or a
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
            ext = extensions.getExtension(X509Extensions.BasicConstraints);
            if (ext != null) {
                BasicConstraints basicExt = getBasicConstraints(ext);
                if (basicExt.isCA()) {
                    return GSIConstants.CertificateType.CA;
                }
            }
        }

        GSIConstants.CertificateType type = GSIConstants.CertificateType.EEC;

        // does not handle multiple AVAs
        X509Name subject = crt.getSubject();

        ASN1Set entry = X509NameHelper.getLastNameEntry(subject);
        ASN1Sequence ava = (ASN1Sequence) entry.getObjectAt(0);
        if (X509Name.CN.equals(ava.getObjectAt(0))) {
            type = processCN(extensions, type, ava);
        }

        return type;
    }

    private static GSIConstants.CertificateType processCN(
            X509Extensions extensions, GSIConstants.CertificateType type, ASN1Sequence ava) throws CertificateException {
        X509Extension ext;
        String value = ((DERString) ava.getObjectAt(1)).getString();
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
        DERObjectIdentifier oid =
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
    public static DERObject toDERObject(byte[] data)
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
        DERObject obj = toDERObject(cert.getTBSCertificate());
        return TBSCertificateStructure.getInstance(obj);
    }

    public static boolean[] getKeyUsage(TBSCertificateStructure crt)
            throws IOException {
        X509Extensions extensions = crt.getExtensions();
        if (extensions == null) {
            return new boolean[0];
        }
        X509Extension extension =
                extensions.getExtension(X509Extensions.KeyUsage);
        return (extension != null) ? getKeyUsage(extension) : new boolean[0];
    }

    /**
     * Gets a boolean array representing bits of the KeyUsage extension.
     *
     * @throws IOException if failed to extract the KeyUsage extension value.
     * @see java.security.cert.X509Certificate#getKeyUsage
     */
    public static boolean[] getKeyUsage(X509Extension ext)
            throws IOException {
        DERBitString bits = (DERBitString) getExtensionObject(ext);

        // copied from X509CertificateObject
        byte[] bytes = bits.getBytes();
        int length = (bytes.length * 8) - bits.getPadBits();

        boolean[] keyUsage = new boolean[(length < DEFAULT_USAGE_LENGTH) ? DEFAULT_USAGE_LENGTH : length];

        for (int i = 0; i != length; i++) {
            keyUsage[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
        }

        return keyUsage;
    }

    /**
     * Extracts the value of a certificate extension.
     *
     * @param ext the certificate extension to extract the value from.
     * @throws IOException if extraction fails.
     */
    public static DERObject getExtensionObject(X509Extension ext)
            throws IOException {
        return toDERObject(ext.getValue().getOctets());
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

        String dn = principal.getName();

        StringBuilder buf = new StringBuilder();

        String[] tokens = dn.split(",");
        for (int i = tokens.length - 1; i >= 0; i--) {
            String token = tokens[i].trim();
            if (!token.isEmpty()) {
                buf.append("/");
                buf.append(token);
            }
        }

        return buf.toString();
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
        StringBuilder buf = new StringBuilder();

        if (!id.isEmpty()) {
            String[] tokens = id.split("/");
            Deque<String> rdnList = new ArrayDeque<String>(tokens.length);

            for (String token: tokens) {
                if (!token.trim().isEmpty()) {
                    if (token.contains("=")) {
                        // prepend an RDN type and at least part of its value
                        rdnList.addFirst(token);
                    } else {
                        // insert part of an RDN value that was mistakenly removed
                        // as a result of tokenizing on forward slash
                        rdnList.addFirst(rdnList.removeFirst() + "/" + token);
                    }
                }
            }

            for (String rdn : rdnList) {
                buf.append(rdn.trim());
                buf.append(",");
            }

            // delete extra comma
            buf.deleteCharAt(buf.length() - 1);
        }

        String dn = buf.toString();

        return new X500Principal(dn);
    }

    // JGLOBUS-91 
    public static CertPath getCertPath(X509Certificate[] certs) throws CertificateException {

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return factory.generateCertPath(Arrays.asList(certs));
    }

    
}
