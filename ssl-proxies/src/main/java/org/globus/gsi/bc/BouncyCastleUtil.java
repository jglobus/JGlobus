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
package org.globus.gsi.bc;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.globus.gsi.GSIConstants;
import org.globus.gsi.TrustedCertificates;
import org.globus.gsi.TrustedCertificatesUtil;
import org.globus.gsi.proxy.ext.ProxyCertInfo;
import org.globus.gsi.proxy.ext.ProxyPolicy;
import org.globus.gsi.util.ProxyCertificateUtil;
import org.globus.util.I18n;

// COMMENT: BCB: removed methods createCertificateType(...) that took a TBSCertificateStructure as parameter
/**
 * A collection of various utility functions.
 */
public class BouncyCastleUtil {

    static {
	Security.addProvider(new BouncyCastleProvider());
    }

    private static I18n i18n =
        I18n.getI18n("org.globus.gsi.errors",
                     BouncyCastleUtil.class.getClassLoader());

    /**
     * Converts given <code>DERObject</code> into
     * a DER-encoded byte array.
     *
     * @param obj DERObject to convert.
     * @return the DER-encoded byte array
     * @exception IOException if conversion fails
     */
    public static byte[] toByteArray(ASN1Primitive obj)
	throws IOException {
	ByteArrayOutputStream bout = new ByteArrayOutputStream();
	DEROutputStream der = new DEROutputStream(bout);
	der.writeObject(obj);
	return bout.toByteArray();
    }

    /**
     * Converts the DER-encoded byte array into a
     * <code>DERObject</code>.
     *
     * @param data the DER-encoded byte array to convert.
     * @return the DERObject.
     * @exception IOException if conversion fails
     */
    public static ASN1Primitive toASN1Primitive(byte[] data)
	throws IOException {
        ByteArrayInputStream inStream = new ByteArrayInputStream(data);
        ASN1InputStream derInputStream = new ASN1InputStream(inStream);
        return derInputStream.readObject();
    }



    /**
     * Replicates a given <code>DERObject</code>.
     *
     * @param obj the DERObject to replicate.
     * @return a copy of the DERObject.
     * @exception IOException if replication fails
     */
    public static ASN1Primitive duplicate(ASN1Primitive obj)
	throws IOException {
	return toASN1Primitive(toByteArray(obj));
    }

    /**
     * Extracts the TBS certificate from the given certificate.
     *
     * @param cert the X.509 certificate to extract the TBS certificate from.
     * @return the TBS certificate
     * @exception IOException if extraction fails.
     * @exception CertificateEncodingException if extraction fails.
     */
    public static TBSCertificateStructure getTBSCertificateStructure(X509Certificate cert)
	throws CertificateEncodingException, IOException {
	ASN1Primitive obj = BouncyCastleUtil.toASN1Primitive(cert.getTBSCertificate());
	return TBSCertificateStructure.getInstance(obj);
    }

    /**
     * Extracts the value of a certificate extension.
     *
     * @param ext the certificate extension to extract the value from.
     * @exception IOException if extraction fails.
     */
    public static ASN1Primitive getExtensionObject(X509Extension ext)
	throws IOException {
	return toASN1Primitive(ext.getValue().getOctets());
    }

    /**
     * Returns certificate type of the given certificate.
     * Please see {@link #getCertificateType(TBSCertificateStructure,
     * TrustedCertificates) getCertificateType} for details for
     * determining the certificate type.
     *
     * @param cert the certificate to get the type of.
     * @param trustedCerts the trusted certificates to double check the
     *                     {@link GSIConstants#EEC GSIConstants.EEC}
     *                     certificate against.
     * @return the certificate type as determined by
     *             {@link #getCertificateType(TBSCertificateStructure,
     *              TrustedCertificates) getCertificateType}.
     * @exception CertificateException if something goes wrong.
     * @deprecated
     */
    public static GSIConstants.CertificateType getCertificateType(X509Certificate cert,
					 TrustedCertificates trustedCerts)
	throws CertificateException {
        try {
            return getCertificateType(cert, TrustedCertificatesUtil.createCertStore(trustedCerts));
	} catch (Exception e) {
	    throw new CertificateException("", e);
	}
    }

    /**
     * Returns the certificate type of the given certificate.
     * Please see {@link #getCertificateType(TBSCertificateStructure,
     * TrustedCertificates) getCertificateType} for details for
     * determining the certificate type.
     *
     * @param cert the certificate to get the type of.
     * @param trustedCerts the trusted certificates to double check the
     *                     {@link GSIConstants#EEC GSIConstants.EEC}
     *                     certificate against.
     * @return the certificate type as determined by
     *             {@link #getCertificateType(TBSCertificateStructure,
     *              TrustedCertificates) getCertificateType}.
     * @exception CertificateException if something goes wrong.
     */
    public static GSIConstants.CertificateType getCertificateType(X509Certificate cert, CertStore trustedCerts)
    throws CertificateException {
        try {
            TBSCertificateStructure crt = getTBSCertificateStructure(cert);
            GSIConstants.CertificateType type = getCertificateType(crt);

            // check subject of the cert in trusted cert list
            // to make sure the cert is not a ca cert
            if (type == GSIConstants.CertificateType.EEC) {
                X509CertSelector selector = new X509CertSelector();
                selector.setSubject(cert.getSubjectX500Principal());
                Collection c = trustedCerts.getCertificates(selector);
                if (c != null && c.size() > 0) {
                    type = GSIConstants.CertificateType.CA;
                }
            }
            return type;
        } catch (Exception e) {
            // but this should not happen
            throw new CertificateException("", e);
        }
    }

    /**
     * Returns certificate type of the given certificate.
     * Please see {@link #getCertificateType(TBSCertificateStructure)
     * getCertificateType} for details for determining the certificate type.
     *
     * @param cert the certificate to get the type of.
     * @return the certificate type as determined by
     *             {@link #getCertificateType(TBSCertificateStructure)
     *              getCertificateType}.
     * @exception CertificateException if something goes wrong.
     */
    public static GSIConstants.CertificateType getCertificateType(X509Certificate cert)
    throws CertificateException {
    try {
        TBSCertificateStructure crt = getTBSCertificateStructure(cert);
        return getCertificateType(crt);
    } catch (IOException e) {
        // but this should not happen
        throw new CertificateException("", e);
    }
    }

	public static GSIConstants.CertificateType getCertificateType(TBSCertificateStructure crt, TrustedCertificates trustedCerts)
			throws CertificateException, IOException {
		GSIConstants.CertificateType type = getCertificateType(crt);

		// check subject of the cert in trusted cert list
		// to make sure the cert is not a ca cert
		if (type == GSIConstants.CertificateType.EEC) {
			if (trustedCerts == null) {
				trustedCerts = TrustedCertificates.getDefaultTrustedCertificates();
			}
			if (trustedCerts != null && trustedCerts.getCertificate(crt.getSubject().toString()) != null) {
				type = GSIConstants.CertificateType.CA;
			}
		}

		return type;
	}

    /**
     * Returns certificate type of the given TBS certificate. <BR>
     * The certificate type is {@link GSIConstants#CA GSIConstants.CA}
     * <B>only</B> if the certificate contains a
     * BasicConstraints extension and it is marked as CA.<BR>
     * A certificate is a GSI-2 proxy when the subject DN of the certificate
     * ends with <I>"CN=proxy"</I> (certificate type {@link
     * GSIConstants#GSI_2_PROXY GSIConstants.GSI_2_PROXY}) or
     * <I>"CN=limited proxy"</I> (certificate type {@link
     * GSIConstants#GSI_2_LIMITED_PROXY GSIConstants.LIMITED_PROXY}) component
     * and the issuer DN of the certificate matches the subject DN without
     * the last proxy <I>CN</I> component.<BR>
     * A certificate is a GSI-3 proxy when the subject DN of the certificate
     * ends with a <I>CN</I> component, the issuer DN of the certificate
     * matches the subject DN without the last <I>CN</I> component and
     * the certificate contains {@link ProxyCertInfo ProxyCertInfo} critical
     * extension.
     * The certificate type is {@link GSIConstants#GSI_3_IMPERSONATION_PROXY
     * GSIConstants.GSI_3_IMPERSONATION_PROXY} if the policy language of
     * the {@link ProxyCertInfo ProxyCertInfo} extension is set to
     * {@link ProxyPolicy#IMPERSONATION ProxyPolicy.IMPERSONATION} OID.
     * The certificate type is {@link GSIConstants#GSI_3_LIMITED_PROXY
     * GSIConstants.GSI_3_LIMITED_PROXY} if the policy language of
     * the {@link ProxyCertInfo ProxyCertInfo} extension is set to
     * {@link ProxyPolicy#LIMITED ProxyPolicy.LIMITED} OID.
     * The certificate type is {@link GSIConstants#GSI_3_INDEPENDENT_PROXY
     * GSIConstants.GSI_3_INDEPENDENT_PROXY} if the policy language of
     * the {@link ProxyCertInfo ProxyCertInfo} extension is set to
     * {@link ProxyPolicy#INDEPENDENT ProxyPolicy.INDEPENDENT} OID.
     * The certificate type is {@link GSIConstants#GSI_3_RESTRICTED_PROXY
     * GSIConstants.GSI_3_RESTRICTED_PROXY} if the policy language of
     * the {@link ProxyCertInfo ProxyCertInfo} extension is set to
     * any other OID then the above.<BR>
     * The certificate type is {@link GSIConstants#EEC GSIConstants.EEC}
     * if the certificate is not a CA certificate or a GSI-2 or GSI-3 proxy.
     *
     * @param crt the TBS certificate to get the type of.
     * @return the certificate type. The certificate type is determined
     *         by rules described above.
     * @exception IOException if something goes wrong.
     * @exception CertificateException for proxy certificates, if
     *            the issuer DN of the certificate does not match
     *            the subject DN of the certificate without the
     *            last <I>CN</I> component. Also, for GSI-3 proxies
     *            when the <code>ProxyCertInfo</code> extension is
     *            not marked as critical.
     */
    private static GSIConstants.CertificateType getCertificateType(TBSCertificateStructure crt)
	throws CertificateException, IOException {
	X509Extensions extensions = crt.getExtensions();
	X509Extension ext = null;

	if (extensions != null) {
	    ext = extensions.getExtension(X509Extension.basicConstraints);
	    if (ext != null) {
		BasicConstraints basicExt = BasicConstraints.getInstance(ext);
		if (basicExt.isCA()) {
		    return GSIConstants.CertificateType.CA;
		}
	    }
	}

	GSIConstants.CertificateType type = GSIConstants.CertificateType.EEC;

	// does not handle multiple AVAs
	X500Name subject = crt.getSubject();

	ASN1Set entry = X509NameHelper.getLastNameEntry(subject);
	ASN1Sequence ava = (ASN1Sequence)entry.getObjectAt(0);
	if (BCStyle.CN.equals(ava.getObjectAt(0))) {
	    String value = ((ASN1String)ava.getObjectAt(1)).getString();
	    if (value.equalsIgnoreCase("proxy")) {
		type = GSIConstants.CertificateType.GSI_2_PROXY;
	    } else if (value.equalsIgnoreCase("limited proxy")) {
		type = GSIConstants.CertificateType.GSI_2_LIMITED_PROXY;
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
			ProxyCertInfo proxyCertExt = getProxyCertInfo(ext);
                        ProxyPolicy proxyPolicy =
                            proxyCertExt.getProxyPolicy();
                        ASN1ObjectIdentifier oid =
                            proxyPolicy.getPolicyLanguage();
			if (ProxyPolicy.IMPERSONATION.equals(oid)) {
                            if (gsi4) {
                                type = GSIConstants.CertificateType.GSI_4_IMPERSONATION_PROXY;
                            } else {
                                type = GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY;
                            }
			} else if (ProxyPolicy.INDEPENDENT.equals(oid)) {
                            if (gsi4) {
                                type = GSIConstants.CertificateType.GSI_4_INDEPENDENT_PROXY;
                            } else {
                                type = GSIConstants.CertificateType.GSI_3_INDEPENDENT_PROXY;
                            }
			} else if (ProxyPolicy.LIMITED.equals(oid)) {
                            if (gsi4) {
                                type = GSIConstants.CertificateType.GSI_4_LIMITED_PROXY;
                            } else {
                                type = GSIConstants.CertificateType.GSI_3_LIMITED_PROXY;
                            }
			} else {
                            if (gsi4) {
                                type = GSIConstants.CertificateType.GSI_4_RESTRICTED_PROXY;
                            } else {
                                type = GSIConstants.CertificateType.GSI_3_RESTRICTED_PROXY;
                            }
			}

		    } else {
                        String err = i18n.getMessage("proxyCertCritical");
			throw new CertificateException(err);
		    }
		}
	    }

	    if (ProxyCertificateUtil.isProxy(type)) {
		X509NameHelper iss = new X509NameHelper(crt.getIssuer());
		iss.add((ASN1Set)BouncyCastleUtil.duplicate(entry));
		X509Name issuer = iss.getAsName();
		if (!issuer.equals(X509Name.getInstance(subject))) {
                    String err = i18n.getMessage("proxyDNErr");
		    throw new CertificateException(err);
		}
	    }
	}

	return type;
    }

    /**
     * Gets a boolean array representing bits of the KeyUsage extension.
     *
     * @see java.security.cert.X509Certificate#getKeyUsage
     * @exception IOException if failed to extract the KeyUsage extension value.
     */
    public static boolean[] getKeyUsage(X509Extension ext)
	throws IOException {
	DERBitString bits = (DERBitString)getExtensionObject(ext);

	// copied from X509CertificateObject
	byte [] bytes = bits.getBytes();
	int length = (bytes.length * 8) - bits.getPadBits();

	boolean[]  keyUsage = new boolean[(length < 9) ? 9 : length];

	for (int i = 0; i != length; i++) {
	    keyUsage[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
	}

	return keyUsage;
    }

    /**
     * Creates a <code>ProxyCertInfo</code> object from given
     * extension.
     *
     * @param ext the extension.
     * @return the <code>ProxyCertInfo</code> object.
     * @exception IOException if something fails.
     */
    public static ProxyCertInfo getProxyCertInfo(X509Extension ext)
	throws IOException {
	return ProxyCertInfo.getInstance(BouncyCastleUtil.getExtensionObject(ext));
    }

    /**
     * Returns the subject DN of the given certificate in the Globus format.
     *
     * @param cert the certificate to get the subject of. The certificate
     *             must be of <code>X509CertificateObject</code> type.
     * @return the subject DN of the certificate in the Globus format.
     */
    public static String getIdentity(X509Certificate cert) {
    	if (cert == null) {
    		return null;
    	}

    	String subjectDN = cert.getSubjectX500Principal().getName(X500Principal.RFC2253);
    	X509Name name = new X509Name(true, subjectDN);
	    return X509NameHelper.toString(name);
    }

    public static String getIdentityPrefix(X509Certificate cert) {
    	if (cert == null) {
    		return null;
    	}

    	String subjectDN = cert.getSubjectX500Principal().getName(X500Principal.RFC2253);
    	LdapName ldapname = null;
		try {
			ldapname = new LdapName(subjectDN);
			ldapname.remove(ldapname.size() - 1);
		} catch (InvalidNameException e) {
			return null;
		}
    	X509Name name = new X509Name(true, ldapname.toString());
	    return X509NameHelper.toString(name);
    }

    /**
     * Finds the identity certificate in the given chain and
     * returns the subject DN of that certificate in the Globus format.
     *
     * @param chain the certificate chain to find the identity
     *              certificate in. The certificates must be
     *              of <code>X509CertificateObject</code> type.
     * @return the subject DN of the identity certificate in
     *         the Globus format.
     * @exception CertificateException if something goes wrong.
     */
    public static String getIdentity(X509Certificate [] chain)
	throws CertificateException {
	return getIdentity(getIdentityCertificate(chain));
    }

    /**
     * Finds the identity certificate in the given chain.
     * The identity certificate is the first certificate in the
     * chain that is not an impersonation proxy (full or limited)
     *
     * @param chain the certificate chain to find the identity
     *              certificate in.
     * @return the identity certificate.
     * @exception CertificateException if something goes wrong.
     */
    public static X509Certificate getIdentityCertificate(X509Certificate [] chain)
	throws CertificateException {
	if (chain == null) {
	    throw new IllegalArgumentException(i18n.getMessage("certChainNull"));
	}
	GSIConstants.CertificateType certType;
	for (int i=0;i<chain.length;i++) {
	    certType = getCertificateType(chain[i]);
	    if (!ProxyCertificateUtil.isImpersonationProxy(certType)) {
		return chain[i];
	    }
	}
	return null;
    }

    /**
     * Retrieves the actual value of the X.509 extension.
     *
     * @param certExtValue the DER-encoded OCTET string value of the extension.
     * @return the decoded/actual value of the extension (the octets).
     */
    public static byte[] getExtensionValue(byte [] certExtValue)
	throws IOException {
	ByteArrayInputStream inStream = new ByteArrayInputStream(certExtValue);
	ASN1InputStream derInputStream = new ASN1InputStream(inStream);
        ASN1Primitive object = derInputStream.readObject();
	if (object instanceof ASN1OctetString) {
	    return ((ASN1OctetString)object).getOctets();
	} else {
	    throw new IOException(i18n.getMessage("octectExp"));
	}
    }

    /**
     * Returns the actual value of the extension.
     *
     * @param cert the certificate that contains the extensions to retrieve.
     * @param oid the oid of the extension to retrieve.
     * @return the actual value of the extension (not octet string encoded)
     * @exception IOException if decoding the extension fails.
     */
    public static byte[] getExtensionValue(X509Certificate cert, String oid)
    throws IOException {
    if (cert == null) {
        throw new IllegalArgumentException(i18n.getMessage("certNull"));
    }
    if (oid == null) {
        throw new IllegalArgumentException(i18n.getMessage("oidNull"));
    }

    byte [] value = cert.getExtensionValue(oid);
    if (value == null) {
        return null;
    }

    return getExtensionValue(value);
    }

    public static int getProxyPathConstraint(X509Certificate cert)
            throws IOException, CertificateEncodingException {

        TBSCertificateStructure crt = getTBSCertificateStructure(cert);
        return getProxyPathConstraint(crt);
    }


    public static int getProxyPathConstraint(TBSCertificateStructure crt)
        throws IOException {

        ProxyCertInfo proxyCertExt = getProxyCertInfo(crt);
        return (proxyCertExt != null) ? proxyCertExt.getPathLenConstraint() :
            -1;
    }

    public static ProxyCertInfo getProxyCertInfo(TBSCertificateStructure crt)
	throws IOException {

	X509Extensions extensions = crt.getExtensions();
	if (extensions == null) {
	    return null;
	}
	X509Extension ext =
	    extensions.getExtension(ProxyCertInfo.OID);
        if (ext == null) {
            ext = extensions.getExtension(ProxyCertInfo.OLD_OID);
        }
	return (ext != null) ? BouncyCastleUtil.getProxyCertInfo(ext) : null;
    }

}
