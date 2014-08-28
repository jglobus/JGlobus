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

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.globus.gsi.util.CertificateLoadUtil;
import org.globus.gsi.util.ProxyCertificateUtil;

import org.globus.gsi.X509Credential;

import org.globus.gsi.VersionUtil;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.util.Random;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.Iterator;
import java.util.Calendar;
import java.io.InputStream;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import org.globus.util.I18n;
import org.globus.gsi.GlobusCredential;
import org.globus.gsi.GSIConstants;
import org.globus.gsi.X509ExtensionSet;
import org.globus.gsi.proxy.ext.ProxyCertInfo;
import org.globus.gsi.proxy.ext.ProxyPolicy;
import org.globus.gsi.proxy.ext.ProxyCertInfoExtension;
import org.globus.gsi.proxy.ext.GlobusProxyCertInfoExtension;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.KeyUsage;

/**
 * Provides certificate processing API such as creating new certificates, certificate requests, etc.
 */
public class BouncyCastleCertProcessingFactory {

    private static I18n i18n = I18n.getI18n("org.globus.gsi.errors", BouncyCastleCertProcessingFactory.class
        .getClassLoader());

    private static BouncyCastleCertProcessingFactory factory;

    protected BouncyCastleCertProcessingFactory() {
    }

    /**
     * Returns an instance of this class..
     *
     * @return <code>BouncyCastleCertProcessingFactory</code> instance.
     */
    public static synchronized BouncyCastleCertProcessingFactory getDefault() {
        if (factory == null) {
            factory = new BouncyCastleCertProcessingFactory();
        }
        return factory;
    }

    /**
     * Creates a proxy certificate from the certificate request.
     *
     * @see #createCertificate(InputStream, X509Certificate, PrivateKey, int, int, X509ExtensionSet, String)
     *      createCertificate
     * @deprecated
     */
    public X509Certificate createCertificate(InputStream certRequestInputStream, X509Certificate cert,
        PrivateKey privateKey, int lifetime, int delegationMode) throws IOException, GeneralSecurityException {
        return createCertificate(certRequestInputStream, cert, privateKey, lifetime, delegationMode,
            (X509ExtensionSet) null, null);
    }

    /**
     * Creates a proxy certificate from the certificate request.
     *
     * @see #createCertificate(InputStream, X509Certificate, PrivateKey, int, int, X509ExtensionSet, String)
     *      createCertificate
     * @deprecated
     */
    public X509Certificate createCertificate(InputStream certRequestInputStream, X509Certificate cert,
        PrivateKey privateKey, int lifetime, int delegationMode, X509ExtensionSet extSet) throws IOException,
        GeneralSecurityException {
        return createCertificate(certRequestInputStream, cert, privateKey, lifetime, delegationMode, extSet, null);
    }

    /**
     * Creates a proxy certificate from the certificate request. (Signs a certificate request creating a new
     * certificate)
     *
     * @see #createProxyCertificate(X509Certificate, PrivateKey, PublicKey, int, int, X509ExtensionSet,
     *      String) createProxyCertificate
     * @param certRequestInputStream
     *            the input stream to read the certificate request from.
     * @param cert
     *            the issuer certificate
     * @param privateKey
     *            the private key to sign the new certificate with.
     * @param lifetime
     *            lifetime of the new certificate in seconds. If 0 (or less then) the new certificate will
     *            have the same lifetime as the issuing certificate.
     * @param delegationMode
     *            the type of proxy credential to create
     * @param extSet
     *            a set of X.509 extensions to be included in the new proxy certificate. Can be null. If
     *            delegation mode is {@link org.globus.gsi.GSIConstants.CertificateType#GSI_3_RESTRICTED_PROXY
     *            GSIConstants.CertificateType.GSI_3_RESTRICTED_PROXY} or {@link org.globus.gsi.GSIConstants.CertificateType#GSI_4_RESTRICTED_PROXY
     *            GSIConstants.CertificateType.GSI_4_RESTRICTED_PROXY} then
     *            {@link org.globus.gsi.proxy.ext.ProxyCertInfoExtension ProxyCertInfoExtension} must be
     *            present in the extension set.
     * @param cnValue
     *            the value of the CN component of the subject of the new certificate. If null, the defaults
     *            will be used depending on the proxy certificate type created.
     * @return <code>X509Certificate</code> the new proxy certificate
     * @exception IOException
     *                if error reading the certificate request
     * @exception GeneralSecurityException
     *                if a security error occurs.
     * @deprecated
     */
    public X509Certificate createCertificate(InputStream certRequestInputStream, X509Certificate cert,
        PrivateKey privateKey, int lifetime, int delegationMode, X509ExtensionSet extSet, String cnValue)
        throws IOException, GeneralSecurityException {

        ASN1InputStream derin = new ASN1InputStream(certRequestInputStream);
        ASN1Primitive reqInfo = derin.readObject();
        PKCS10CertificationRequest certReq = new PKCS10CertificationRequest((ASN1Sequence) reqInfo);

        boolean rs = certReq.verify();

        if (!rs) {
            String err = i18n.getMessage("certReqVerification");
            throw new GeneralSecurityException(err);
        }

        return createProxyCertificate(cert, privateKey, certReq.getPublicKey(), lifetime, delegationMode, extSet,
            cnValue);
    }

    /**
     * Creates a new proxy credential from the specified certificate chain and a private key.
     *
     * @see #createCredential(X509Certificate[], PrivateKey, int, int, int, X509ExtensionSet, String)
     *      createCredential
     * @deprecated
     */
    public GlobusCredential createCredential(X509Certificate[] certs, PrivateKey privateKey, int bits, int lifetime,
        int delegationMode) throws GeneralSecurityException {
        return createCredential(certs, privateKey, bits, lifetime, delegationMode, (X509ExtensionSet) null, null);
    }

    /**
     * Creates a new proxy credential from the specified certificate chain and a private key.
     *
     * @see #createCredential(X509Certificate[], PrivateKey, int, int, int, X509ExtensionSet, String)
     *      createCredential
     * @deprecated
     */
    public GlobusCredential createCredential(X509Certificate[] certs, PrivateKey privateKey, int bits, int lifetime,
        int delegationMode, X509ExtensionSet extSet) throws GeneralSecurityException {
        return createCredential(certs, privateKey, bits, lifetime, delegationMode, extSet, null);
    }

    /**
     * Creates a new proxy credential from the specified certificate chain and a private key. A set of X.509
     * extensions can be optionally included in the new proxy certificate. This function automatically creates
     * a "RSA"-based key pair.
     *
     * @see #createProxyCertificate(X509Certificate, PrivateKey, PublicKey, int, int, X509ExtensionSet,
     *      String) createProxyCertificate
     * @param certs
     *            the certificate chain for the new proxy credential. The top-most certificate
     *            <code>cert[0]</code> will be designated as the issuing certificate.
     * @param privateKey
     *            the private key of the issuing certificate. The new proxy certificate will be signed with
     *            that private key.
     * @param bits
     *            the strength of the key pair for the new proxy certificate.
     * @param lifetime
     *            lifetime of the new certificate in seconds. If 0 (or less then) the new certificate will
     *            have the same lifetime as the issuing certificate.
     * @param delegationMode
     *            the type of proxy credential to create
     * @param extSet
     *            a set of X.509 extensions to be included in the new proxy certificate. Can be null. If
     *            delegation mode is {@link org.globus.gsi.GSIConstants.CertificateType#GSI_3_RESTRICTED_PROXY
     *            GSIConstants.CertificateType.GSI_3_RESTRICTED_PROXY} or {@link org.globus.gsi.GSIConstants.CertificateType#GSI_4_RESTRICTED_PROXY
     *            GSIConstants.CertificateType.GSI_4_RESTRICTED_PROXY} then
     *            {@link org.globus.gsi.proxy.ext.ProxyCertInfoExtension ProxyCertInfoExtension} must be
     *            present in the extension set.
     * @param cnValue
     *            the value of the CN component of the subject of the new proxy credential. If null, the
     *            defaults will be used depending on the proxy certificate type created.
     * @return <code>GlobusCredential</code> the new proxy credential.
     * @exception GeneralSecurityException
     *                if a security error occurs.
     * @deprecated
     */
    public GlobusCredential createCredential(X509Certificate[] certs, PrivateKey privateKey, int bits, int lifetime,
        int delegationMode, X509ExtensionSet extSet, String cnValue) throws GeneralSecurityException {

        X509Certificate[] bcCerts = getX509CertificateObjectChain(certs);

        KeyPairGenerator keyGen = null;
        keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(bits);
        KeyPair keyPair = keyGen.genKeyPair();

        X509Certificate newCert = createProxyCertificate(bcCerts[0], privateKey, keyPair.getPublic(), lifetime,
            delegationMode, extSet, cnValue);

        X509Certificate[] newCerts = new X509Certificate[bcCerts.length + 1];
        newCerts[0] = newCert;
        System.arraycopy(certs, 0, newCerts, 1, certs.length);

        return new GlobusCredential(keyPair.getPrivate(), newCerts);
    }

    /**
     * Creates a proxy certificate. A set of X.509 extensions can be optionally included in the new proxy
     * certificate. <BR>
     * If a GSI-2 proxy is created, the serial number of the proxy certificate will be the same as of the
     * issuing certificate. Also, none of the extensions in the issuing certificate will be copied into the
     * proxy certificate.<BR>
     * If a GSI-3 or GSI 4 proxy is created, the serial number of the proxy certificate will be picked
     * randomly. If the issuing certificate contains a <i>KeyUsage</i> extension, the extension will be copied
     * into the proxy certificate with <i>keyCertSign</i> and <i>nonRepudiation</i> bits turned off. No other
     * extensions are currently copied.
     *
     * The methods defaults to creating GSI 4 proxy
     *
     * @param issuerCert_
     *            the issuing certificate
     * @param issuerKey
     *            private key matching the public key of issuer certificate. The new proxy certificate will be
     *            signed by that key.
     * @param publicKey
     *            the public key of the new certificate
     * @param lifetime
     *            lifetime of the new certificate in seconds. If 0 (or less then) the new certificate will
     *            have the same lifetime as the issuing certificate.
     * @param proxyType
     *            can be one of {@link GSIConstants#DELEGATION_LIMITED GSIConstants.DELEGATION_LIMITED},
     *            {@link GSIConstants#DELEGATION_FULL GSIConstants.DELEGATION_FULL},
     *
     *            {@link GSIConstants#GSI_2_LIMITED_PROXY GSIConstants.GSI_2_LIMITED_PROXY},
     *            {@link GSIConstants#GSI_2_PROXY GSIConstants.GSI_2_PROXY},
     *            {@link GSIConstants#GSI_3_IMPERSONATION_PROXY GSIConstants.GSI_3_IMPERSONATION_PROXY},
     *            {@link GSIConstants#GSI_3_LIMITED_PROXY GSIConstants.GSI_3_LIMITED_PROXY},
     *            {@link GSIConstants#GSI_3_INDEPENDENT_PROXY GSIConstants.GSI_3_INDEPENDENT_PROXY},
     *            {@link GSIConstants#GSI_3_RESTRICTED_PROXY GSIConstants.GSI_3_RESTRICTED_PROXY}.
     *            {@link GSIConstants#GSI_4_IMPERSONATION_PROXY GSIConstants.GSI_4_IMPERSONATION_PROXY},
     *            {@link GSIConstants#GSI_4_LIMITED_PROXY GSIConstants.GSI_3_LIMITED_PROXY},
     *            {@link GSIConstants#GSI_4_INDEPENDENT_PROXY GSIConstants.GSI_4_INDEPENDENT_PROXY},
     *            {@link GSIConstants#GSI_4_RESTRICTED_PROXY GSIConstants.GSI_4_RESTRICTED_PROXY}.
     *
     *            If {@link GSIConstants#DELEGATION_LIMITED GSIConstants.DELEGATION_LIMITED} and if
     *            {@link VersionUtil#isGsi2Enabled() CertUtil.isGsi2Enabled} returns true then a GSI-2 limited
     *            proxy will be created. Else if {@link VersionUtil#isGsi3Enabled() CertUtil.isGsi3Enabled}
     *            returns true then a GSI-3 limited proxy will be created. If not, a GSI-4 limited proxy will
     *            be created.
     *
     *            If {@link GSIConstants#DELEGATION_FULL GSIConstants.DELEGATION_FULL} and if
     *            {@link VersionUtil#isGsi2Enabled() CertUtil.isGsi2Enabled} returns true then a GSI-2 full proxy
     *            will be created. Else if {@link VersionUtil#isGsi3Enabled() CertUtil.isGsi3Enabled} returns
     *            true then a GSI-3 full proxy will be created. If not, a GSI-4 full proxy will be created.
     *
     * @param extSet
     *            a set of X.509 extensions to be included in the new proxy certificate. Can be null. If
     *            delegation mode is {@link GSIConstants#GSI_3_RESTRICTED_PROXY
     *            GSIConstants.GSI_3_RESTRICTED_PROXY} or {@link GSIConstants#GSI_4_RESTRICTED_PROXY
     *            GSIConstants.GSI_4_RESTRICTED_PROXY} then
     *            {@link org.globus.gsi.proxy.ext.ProxyCertInfoExtension ProxyCertInfoExtension} must be
     *            present in the extension set.
     *
     * @param cnValue
     *            the value of the CN component of the subject of the new certificate. If null, the defaults
     *            will be used depending on the proxy certificate type created.
     * @return <code>X509Certificate</code> the new proxy certificate.
     * @exception GeneralSecurityException
     *                if a security error occurs.
     * @deprecated
     */
    public X509Certificate createProxyCertificate(X509Certificate issuerCert_, PrivateKey issuerKey,
        PublicKey publicKey, int lifetime, int proxyType, X509ExtensionSet extSet, String cnValue)
        throws GeneralSecurityException {

        X509Certificate issuerCert = issuerCert_;
        if (!(issuerCert_ instanceof X509CertificateObject)) {
            issuerCert = CertificateLoadUtil.loadCertificate(new ByteArrayInputStream(issuerCert.getEncoded()));
        }

        if (proxyType == GSIConstants.DELEGATION_LIMITED) {
            GSIConstants.CertificateType type = BouncyCastleUtil.getCertificateType(issuerCert);
            if (ProxyCertificateUtil.isGsi4Proxy(type)) {
                proxyType = GSIConstants.GSI_4_LIMITED_PROXY;
            } else if (ProxyCertificateUtil.isGsi3Proxy(type)) {
                proxyType = GSIConstants.GSI_3_LIMITED_PROXY;
            } else if (ProxyCertificateUtil.isGsi2Proxy(type)) {
                proxyType = GSIConstants.GSI_2_LIMITED_PROXY;
            } else {
                // default to RFC compliant proxy
                if (VersionUtil.isGsi2Enabled()) {
                    proxyType = GSIConstants.GSI_2_LIMITED_PROXY;
                } else {
                    proxyType = VersionUtil.isGsi3Enabled() ? GSIConstants.GSI_3_LIMITED_PROXY
                        : GSIConstants.GSI_4_LIMITED_PROXY;
                }
            }
        } else if (proxyType == GSIConstants.DELEGATION_FULL) {
            GSIConstants.CertificateType type = BouncyCastleUtil.getCertificateType(issuerCert);
            if (ProxyCertificateUtil.isGsi4Proxy(type)) {
                proxyType = GSIConstants.GSI_4_IMPERSONATION_PROXY;
            } else if (ProxyCertificateUtil.isGsi3Proxy(type)) {
                proxyType = GSIConstants.GSI_3_IMPERSONATION_PROXY;
            } else if (ProxyCertificateUtil.isGsi2Proxy(type)) {
                proxyType = GSIConstants.GSI_2_PROXY;
            } else {
                // Default to RFC complaint proxy
                if (VersionUtil.isGsi2Enabled()) {
                    proxyType = GSIConstants.GSI_2_PROXY;
                } else {
                    proxyType = (VersionUtil.isGsi3Enabled()) ? GSIConstants.GSI_3_IMPERSONATION_PROXY
                        : GSIConstants.GSI_4_IMPERSONATION_PROXY;
                }
            }
        }

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        org.globus.gsi.X509Extension x509Ext = null;
        BigInteger serialNum = null;
        String delegDN = null;

        if (ProxyCertificateUtil.isGsi3Proxy(GSIConstants.CertificateType.get(proxyType)) ||
            ProxyCertificateUtil.isGsi4Proxy(GSIConstants.CertificateType.get(proxyType))) {
            Random rand = new Random();
            delegDN = String.valueOf(Math.abs(rand.nextInt()));
            serialNum = new BigInteger(20, rand);

            if (extSet != null) {
                x509Ext = extSet.get(ProxyCertInfo.OID.getId());
                if (x509Ext == null) {
                    x509Ext = extSet.get(ProxyCertInfo.OLD_OID.getId());
                }
            }

            if (x509Ext == null) {
                // create ProxyCertInfo extension
                ProxyPolicy policy = null;
                if (ProxyCertificateUtil.isLimitedProxy(GSIConstants.CertificateType.get(proxyType))) {
                    policy = new ProxyPolicy(ProxyPolicy.LIMITED);
                } else if (ProxyCertificateUtil.isIndependentProxy(GSIConstants.CertificateType.get(proxyType))) {
                    policy = new ProxyPolicy(ProxyPolicy.INDEPENDENT);
                } else if (ProxyCertificateUtil.isImpersonationProxy(GSIConstants.CertificateType.get(proxyType))) {
                    // since limited has already been checked, this should work.
                    policy = new ProxyPolicy(ProxyPolicy.IMPERSONATION);
                } else if ((proxyType == GSIConstants.GSI_3_RESTRICTED_PROXY)
                    || (proxyType == GSIConstants.GSI_4_RESTRICTED_PROXY)) {
                    String err = i18n.getMessage("restrictProxy");
                    throw new IllegalArgumentException(err);
                } else {
                    String err = i18n.getMessage("invalidProxyType");
                    throw new IllegalArgumentException(err);
                }

                ProxyCertInfo proxyCertInfo = new ProxyCertInfo(policy);
                x509Ext = new ProxyCertInfoExtension(proxyCertInfo);
                if (ProxyCertificateUtil.isGsi4Proxy(GSIConstants.CertificateType.get(proxyType))) {
                    // RFC compliant OID
                    x509Ext = new ProxyCertInfoExtension(proxyCertInfo);
                } else {
                    // old OID
                    x509Ext = new GlobusProxyCertInfoExtension(proxyCertInfo);
                }
            }

            try {
                // add ProxyCertInfo extension to the new cert
                certGen.addExtension(x509Ext.getOid(), x509Ext.isCritical(), x509Ext.getValue());

                // handle KeyUsage in issuer cert
                TBSCertificateStructure crt = BouncyCastleUtil.getTBSCertificateStructure(issuerCert);

                X509Extensions extensions = crt.getExtensions();
                if (extensions != null) {
                    X509Extension ext;

                    // handle key usage ext
                    ext = extensions.getExtension(X509Extension.keyUsage);
                    if (ext != null) {

                        // TBD: handle this better
                        if (extSet != null && (extSet.get(X509Extension.keyUsage.getId()) != null)) {
                            String err = i18n.getMessage("keyUsageExt");
                            throw new GeneralSecurityException(err);
                        }

                        DERBitString bits = (DERBitString) BouncyCastleUtil.getExtensionObject(ext);

                        byte[] bytes = bits.getBytes();

                        // make sure they are disabled
                        if ((bytes[0] & KeyUsage.nonRepudiation) != 0) {
                            bytes[0] ^= KeyUsage.nonRepudiation;
                        }

                        if ((bytes[0] & KeyUsage.keyCertSign) != 0) {
                            bytes[0] ^= KeyUsage.keyCertSign;
                        }

                        bits = new DERBitString(bytes, bits.getPadBits());

                        certGen.addExtension(X509Extension.keyUsage, ext.isCritical(), bits);
                    }
                }

            } catch (IOException e) {
                // but this should not happen
                throw new GeneralSecurityException(e.getMessage());
            }

        } else if (proxyType == GSIConstants.GSI_2_LIMITED_PROXY) {
            delegDN = "limited proxy";
            serialNum = issuerCert.getSerialNumber();
        } else if (proxyType == GSIConstants.GSI_2_PROXY) {
            delegDN = "proxy";
            serialNum = issuerCert.getSerialNumber();
        } else {
            String err = i18n.getMessage("unsupportedProxy", Integer.toString(proxyType));
            throw new IllegalArgumentException(err);
        }

        // add specified extensions
        if (extSet != null) {
            Iterator iter = extSet.oidSet().iterator();
            while (iter.hasNext()) {
                String oid = (String) iter.next();
                // skip ProxyCertInfo extension
                if (oid.equals(ProxyCertInfo.OID.getId()) || oid.equals(ProxyCertInfo.OLD_OID.getId())) {
                    continue;
                }
                x509Ext = (org.globus.gsi.X509Extension) extSet.get(oid);
                certGen.addExtension(x509Ext.getOid(), x509Ext.isCritical(), x509Ext.getValue());
            }
        }

        X509Name issuerDN;
        if (issuerCert.getSubjectDN() instanceof X509Name) {
        	issuerDN = (X509Name)issuerCert.getSubjectDN();
        } else {
        	issuerDN = new X509Name(true,issuerCert.getSubjectX500Principal().getName());
        }

        X509NameHelper issuer = new X509NameHelper(issuerDN);

        X509NameHelper subject = new X509NameHelper(issuerDN);
        subject.add(BCStyle.CN, (cnValue == null) ? delegDN : cnValue);

        certGen.setSubjectDN(subject.getAsName());
        certGen.setIssuerDN(issuer.getAsName());

        certGen.setSerialNumber(serialNum);
        certGen.setPublicKey(publicKey);
        certGen.setSignatureAlgorithm(issuerCert.getSigAlgName());

        GregorianCalendar date = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
        /* Allow for a five minute clock skew here. */
        date.add(Calendar.MINUTE, -5);
        certGen.setNotBefore(date.getTime());

        /* If hours = 0, then cert lifetime is set to user cert */
        if (lifetime <= 0) {
            certGen.setNotAfter(issuerCert.getNotAfter());
        } else {
            date.add(Calendar.MINUTE, 5);
            date.add(Calendar.SECOND, lifetime);
            certGen.setNotAfter(date.getTime());
        }



        return certGen.generateX509Certificate(issuerKey);
    }

    /**
     * Creates a proxy certificate from the certificate request.
     *
     * @see #createCertificate(InputStream, X509Certificate, PrivateKey, int, int, X509ExtensionSet, String)
     *      createCertificate
     */
    public X509Certificate createCertificate(InputStream certRequestInputStream, X509Certificate cert,
        PrivateKey privateKey, int lifetime, GSIConstants.CertificateType certType) throws IOException,
        GeneralSecurityException {
        return createCertificate(certRequestInputStream, cert, privateKey, lifetime, certType, (X509ExtensionSet) null,
            null);
    }

    /**
     * Creates a proxy certificate from the certificate request.
     *
     * @see #createCertificate(InputStream, X509Certificate, PrivateKey, int, GSIConstants.CertificateType, X509ExtensionSet, String)
     *      createCertificate
     */
    public X509Certificate createCertificate(InputStream certRequestInputStream, X509Certificate cert,
        PrivateKey privateKey, int lifetime, GSIConstants.CertificateType certType, X509ExtensionSet extSet)
        throws IOException, GeneralSecurityException {
        return createCertificate(certRequestInputStream, cert, privateKey, lifetime, certType, extSet, null);
    }

    /**
     * Creates a proxy certificate from the certificate request. (Signs a certificate request creating a new
     * certificate)
     *
     * @see #createProxyCertificate(X509Certificate, PrivateKey, PublicKey, int, int, X509ExtensionSet,
     *      String) createProxyCertificate
     * @param certRequestInputStream
     *            the input stream to read the certificate request from.
     * @param cert
     *            the issuer certificate
     * @param privateKey
     *            the private key to sign the new certificate with.
     * @param lifetime
     *            lifetime of the new certificate in seconds. If 0 (or less then) the new certificate will
     *            have the same lifetime as the issuing certificate.
     * @param certType
     *            the type of proxy credential to create
     * @param extSet
     *            a set of X.509 extensions to be included in the new proxy certificate. Can be null. If
     *            delegation mode is {@link org.globus.gsi.GSIConstants.CertificateType#GSI_3_RESTRICTED_PROXY
     *            GSIConstants.CertificateType.GSI_3_RESTRICTED_PROXY} or {@link org.globus.gsi.GSIConstants.CertificateType#GSI_4_RESTRICTED_PROXY
     *            GSIConstants.CertificateType.GSI_4_RESTRICTED_PROXY} then
     *            {@link org.globus.gsi.proxy.ext.ProxyCertInfoExtension ProxyCertInfoExtension} must be
     *            present in the extension set.
     * @param cnValue
     *            the value of the CN component of the subject of the new certificate. If null, the defaults
     *            will be used depending on the proxy certificate type created.
     * @return <code>X509Certificate</code> the new proxy certificate
     * @exception IOException
     *                if error reading the certificate request
     * @exception GeneralSecurityException
     *                if a security error occurs.
     */
    public X509Certificate createCertificate(InputStream certRequestInputStream, X509Certificate cert,
        PrivateKey privateKey, int lifetime, GSIConstants.CertificateType certType, X509ExtensionSet extSet,
        String cnValue) throws IOException, GeneralSecurityException {

        ASN1InputStream derin = new ASN1InputStream(certRequestInputStream);
        ASN1Primitive reqInfo = derin.readObject();
        PKCS10CertificationRequest certReq = new PKCS10CertificationRequest((ASN1Sequence) reqInfo);

        boolean rs = certReq.verify();

        if (!rs) {
            String err = i18n.getMessage("certReqVerification");
            throw new GeneralSecurityException(err);
        }

        return createProxyCertificate(cert, privateKey, certReq.getPublicKey(), lifetime, certType, extSet, cnValue);
    }

    /**
     * Creates a new proxy credential from the specified certificate chain and a private key.
     *
     * @see #createCredential(X509Certificate[], PrivateKey, int, int, GSIConstants.CertificateType, X509ExtensionSet, String)
     *      createCredential
     */
    public X509Credential createCredential(X509Certificate[] certs, PrivateKey privateKey, int bits, int lifetime,
        GSIConstants.CertificateType certType) throws GeneralSecurityException {
        return createCredential(certs, privateKey, bits, lifetime, certType, (X509ExtensionSet) null, null);
    }

    /**
     * Creates a new proxy credential from the specified certificate chain and a private key.
     *
     * @see #createCredential(X509Certificate[], PrivateKey, int, int, GSIConstants.CertificateType, X509ExtensionSet, String)
     *      createCredential
     */
    public X509Credential createCredential(X509Certificate[] certs, PrivateKey privateKey, int bits, int lifetime,
        GSIConstants.CertificateType certType, X509ExtensionSet extSet) throws GeneralSecurityException {
        return createCredential(certs, privateKey, bits, lifetime, certType, extSet, null);
    }

    /**
     * Creates a new proxy credential from the specified certificate chain and a private key. A set of X.509
     * extensions can be optionally included in the new proxy certificate. This function automatically creates
     * a "RSA"-based key pair.
     *
     * @see #createProxyCertificate(X509Certificate, PrivateKey, PublicKey, int, int, X509ExtensionSet,
     *      String) createProxyCertificate
     * @param certs
     *            the certificate chain for the new proxy credential. The top-most certificate
     *            <code>cert[0]</code> will be designated as the issuing certificate.
     * @param privateKey
     *            the private key of the issuing certificate. The new proxy certificate will be signed with
     *            that private key.
     * @param bits
     *            the strength of the key pair for the new proxy certificate.
     * @param lifetime
     *            lifetime of the new certificate in seconds. If 0 (or less then) the new certificate will
     *            have the same lifetime as the issuing certificate.
     * @param certType
     *            the type of proxy credential to create
     * @param extSet
     *            a set of X.509 extensions to be included in the new proxy certificate. Can be null. If
     *            delegation mode is {@link org.globus.gsi.GSIConstants.CertificateType#GSI_3_RESTRICTED_PROXY
     *            GSIConstants.CertificateType.GSI_3_RESTRICTED_PROXY} or {@link org.globus.gsi.GSIConstants.CertificateType#GSI_4_RESTRICTED_PROXY
     *            GSIConstants.CertificateType.GSI_4_RESTRICTED_PROXY} then
     *            {@link org.globus.gsi.proxy.ext.ProxyCertInfoExtension ProxyCertInfoExtension} must be
     *            present in the extension set.
     * @param cnValue
     *            the value of the CN component of the subject of the new proxy credential. If null, the
     *            defaults will be used depending on the proxy certificate type created.
     * @return <code>GlobusCredential</code> the new proxy credential.
     * @exception GeneralSecurityException
     *                if a security error occurs.
     */
    public X509Credential createCredential(X509Certificate[] certs, PrivateKey privateKey, int bits, int lifetime,
        GSIConstants.CertificateType certType, X509ExtensionSet extSet, String cnValue) throws GeneralSecurityException {

        X509Certificate[] bcCerts = getX509CertificateObjectChain(certs);

        KeyPairGenerator keyGen = null;
        keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(bits);
        KeyPair keyPair = keyGen.genKeyPair();

        X509Certificate newCert = createProxyCertificate(bcCerts[0], privateKey, keyPair.getPublic(), lifetime,
            certType, extSet, cnValue);

        X509Certificate[] newCerts = new X509Certificate[bcCerts.length + 1];
        newCerts[0] = newCert;
        System.arraycopy(certs, 0, newCerts, 1, certs.length);

        return new X509Credential(keyPair.getPrivate(), newCerts);
    }

    /**
     * Creates a new proxy credential from the specified certificate chain and a private key,
     * using the given delegation mode.
     *
     * @see #createCredential(X509Certificate[], PrivateKey, int, int, GSIConstants.CertificateType, X509ExtensionSet, String)
     *      createCredential
     */
    public X509Credential createCredential(X509Certificate[] certs, PrivateKey privateKey, int bits, int lifetime,
        GSIConstants.DelegationType delegType) throws GeneralSecurityException {
        return createCredential(certs, privateKey, bits, lifetime, delegType, (X509ExtensionSet) null, null);
    }

    /**
     * Creates a new proxy credential from the specified certificate chain and a private key,
     * using the given delegation mode.
     *
     * @see #createCredential(X509Certificate[], PrivateKey, int, int, GSIConstants.CertificateType, X509ExtensionSet, String)
     *      createCredential
     */
    public X509Credential createCredential(X509Certificate[] certs, PrivateKey privateKey, int bits, int lifetime,
        GSIConstants.DelegationType delegType, X509ExtensionSet extSet) throws GeneralSecurityException {
        return createCredential(certs, privateKey, bits, lifetime, delegType, extSet, null);
    }

    /**
     * Creates a new proxy credential from the specified certificate chain and a private key,
     * using the given delegation mode.
     * @see #createCredential(X509Certificate[], PrivateKey, int, int, GSIConstants.CertificateType, X509ExtensionSet, String)
     */
    public X509Credential createCredential(X509Certificate[] certs, PrivateKey privateKey, int bits, int lifetime,
       GSIConstants.DelegationType delegType, X509ExtensionSet extSet, String cnValue) throws GeneralSecurityException {

        X509Certificate[] bcCerts = getX509CertificateObjectChain(certs);

        return createCredential(bcCerts, privateKey, bits, lifetime, decideProxyType(bcCerts[0], delegType), extSet, cnValue);
    }

    /**
     * Creates a proxy certificate. A set of X.509 extensions can be optionally included in the new proxy
     * certificate. <BR>
     * If a GSI-2 proxy is created, the serial number of the proxy certificate will be the same as of the
     * issuing certificate. Also, none of the extensions in the issuing certificate will be copied into the
     * proxy certificate.<BR>
     * If a GSI-3 or GSI 4 proxy is created, the serial number of the proxy certificate will be picked
     * randomly. If the issuing certificate contains a <i>KeyUsage</i> extension, the extension will be copied
     * into the proxy certificate with <i>keyCertSign</i> and <i>nonRepudiation</i> bits turned off. No other
     * extensions are currently copied.
     *
     * The methods defaults to creating GSI 4 proxy
     *
     * @param issuerCert_
     *            the issuing certificate
     * @param issuerKey
     *            private key matching the public key of issuer certificate. The new proxy certificate will be
     *            signed by that key.
     * @param publicKey
     *            the public key of the new certificate
     * @param lifetime
     *            lifetime of the new certificate in seconds. If 0 (or less then) the new certificate will
     *            have the same lifetime as the issuing certificate.
     * @param certType
     *            can be one of {@link org.globus.gsi.GSIConstants.CertificateType#GSI_2_LIMITED_PROXY GSIConstants.CertificateType.GSI_2_LIMITED_PROXY},
     *            {@link org.globus.gsi.GSIConstants.CertificateType#GSI_2_PROXY GSIConstants.CertificateType.GSI_2_PROXY},
     *            {@link org.globus.gsi.GSIConstants.CertificateType#GSI_3_IMPERSONATION_PROXY GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY},
     *            {@link org.globus.gsi.GSIConstants.CertificateType#GSI_3_LIMITED_PROXY GSIConstants.CertificateType.GSI_3_LIMITED_PROXY},
     *            {@link org.globus.gsi.GSIConstants.CertificateType#GSI_3_INDEPENDENT_PROXY GSIConstants.CertificateType.GSI_3_INDEPENDENT_PROXY},
     *            {@link org.globus.gsi.GSIConstants.CertificateType#GSI_3_RESTRICTED_PROXY GSIConstants.CertificateType.GSI_3_RESTRICTED_PROXY}.
     *            {@link org.globus.gsi.GSIConstants.CertificateType#GSI_4_IMPERSONATION_PROXY GSIConstants.CertificateType.GSI_4_IMPERSONATION_PROXY},
     *            {@link org.globus.gsi.GSIConstants.CertificateType#GSI_4_LIMITED_PROXY GSIConstants.CertificateType.GSI_3_LIMITED_PROXY},
     *            {@link org.globus.gsi.GSIConstants.CertificateType#GSI_4_INDEPENDENT_PROXY GSIConstants.CertificateType.GSI_4_INDEPENDENT_PROXY},
     *            {@link org.globus.gsi.GSIConstants.CertificateType#GSI_4_RESTRICTED_PROXY GSIConstants.CertificateType.GSI_4_RESTRICTED_PROXY}.
     *
     * @param extSet
     *            a set of X.509 extensions to be included in the new proxy certificate. Can be null. If
     *            delegation mode is {@link org.globus.gsi.GSIConstants.CertificateType#GSI_3_RESTRICTED_PROXY
     *            GSIConstants.CertificateType.GSI_3_RESTRICTED_PROXY} or {@link org.globus.gsi.GSIConstants.CertificateType#GSI_4_RESTRICTED_PROXY
     *            GSIConstants.CertificateType.GSI_4_RESTRICTED_PROXY} then
     *            {@link org.globus.gsi.proxy.ext.ProxyCertInfoExtension ProxyCertInfoExtension} must be
     *            present in the extension set.
     *
     * @param cnValue
     *            the value of the CN component of the subject of the new certificate. If null, the defaults
     *            will be used depending on the proxy certificate type created.
     * @return <code>X509Certificate</code> the new proxy certificate.
     * @exception GeneralSecurityException
     *                if a security error occurs.
     */
    public X509Certificate createProxyCertificate(X509Certificate issuerCert_, PrivateKey issuerKey,
        PublicKey publicKey, int lifetime, GSIConstants.CertificateType certType, X509ExtensionSet extSet,
        String cnValue) throws GeneralSecurityException {

        X509Certificate issuerCert = issuerCert_;
        if (!(issuerCert_ instanceof X509CertificateObject)) {
            issuerCert = CertificateLoadUtil.loadCertificate(new ByteArrayInputStream(issuerCert.getEncoded()));
        }

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        org.globus.gsi.X509Extension x509Ext = null;
        BigInteger serialNum = null;
        String delegDN = null;

        if (ProxyCertificateUtil.isGsi3Proxy(certType) || ProxyCertificateUtil.isGsi4Proxy(certType)) {
            Random rand = new Random();
            delegDN = String.valueOf(Math.abs(rand.nextInt()));
            serialNum = new BigInteger(20, rand);

            if (extSet != null) {
                x509Ext = extSet.get(ProxyCertInfo.OID.getId());
                if (x509Ext == null) {
                    x509Ext = extSet.get(ProxyCertInfo.OLD_OID.getId());
                }
            }

            if (x509Ext == null) {
                // create ProxyCertInfo extension
                ProxyPolicy policy = null;
                if (ProxyCertificateUtil.isLimitedProxy(certType)) {
                    policy = new ProxyPolicy(ProxyPolicy.LIMITED);
                } else if (ProxyCertificateUtil.isIndependentProxy(certType)) {
                    policy = new ProxyPolicy(ProxyPolicy.INDEPENDENT);
                } else if (ProxyCertificateUtil.isImpersonationProxy(certType)) {
                    // since limited has already been checked, this should work.
                    policy = new ProxyPolicy(ProxyPolicy.IMPERSONATION);
                } else if ((certType == GSIConstants.CertificateType.GSI_3_RESTRICTED_PROXY)
                    || (certType == GSIConstants.CertificateType.GSI_4_RESTRICTED_PROXY)) {
                    String err = i18n.getMessage("restrictProxy");
                    throw new IllegalArgumentException(err);
                } else {
                    String err = i18n.getMessage("invalidProxyType");
                    throw new IllegalArgumentException(err);
                }

                ProxyCertInfo proxyCertInfo = new ProxyCertInfo(policy);
                x509Ext = new ProxyCertInfoExtension(proxyCertInfo);
                if (ProxyCertificateUtil.isGsi4Proxy(certType)) {
                    // RFC compliant OID
                    x509Ext = new ProxyCertInfoExtension(proxyCertInfo);
                } else {
                    // old OID
                    x509Ext = new GlobusProxyCertInfoExtension(proxyCertInfo);
                }
            }

            try {
                // add ProxyCertInfo extension to the new cert
                certGen.addExtension(x509Ext.getOid(), x509Ext.isCritical(), x509Ext.getValue());

                // handle KeyUsage in issuer cert
                TBSCertificateStructure crt = BouncyCastleUtil.getTBSCertificateStructure(issuerCert);

                X509Extensions extensions = crt.getExtensions();
                if (extensions != null) {
                    X509Extension ext;

                    // handle key usage ext
                    ext = extensions.getExtension(X509Extension.keyUsage);
                    if (ext != null) {

                        // TBD: handle this better
                        if (extSet != null && (extSet.get(X509Extension.keyUsage.getId()) != null)) {
                            String err = i18n.getMessage("keyUsageExt");
                            throw new GeneralSecurityException(err);
                        }

                        DERBitString bits = (DERBitString) BouncyCastleUtil.getExtensionObject(ext);

                        byte[] bytes = bits.getBytes();

                        // make sure they are disabled
                        if ((bytes[0] & KeyUsage.nonRepudiation) != 0) {
                            bytes[0] ^= KeyUsage.nonRepudiation;
                        }

                        if ((bytes[0] & KeyUsage.keyCertSign) != 0) {
                            bytes[0] ^= KeyUsage.keyCertSign;
                        }

                        bits = new DERBitString(bytes, bits.getPadBits());

                        certGen.addExtension(X509Extension.keyUsage, ext.isCritical(), bits);
                    }
                }

            } catch (IOException e) {
                // but this should not happen
                throw new GeneralSecurityException(e.getMessage());
            }

        } else if (certType == GSIConstants.CertificateType.GSI_2_LIMITED_PROXY) {
            delegDN = "limited proxy";
            serialNum = issuerCert.getSerialNumber();
        } else if (certType == GSIConstants.CertificateType.GSI_2_PROXY) {
            delegDN = "proxy";
            serialNum = issuerCert.getSerialNumber();
        } else {
            String err = i18n.getMessage("unsupportedProxy", certType);
            throw new IllegalArgumentException(err);
        }

        // add specified extensions
        if (extSet != null) {
            Iterator iter = extSet.oidSet().iterator();
            while (iter.hasNext()) {
                String oid = (String) iter.next();
                // skip ProxyCertInfo extension
                if (oid.equals(ProxyCertInfo.OID.getId()) || oid.equals(ProxyCertInfo.OLD_OID.getId())) {
                    continue;
                }
                x509Ext = (org.globus.gsi.X509Extension) extSet.get(oid);
                certGen.addExtension(x509Ext.getOid(), x509Ext.isCritical(), x509Ext.getValue());
            }
        }

        X509Name issuerDN;
        if (issuerCert.getSubjectDN() instanceof X509Name) {
        	issuerDN = (X509Name)issuerCert.getSubjectDN();
        } else {
        	issuerDN = new X509Name(true,issuerCert.getSubjectX500Principal().getName());
        }
        X509NameHelper issuer = new X509NameHelper(issuerDN);
        X509NameHelper subject = new X509NameHelper(issuerDN);
        subject.add(BCStyle.CN, (cnValue == null) ? delegDN : cnValue);

        certGen.setSubjectDN(subject.getAsName());
        certGen.setIssuerDN(issuer.getAsName());

        certGen.setSerialNumber(serialNum);
        certGen.setPublicKey(publicKey);
        certGen.setSignatureAlgorithm(issuerCert.getSigAlgName());

        GregorianCalendar date = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
        /* Allow for a five minute clock skew here. */
        date.add(Calendar.MINUTE, -5);
        certGen.setNotBefore(date.getTime());

        /* If hours = 0, then cert lifetime is set to user cert */
        if (lifetime <= 0) {
            certGen.setNotAfter(issuerCert.getNotAfter());
        } else {
            date.add(Calendar.MINUTE, 5);
            date.add(Calendar.SECOND, lifetime);
            certGen.setNotAfter(date.getTime());
        }


        return certGen.generateX509Certificate(issuerKey);
    }

    /**
     * Loads a X509 certificate from the specified input stream. Input stream must contain DER-encoded
     * certificate.
     *
     * @param in
     *            the input stream to read the certificate from.
     * @return <code>X509Certificate</code> the loaded certificate.
     * @exception GeneralSecurityException
     *                if certificate failed to load.
     */
    public X509Certificate loadCertificate(InputStream in) throws IOException, GeneralSecurityException {
        ASN1InputStream derin = new ASN1InputStream(in);
        ASN1Primitive certInfo = derin.readObject();
        ASN1Sequence seq = ASN1Sequence.getInstance(certInfo);
        return new X509CertificateObject(Certificate.getInstance(seq));
    }

    /**
     * Creates a certificate request from the specified subject DN and a key pair. The
     * <I>"MD5WithRSAEncryption"</I> is used as the signing algorithm of the certificate request.
     *
     * @param subject
     *            the subject of the certificate request
     * @param keyPair
     *            the key pair of the certificate request
     * @return the certificate request.
     * @exception GeneralSecurityException
     *                if security error occurs.
     */
    public byte[] createCertificateRequest(String subject, KeyPair keyPair) throws GeneralSecurityException {
        X509Name name = new X509Name(subject);
        return createCertificateRequest(name, "MD5WithRSAEncryption", keyPair);
    }

    /**
     * Creates a certificate request from the specified certificate and a key pair. The certificate's subject
     * DN with <I>"CN=proxy"</I> name component appended to the subject is used as the subject of the
     * certificate request. Also the certificate's signing algorithm is used as the certificate request
     * signing algorithm.
     *
     * @param cert
     *            the certificate to create the certificate request from.
     * @param keyPair
     *            the key pair of the certificate request
     * @return the certificate request.
     * @exception GeneralSecurityException
     *                if security error occurs.
     */
    public byte[] createCertificateRequest(X509Certificate cert, KeyPair keyPair) throws GeneralSecurityException {

        String issuer = cert.getSubjectDN().getName();
        X509Name subjectDN = new X509Name(issuer + ",CN=proxy");
        String sigAlgName = cert.getSigAlgName();
        return createCertificateRequest(subjectDN, sigAlgName, keyPair);
    }

    /**
     * Creates a certificate request from the specified subject name, signing algorithm, and a key pair.
     *
     * @param subjectDN
     *            the subject name of the certificate request.
     * @param sigAlgName
     *            the signing algorithm name.
     * @param keyPair
     *            the key pair of the certificate request
     * @return the certificate request.
     * @exception GeneralSecurityException
     *                if security error occurs.
     */
    public byte[] createCertificateRequest(X509Name subjectDN, String sigAlgName, KeyPair keyPair)
        throws GeneralSecurityException {
        DERSet attrs = null;
        PKCS10CertificationRequest certReq = null;
        certReq = new PKCS10CertificationRequest(sigAlgName, subjectDN, keyPair.getPublic(), attrs, keyPair
            .getPrivate());

        return certReq.getEncoded();
    }

    /**
     * Given a delegation mode and an issuing certificate, decides an
     * appropriate certificate type to use for proxies
     * @param issuerCert the issuing certificate of a prospective proxy
     * @param delegType the desired delegation mode
     * @return the appropriate certificate type for proxies or
     * GSIConstants.CertificateType.UNDEFINED when
     * GSIConstants.DelegationType.NONE was specified
     * @throws CertificateException when failing to get the certificate type
     * of the issuing certificate
     */
    public static GSIConstants.CertificateType decideProxyType(
            X509Certificate issuerCert, GSIConstants.DelegationType delegType)
            throws CertificateException {
        GSIConstants.CertificateType proxyType = GSIConstants.CertificateType.UNDEFINED;
        if (delegType == GSIConstants.DelegationType.LIMITED) {
            GSIConstants.CertificateType type = BouncyCastleUtil.getCertificateType(issuerCert);
            if (ProxyCertificateUtil.isGsi4Proxy(type)) {
                proxyType = GSIConstants.CertificateType.GSI_4_LIMITED_PROXY;
            } else if (ProxyCertificateUtil.isGsi3Proxy(type)) {
                proxyType = GSIConstants.CertificateType.GSI_3_LIMITED_PROXY;
            } else if (ProxyCertificateUtil.isGsi2Proxy(type)) {
                proxyType = GSIConstants.CertificateType.GSI_2_LIMITED_PROXY;
            } else {
                // default to RFC compliant proxy
                if (VersionUtil.isGsi2Enabled()) {
                    proxyType = GSIConstants.CertificateType.GSI_2_LIMITED_PROXY;
                } else {
                    proxyType = VersionUtil.isGsi3Enabled() ?
                          GSIConstants.CertificateType.GSI_3_LIMITED_PROXY
                        : GSIConstants.CertificateType.GSI_4_LIMITED_PROXY;
                }
            }
        } else if (delegType == GSIConstants.DelegationType.FULL) {
            GSIConstants.CertificateType type = BouncyCastleUtil.getCertificateType(issuerCert);
            if (ProxyCertificateUtil.isGsi4Proxy(type)) {
                proxyType = GSIConstants.CertificateType.GSI_4_IMPERSONATION_PROXY;
            } else if (ProxyCertificateUtil.isGsi3Proxy(type)) {
                proxyType = GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY;
            } else if (ProxyCertificateUtil.isGsi2Proxy(type)) {
                proxyType = GSIConstants.CertificateType.GSI_2_PROXY;
            } else {
                // Default to RFC complaint proxy
                if (VersionUtil.isGsi2Enabled()) {
                    proxyType = GSIConstants.CertificateType.GSI_2_PROXY;
                } else {
                    proxyType = (VersionUtil.isGsi3Enabled()) ?
                          GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY
                        : GSIConstants.CertificateType.GSI_4_IMPERSONATION_PROXY;
                }
            }
        }
        return proxyType;
    }

    /**
     * Returns a chain of X509Certificate's that are instances of X509CertificateObject
     * This is related to http://bugzilla.globus.org/globus/show_bug.cgi?id=4933
     * @param certs input certificate chain
     * @return a new chain where all X509Certificate's are instances of X509CertificateObject
     * @throws GeneralSecurityException when failing to get load certificate from encoding
     */
    protected X509Certificate[] getX509CertificateObjectChain(X509Certificate[] certs)
            throws GeneralSecurityException {
        X509Certificate[] bcCerts = new X509Certificate[certs.length];
        for (int i = 0; i < certs.length; i++) {
            if (!(certs[i] instanceof X509CertificateObject)) {
                bcCerts[i] = CertificateLoadUtil.loadCertificate(new ByteArrayInputStream(certs[i].getEncoded()));
            } else {
                bcCerts[i] = certs[i];
            }
        }
        return bcCerts;
    }
}
