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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.globus.gsi.util.CertificateUtil;

import org.globus.gsi.trustmanager.X509ProxyCertPathValidator;

import org.globus.gsi.stores.ResourceCertStoreParameters;
import org.globus.gsi.stores.ResourceSigningPolicyStore;
import org.globus.gsi.stores.ResourceSigningPolicyStoreParameters;

import org.globus.gsi.provider.GlobusProvider;
import org.globus.gsi.provider.KeyStoreParametersFactory;

import java.io.File;
import java.security.cert.CertStore;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateEncodingException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import org.globus.common.ChainedIOException;
import org.globus.common.CoGProperties;
import org.globus.gsi.bc.BouncyCastleUtil;

/**
 * Provides a Java object representation of Globus credential which can include the proxy file or host
 * certificates.
 * @deprecated
 */
public class GlobusCredential implements Serializable {

	private Log logger = LogFactory.getLog(getClass());
    private X509Credential cred;
    private static GlobusCredential defaultCred;
    private static transient long credentialLastModified = -1;
    // indicates if default credential was explicitely set
    // and if so - if the credential expired it try
    // to load the proxy from a file.
    private static transient boolean credentialSet = false;
    private static transient File credentialFile = null;

    static {
        new ProviderLoader();
    }

    /**
     * Creates a GlobusCredential from a private key and a certificate chain.
     *
     * @param key
     *            the private key
     * @param certs
     *            the certificate chain
     */
    public GlobusCredential(PrivateKey key, X509Certificate[] certs) {
        cred = new X509Credential(key, certs);
    }

    /**
     * Creates a GlobusCredential from a proxy file.
     *
     * @param proxyFile
     *            the file to load the credential from.
     * @exception GlobusCredentialException
     *                if the credential failed to load.
     */
    public GlobusCredential(String proxyFile) throws GlobusCredentialException {
        try {
            cred = new X509Credential(proxyFile);
        } catch (Exception e) {
            throw new GlobusCredentialException(GlobusCredentialException.FAILURE, e.getMessage(), e);
        }
    }

    /**
     * Creates a GlobusCredential from certificate file and a unencrypted key file.
     *
     * @param certFile
     *            the file containing the certificate
     * @param unencryptedKeyFile
     *            the file containing the private key. The key must be unencrypted.
     * @exception GlobusCredentialException
     *                if something goes wrong.
     */
    public GlobusCredential(String certFile, String unencryptedKeyFile) throws GlobusCredentialException {

        if (certFile == null || unencryptedKeyFile == null) {
            throw new IllegalArgumentException();
        }

        try {
            cred = new X509Credential(certFile, unencryptedKeyFile);
        } catch (Exception e) {
            throw new GlobusCredentialException(GlobusCredentialException.FAILURE, e.getMessage(), e);
        }
    }

    /**
     * Creates a GlobusCredential from an input stream.
     *
     * @param input
     *            the stream to load the credential from.
     * @exception GlobusCredentialException
     *                if the credential failed to load.
     */
    public GlobusCredential(InputStream input) throws GlobusCredentialException {

        try {
            cred = new X509Credential(input);
        } catch (Exception e) {
            throw new GlobusCredentialException(GlobusCredentialException.FAILURE, e.getMessage(), e);
        }
    }

    /**
     * Saves the credential into a specified output stream. The self-signed certificates in the certificate
     * chain will not be saved. The output stream should always be closed after calling this function.
     *
     * @param out
     *            the output stream to write the credential to.
     * @exception IOException
     *                if any error occurred during saving.
     */
    public void save(OutputStream out) throws IOException {

        try {
            cred.save(out);
        } catch (CertificateEncodingException e) {
            throw new ChainedIOException(e.getMessage(), e);
        }
    }

    /**
     * Verifies the validity of the credentials. All certificate path validation is performed using trusted
     * certificates in default locations.
     *
     * @exception GlobusCredentialException
     *                if one of the certificates in the chain expired or if path validiation fails.
     */
    public void verify() throws GlobusCredentialException {
        try {
            String caCertsLocation = "file:" + CoGProperties.getDefault().getCaCertLocations();
            String crlPattern = caCertsLocation + "/*.r*";
            String sigPolPattern = caCertsLocation + "/*.signing_policy";
            KeyStore keyStore = KeyStore.getInstance(GlobusProvider.KEYSTORE_TYPE, GlobusProvider.PROVIDER_NAME);
            CertStore crlStore = CertStore.getInstance(GlobusProvider.CERTSTORE_TYPE, new ResourceCertStoreParameters(null,crlPattern));
            ResourceSigningPolicyStore sigPolStore = new ResourceSigningPolicyStore(new ResourceSigningPolicyStoreParameters(sigPolPattern));
            keyStore.load(KeyStoreParametersFactory.createTrustStoreParameters(caCertsLocation));
            X509ProxyCertPathParameters parameters = new X509ProxyCertPathParameters(keyStore, crlStore, sigPolStore, false);
            X509ProxyCertPathValidator validator = new X509ProxyCertPathValidator();
            validator.engineValidate(CertificateUtil.getCertPath(this.cred.getCertificateChain()), parameters);
        } catch (Exception e) {
        	e.printStackTrace();
            throw new GlobusCredentialException(GlobusCredentialException.FAILURE, e.getMessage(), e);
        }
    }

    /**
     * Returns the identity certificate of this credential. The identity certificate is the first certificate
     * in the chain that is not an impersonation proxy certificate.
     *
     * @return <code>X509Certificate</code> the identity cert. Null, if unable to get the identity certificate
     *         (an error occurred)
     */
    public X509Certificate getIdentityCertificate() {
        return cred.getIdentityCertificate();
    }

    /**
     * Returns the path length constraint. The shortest length in the chain of certificates is returned as the
     * credential's path length.
     *
     * @return The path length constraint of the credential. -1 is any error occurs.
     */
    public int getPathConstraint() {
        return cred.getPathConstraint();
    }

    /**
     * Returns the identity of this credential.
     *
     * @see #getIdentityCertificate()
     *
     * @return The identity cert in Globus format (e.g. /C=US/..). Null, if unable to get the identity (an
     *         error occurred)
     */
    public String getIdentity() {
        return cred.getIdentity();
    }

    /**
     * Returns the private key of this credential.
     *
     * @return <code>PrivateKey</code> the private key
     */
    public PrivateKey getPrivateKey() {
        try {
            return (PrivateKey) cred.getPrivateKey();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Returns the certificate chain of this credential.
     *
     * @return <code>X509Certificate []</code> the certificate chain
     */
    public X509Certificate[] getCertificateChain() {
        return cred.getCertificateChain();
    }

    /**
     * Returns the number of certificates in the credential without the self-signed certificates.
     *
     * @return number of certificates without counting self-signed certificates
     */
    public int getCertNum() {
        return cred.getCertNum();
    }

    /**
     * Returns strength of the private/public key in bits.
     *
     * @return strength of the key in bits. Returns -1 if unable to determine it.
     */
    public int getStrength() {
        try {
            return cred.getStrength();
        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * Returns the subject DN of the first certificate in the chain.
     *
     * @return subject DN.
     */
    public String getSubject() {
        return cred.getSubject();
    }

    /**
     * Returns the issuer DN of the first certificate in the chain.
     *
     * @return issuer DN.
     */
    public String getIssuer() {
        return cred.getIssuer();
    }

    /**
     * Returns the certificate type of the first certificate in the chain. Returns -1 if unable to determine
     * the certificate type (an error occurred)
     *
     * @see BouncyCastleUtil#getCertificateType(X509Certificate)
     *
     * @return the type of first certificate in the chain. -1 if unable to determine the certificate type.
     */
    public int getProxyType() {
        return cred.getProxyType().getCode();
    }

    /**
     * Returns time left of this credential. The time left of the credential is based on the certificate with
     * the shortest validity time.
     *
     * @return time left in seconds. Returns 0 if the certificate has expired.
     */
    public long getTimeLeft() {
        return cred.getTimeLeft();
    }

    /**
     * Returns the default credential. The default credential is usually the user proxy certificate. <BR>
     * The credential will be loaded on the initial call. It must not be expired. All subsequent calls to this
     * function return cached credential object. Once the credential is cached, and the underlying file
     * changes, the credential will be reloaded.
     *
     * @return the default credential.
     * @exception GlobusCredentialException
     *                if the credential expired or some other error with the credential.
     */
    public synchronized static GlobusCredential getDefaultCredential() throws GlobusCredentialException {
        if (defaultCred == null) {
            reloadDefaultCredential();
        } else if (!credentialSet) {
            if (credentialFile.lastModified() == credentialLastModified) {
                defaultCred.verify();
            } else {
                defaultCred = null;
                reloadDefaultCredential();
            }
        }
        return defaultCred;
    }

    private static void reloadDefaultCredential()
        throws GlobusCredentialException {
        String proxyLocation = CoGProperties.getDefault().getProxyFile();
        defaultCred = new GlobusCredential(proxyLocation);
        credentialFile = new File(proxyLocation);
        credentialLastModified = credentialFile.lastModified();
        defaultCred.verify();
    }

    /**
     * Sets default credential.
     *
     * @param cred
     *            the credential to set a default.
     */
    public synchronized static void setDefaultCredential(GlobusCredential cred) {
        credentialSet = (cred != null);
    }

    public String toString() {
        return cred.toString();
    }

}
