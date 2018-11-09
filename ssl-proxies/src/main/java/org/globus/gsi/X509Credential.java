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

import org.globus.gsi.trustmanager.X509ProxyCertPathValidator;

import org.globus.gsi.stores.ResourceSigningPolicyStore;

import org.apache.commons.logging.LogFactory;

import org.apache.commons.logging.Log;


import java.security.cert.CertStore;
import java.security.KeyStore;
import org.globus.common.CoGProperties;
import java.io.FileNotFoundException;
import java.io.FileInputStream;
import java.security.cert.CertificateException;
import org.globus.gsi.bc.BouncyCastleUtil;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Vector;



import org.bouncycastle.util.encoders.Base64;

import org.globus.gsi.stores.Stores;
import org.globus.gsi.bc.BouncyCastleOpenSSLKey;

/**
 * FILL ME
 * <p>
 * This class equivalent was called GlobusCredential in CoG -maybe a better name?
 *
 * @author ranantha@mcs.anl.gov
 */
// COMMENT: Added methods from GlobusCredential
// COMMENT: Do we need the getDefaultCred functionality?
public class X509Credential implements Serializable {

    private static final long serialVersionUID = 1L;
    public static final int BUFFER_SIZE = Integer.MAX_VALUE;
    private static Log logger = LogFactory.getLog(X509Credential.class.getCanonicalName());
    private OpenSSLKey opensslKey;
    private X509Certificate[] certChain;


    private static X509Credential defaultCred;
    private static long credentialLastModified = -1;
    // indicates if default credential was explicitely set
    // and if so - if the credential expired it try
    // to load the proxy from a file.
    private static boolean credentialSet = false;
    private static File credentialFile = null;

    static {
        new ProviderLoader();
    }

    public X509Credential(PrivateKey initKey, X509Certificate[] initCertChain) {

        if (initKey == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }

        if ((initCertChain == null) || (initCertChain.length < 1)) {
            throw new IllegalArgumentException("At least one public certificate required");
        }

        this.certChain = new X509Certificate[initCertChain.length];
        System.arraycopy(initCertChain, 0, this.certChain, 0, initCertChain.length);
        this.opensslKey = new BouncyCastleOpenSSLKey(initKey);
    }

    public X509Credential(InputStream certInputStream, InputStream keyInputStream) throws CredentialException {
        if (certInputStream.markSupported()) {
            certInputStream.mark(BUFFER_SIZE);
        }
        loadKey(keyInputStream);
        loadCertificate(certInputStream);
        validateCredential();
    }

    public X509Credential(String certFile, String keyFile) throws CredentialException, IOException {
        loadKey(new FileInputStream(new File(keyFile)));
        loadCertificate(new FileInputStream(new File(certFile)));
        validateCredential();
    }

    public X509Credential(String proxyFile) throws CredentialException {
        if (proxyFile == null) {
            throw new IllegalArgumentException("proxy file is null");
        }
        logger.debug("Loading proxy file: " + proxyFile);

        try {
            InputStream in = new FileInputStream(proxyFile);
            load(in);
        } catch (FileNotFoundException f) {
            throw new CredentialException("proxy not found");
        }
    }

    public X509Credential(InputStream input) throws CredentialException {
        load(input);
    }

    public X509Certificate[] getCertificateChain() {
        X509Certificate[] returnArray = new X509Certificate[this.certChain.length];
        System.arraycopy(this.certChain, 0, returnArray, 0, this.certChain.length);
        return returnArray;
    }

    public PrivateKey getPrivateKey() throws CredentialException {

        return getPrivateKey(null);
    }

    public PrivateKey getPrivateKey(String password) throws CredentialException {

        if (this.opensslKey.isEncrypted()) {
            if (password == null) {
                throw new CredentialException("Key encrypted, password required");
            } else {
                try {
                    this.opensslKey.decrypt(password);
                } catch (GeneralSecurityException exp) {
                    throw new CredentialException(exp.getMessage(), exp);
                }
            }
        }
        return this.opensslKey.getPrivateKey();

    }

    public boolean isEncryptedKey() {
        return this.opensslKey.isEncrypted();
    }

    /**
     * Reads Base64 encoded data from the stream and returns its decoded value. The reading continues until
     * the "END" string is found in the data. Otherwise, returns null.
     */
    private static byte[] getDecodedPEMObject(BufferedReader reader) throws IOException {
        String line;
        StringBuffer buf = new StringBuffer();
        while ((line = reader.readLine()) != null) {
            if (line.indexOf("--END") != -1) { // found end
                return Base64.decode(buf.toString().getBytes());
            } else {
                buf.append(line);
            }
        }
        throw new EOFException("Missing PEM end footer");
    }

    public void saveKey(OutputStream out) throws IOException {

        this.opensslKey.writeTo(out);
        out.flush();
    }

    // COMMENT Used to be "key cert cert cert ...", which is wrong afaik. must be "cert key cert cert ..."
    public void saveCertificateChain(OutputStream out) throws IOException, CertificateEncodingException {

        CertificateIOUtil.writeCertificate(out, this.certChain[0]);

        for (int i = 1; i < this.certChain.length; i++) {
            // skip the self-signed certificates
            if (this.certChain[i].getSubjectDN().equals(certChain[i].getIssuerDN())) {
                continue;
            }
            CertificateIOUtil.writeCertificate(out, this.certChain[i]);
        }
        out.flush();
    }

    public void save(OutputStream out) throws IOException, CertificateEncodingException {
        CertificateIOUtil.writeCertificate(out, this.certChain[0]);
        saveKey(out);
        for (int i = 1; i < this.certChain.length; i++) {
            // This will skip the self-signed certificates?
            if (this.certChain[i].getSubjectDN().equals(certChain[i].getIssuerDN())) {
                continue;
            }
            CertificateIOUtil.writeCertificate(out, this.certChain[i]);
        }
        out.flush();
    }

    public void writeToFile(File file) throws IOException, CertificateEncodingException {
        writeToFile(file, file);
    }

    public void writeToFile(File certFile, File keyFile) throws IOException, CertificateEncodingException {
        FileOutputStream keyOutputStream = null;
        FileOutputStream certOutputStream = null;
        try {
            keyOutputStream = new FileOutputStream(keyFile);
            certOutputStream = new FileOutputStream(certFile);
            saveKey(keyOutputStream);
            saveCertificateChain(certOutputStream);
        } finally {
            try {
                if (keyOutputStream != null) {
                    keyOutputStream.close();
                }
            } catch (IOException e) {
                logger.warn("Could not close stream on save of key to file. " + keyFile.getPath());
            }
            try {
                if (certOutputStream != null) {
                    certOutputStream.close();
                }
            } catch (IOException e) {
                logger.warn("Could not close stream on save certificate chain to file. " + certFile.getPath());
            }
        }
    }

    public Date getNotBefore() {
        Date notBefore = this.certChain[0].getNotBefore();
        for (int i = 1; i < this.certChain.length; i++) {
            Date date = this.certChain[i].getNotBefore();
            if (date.before(notBefore)) {
                notBefore = date;
            }
        }
        return notBefore;
    }

    /**
     * Returns the number of certificates in the credential without the self-signed certificates.
     *
     * @return number of certificates without counting self-signed certificates
     */
    public int getCertNum() {
        for (int i = this.certChain.length - 1; i >= 0; i--) {
            if (!this.certChain[i].getSubjectDN().equals(this.certChain[i].getIssuerDN())) {
                return i + 1;
            }
        }
        return this.certChain.length;
    }

    /**
     * Returns strength of the private/public key in bits.
     *
     * @return strength of the key in bits. Returns -1 if unable to determine it.
     */
    public int getStrength() throws CredentialException {
        return getStrength(null);
    }

    /**
     * Returns strength of the private/public key in bits.
     *
     * @return strength of the key in bits. Returns -1 if unable to determine it.
     */
    public int getStrength(String password) throws CredentialException {
        if (opensslKey == null) {
            return -1;
        }
        if (this.opensslKey.isEncrypted()) {
            if (password == null) {
                throw new CredentialException("Key encrypted, password required");
            } else {
                try {
                    this.opensslKey.decrypt(password);
                } catch (GeneralSecurityException exp) {
                    throw new CredentialException(exp.getMessage(), exp);
                }
            }
        }
        return ((RSAPrivateKey)opensslKey.getPrivateKey()).getModulus().bitLength();
    }

    /**
     * Returns the subject DN of the first certificate in the chain.
     *
     * @return subject DN.
     */
    public String getSubject() {
        return this.certChain[0].getSubjectDN().getName();
    }

    /**
     * Returns the issuer DN of the first certificate in the chain.
     *
     * @return issuer DN.
     */
    public String getIssuer() {
        return this.certChain[0].getIssuerDN().getName();
    }

    /**
     * Returns the certificate type of the first certificate in the chain. Returns -1 if unable to determine
     * the certificate type (an error occurred)
     *
     * @see BouncyCastleUtil#getCertificateType(X509Certificate)
     *
     * @return the type of first certificate in the chain. -1 if unable to determine the certificate type.
     */
    public GSIConstants.CertificateType getProxyType() {
        try {
            return BouncyCastleUtil.getCertificateType(this.certChain[0]);
        } catch (CertificateException e) {
            logger.error("Error getting certificate type.", e);
            return GSIConstants.CertificateType.UNDEFINED;
        }
    }

    /**
     * Returns time left of this credential. The time left of the credential is based on the certificate with
     * the shortest validity time.
     *
     * @return time left in seconds. Returns 0 if the certificate has expired.
     */
    public long getTimeLeft() {
        Date earliestTime = null;
        for (int i = 0; i < this.certChain.length; i++) {
            Date time = this.certChain[i].getNotAfter();
            if (earliestTime == null || time.before(earliestTime)) {
                earliestTime = time;
            }
        }
        long diff = (earliestTime.getTime() - System.currentTimeMillis()) / 1000;
        return (diff < 0) ? 0 : diff;
    }

    /**
     * Returns the identity of this credential.
     * @see #getIdentityCertificate()
     *
     * @return The identity cert in Globus format (e.g. /C=US/..). Null,
     *         if unable to get the identity (an error occurred)
     */
    public String getIdentity() {
    try {
        return BouncyCastleUtil.getIdentity(this.certChain);
    } catch (CertificateException e) {
            logger.debug("Error getting certificate identity.", e);
        return null;
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
        try {
            return BouncyCastleUtil.getIdentityCertificate(this.certChain);
        } catch (CertificateException e) {
            logger.debug("Error getting certificate identity.", e);
            return null;
        }
    }

    /**
     * Returns the path length constraint. The shortest length in the chain of
     * certificates is returned as the credential's path length.
     *
     * @return The path length constraint of the credential. -1 is any error
     *         occurs.
     */
    public int getPathConstraint() {

        int pathLength = Integer.MAX_VALUE;
        try {
            for (int i=0; i<this.certChain.length; i++) {
                int length = BouncyCastleUtil.getProxyPathConstraint(this.certChain[i]);
                // if length is one, then no proxy cert extension exists, so
                // path length is -1
                if (length == -1) {
                    length = Integer.MAX_VALUE;
                }
                if (length < pathLength) {
                    pathLength = length;
                }
            }
        } catch (Exception e) {
            logger.warn("Error retrieving path length.", e);
            pathLength = -1;
        }
        return pathLength;
    }

    /**
     * Verifies the validity of the credentials. All certificate path validation is performed using trusted
     * certificates in default locations.
     *
     * @exception CredentialException
     *                if one of the certificates in the chain expired or if path validiation fails.
     */
    public void verify() throws CredentialException {
        try {
            String caCertsLocation = "file:" + CoGProperties.getDefault().getCaCertLocations();

            KeyStore keyStore = Stores.getTrustStore(caCertsLocation + "/" + Stores.getDefaultCAFilesPattern());
            CertStore crlStore = Stores.getCRLStore(caCertsLocation + "/" + Stores.getDefaultCRLFilesPattern());
            ResourceSigningPolicyStore sigPolStore = Stores.getSigningPolicyStore(caCertsLocation + "/" + Stores.getDefaultSigningPolicyFilesPattern());

            X509ProxyCertPathParameters parameters = new X509ProxyCertPathParameters(keyStore, crlStore, sigPolStore, false);
            X509ProxyCertPathValidator validator = new X509ProxyCertPathValidator();
            validator.engineValidate(CertificateUtil.getCertPath(certChain), parameters);
        } catch (Exception e) {
            throw new CredentialException(e);
        }
    }


    /**
     * Returns the default credential. The default credential is usually the user proxy certificate. <BR>
     * The credential will be loaded on the initial call. It must not be expired. All subsequent calls to this
     * function return cached credential object. Once the credential is cached, and the underlying file
     * changes, the credential will be reloaded.
     *
     * @return the default credential.
     * @exception CredentialException
     *                if the credential expired or some other error with the credential.
     */
    public synchronized static X509Credential getDefaultCredential() throws CredentialException {
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
        throws CredentialException {
        String proxyLocation = CoGProperties.getDefault().getProxyFile();
        defaultCred = new X509Credential(proxyLocation);
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
    public synchronized static void setDefaultCredential(X509Credential cred) {
        defaultCred = cred;
        credentialSet = (cred != null);
    }

    // COMMENT: In case of an exception because of missing password with an
    // encrypted key: put in -1 as strength
    public String toString() {
        String lineSep = System.getProperty("line.separator");
        StringBuffer buf = new StringBuffer();
        buf.append("subject    : ").append(getSubject()).append(lineSep);
        buf.append("issuer     : ").append(getIssuer()).append(lineSep);
        int strength = -1;
        try {
            strength = this.getStrength();
        } catch(Exception e) {}
        buf.append("strength   : ").append(strength).append(lineSep);
        buf.append("timeleft   : ").append(getTimeLeft() + " sec").append(lineSep);
        buf.append("proxy type : ").append(ProxyCertificateUtil.getProxyTypeAsString(getProxyType()));
        return buf.toString();
    }

    protected void load(InputStream input) throws CredentialException {

        if (input == null) {
            throw new IllegalArgumentException("input stream cannot be null");
        }

        X509Certificate cert = null;
        Vector chain = new Vector(3);
        String line;
        BufferedReader reader = null;

        try {
            reader = new BufferedReader(new InputStreamReader(input));
            while ((line = reader.readLine()) != null) {

                if (line.indexOf("BEGIN CERTIFICATE") != -1) {
                    byte[] data = getDecodedPEMObject(reader);
                    cert = CertificateLoadUtil.loadCertificate(new ByteArrayInputStream(data));
                    chain.addElement(cert);
                } else if (line.indexOf("BEGIN RSA PRIVATE KEY") != -1) {
                    byte[] data = getDecodedPEMObject(reader);
                    this.opensslKey = new BouncyCastleOpenSSLKey("RSA", data);
                } else if (line.indexOf("BEGIN PRIVATE KEY") != -1) {
                    byte[] data = getDecodedPEMObject(reader);
                    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(data);
                    KeyFactory kfac = KeyFactory.getInstance("RSA");
                    this.opensslKey = new BouncyCastleOpenSSLKey(kfac.generatePrivate(spec));
                }
            }
        } catch (Exception e) {
            throw new CredentialException(e);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                }
            }
        }

        int size = chain.size();

        if (size == 0) {
            throw new CredentialException("no certs");
        }

        if (opensslKey == null) {
            throw new CredentialException("no key");
        }

        // set chain
        this.certChain = new X509Certificate[size];
        chain.copyInto(certChain);
    }

    protected void loadCertificate(InputStream input) throws CredentialException {

        if (input == null) {
            throw new IllegalArgumentException("Input stream to load X509Credential is null");
        }

        X509Certificate cert;
        Vector<X509Certificate> chain = new Vector<X509Certificate>();

        String line;
        BufferedReader reader = null;
        try {
            if (input.markSupported()) {
                input.reset();
            }
            reader = new BufferedReader(new InputStreamReader(input));

            while ((line = reader.readLine()) != null) {

                if (line.indexOf("BEGIN CERTIFICATE") != -1) {
                    byte[] data = getDecodedPEMObject(reader);
                    cert = CertificateLoadUtil.loadCertificate(new ByteArrayInputStream(data));
                    chain.addElement(cert);
                }
            }

        } catch (IOException e) {
            throw new CredentialException(e);
        } catch (GeneralSecurityException e) {
            throw new CredentialException(e);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    logger.debug("error closing reader", e);
                    // This is ok
                }
            }
        }

        int size = chain.size();
        if (size > 0) {
            this.certChain = new X509Certificate[size];
            chain.copyInto(this.certChain);
        }

    }

    protected void loadKey(InputStream input) throws CredentialException {

        // JGLOBUS-95: BC seems to have some PEM utility but the actual
        // load is in private methods and cannot be leveraged.
        // Investigate availability of standard libraries for these
        // low level reads. FOr now, copying from CoG
        try {
            this.opensslKey = new BouncyCastleOpenSSLKey(input);
        } catch (IOException e) {
            throw new CredentialException(e.getMessage(), e);
        } catch (GeneralSecurityException e) {
            throw new CredentialException(e.getMessage(), e);
        }
    }

    private void validateCredential() throws CredentialException {

        if (this.certChain == null) {
            throw new CredentialException("No certificates found");
        }
        int size = this.certChain.length;

        if (size < 0) {
            throw new CredentialException("No certificates found.");
        }

        if (this.opensslKey == null) {
            throw new CredentialException("NO private key found");
        }
    }


    @Override
    public boolean equals(Object object) {
        if(object == this) {
            return true;
        }

        if(!(object instanceof X509Credential)) {
            return false;
        }

        X509Credential other = (X509Credential) object;

        return Arrays.equals(this.certChain, other.certChain) &&
                this.opensslKey.equals(other.opensslKey);
    }

    @Override
    public int hashCode() {
        return (certChain == null ? 0 : Arrays.hashCode(certChain)) ^
                opensslKey.hashCode();
    }
}
