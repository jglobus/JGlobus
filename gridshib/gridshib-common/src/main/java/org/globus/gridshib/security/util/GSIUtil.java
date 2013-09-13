/*
 * Copyright 1999-2007 University of Chicago
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

package org.globus.gridshib.security.util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
//import java.security.UnrecoverableEntryException;  // requires JDK 1.5
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.globus.common.ChainedIOException;
import org.globus.gridshib.security.x509.SAMLX509Extension;
import org.globus.gsi.GSIConstants;
import org.globus.gsi.X509Credential;
import org.globus.gsi.CredentialException;
import org.globus.gsi.OpenSSLKey;
import org.globus.gsi.X509Extension;
import org.globus.gsi.X509ExtensionSet;
import org.globus.gsi.bc.BouncyCastleCertProcessingFactory;
import org.globus.gsi.bc.BouncyCastleOpenSSLKey;
import org.globus.gsi.gssapi.GlobusGSSCredentialImpl;
import org.globus.gsi.util.CertificateIOUtil;
import org.globus.opensaml11.saml.SAMLAssertion;
import org.globus.util.Util;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;

/**
 * Utilities for Globus proxy credentials.
 *
 * The <code>bindAssertion</code> methods bind a <code>SAMLAssertion</code>
 * instance to a Globus proxy certificate.  If the proxy certificate
 * is to be processed by the GridShib Security Framework (i.e., this
 * library) the assertion MUST be a <code>SAMLSubjectAssertion</code>
 * instance, that is, the assertion must conform to the SAML
 * Subject-based Assertion Profile.
 *
 * @see org.globus.wsrf.impl.security.util.SAMLUtil
 */
public class GSIUtil {

    private static Log logger =
        LogFactory.getLog(GSIUtil.class.getName());

    private static final int DEFAULT_LIFETIME;
    private static BouncyCastleCertProcessingFactory certFactory;

    static {
        DEFAULT_LIFETIME = 12*60*60;  // 12 hrs
        certFactory = BouncyCastleCertProcessingFactory.getDefault();
        Security.addProvider(new BouncyCastleProvider());
    }

    public static int getDefaultLifetime() {
        return DEFAULT_LIFETIME;
    }

    /**
     * Utility method to bind a SAML assertion to an X.509
     * proxy certificate.  The lifetime of the proxy defaults
     * to a reasonable value.
     *
     * @param credential the issuing credential
     * @param assertion the assertion to bind to the proxy
     *
     * @return a Globus proxy credential
     *
     * @exception org.globus.gsi.CredentialException
     *            If the credential can not be created or
     *            the assertion can not be embedded in the credential
     *
     * @since 0.3.0
     */
    public static X509Credential bindAssertion(X509Credential credential,
                                                 SAMLAssertion assertion)
                                          throws CredentialException {

        return bindAssertion(credential, assertion, DEFAULT_LIFETIME);
    }

    /**
     * Utility method to bind a SAML assertion to an X.509
     * proxy certificate.
     *
     * @param credential the issuing credential
     * @param assertion the assertion to bind to the proxy
     * @param lifetime the desired lifetime of the proxy
     *
     * @return a Globus proxy credential
     *
     * @exception org.globus.gsi.CredentialException
     *            If the credential can not be created or
     *            the assertion can not be embedded in the credential
     *
     * @since 0.3.0
     */
    public static X509Credential bindAssertion(X509Credential credential,
                                                 SAMLAssertion assertion,
                                                 int lifetime)
                                          throws CredentialException {

        X509Extension extension = null;
        try {
            extension = new SAMLX509Extension(assertion);
        } catch (IOException e) {
            String msg = "Unable to create the SAML Extension";
            logger.error(msg);
            throw new CredentialException(msg, e);
        }
        X509ExtensionSet extensions = new X509ExtensionSet();
        extensions.add(extension);

        X509Credential cred =
            createCredential(credential, extensions, lifetime);

        X509Certificate cert = cred.getCertificateChain()[0];
        try {
            Date notBefore = assertion.getNotBefore();
            if (notBefore != null) {
                cert.checkValidity(notBefore);
            }
        } catch (CertificateNotYetValidException e) {
            String msg = "SAML NotBefore less than X.509 NotBefore";
            logger.error(msg);
            throw new CredentialException(msg, e);
        } catch (CertificateExpiredException e) {
            String msg = "SAML NotBefore greater than X.509 NotOnOrAfter";
            logger.error(msg);
            throw new CredentialException(msg, e);
        }
        try {
            Date notOnOrAfter = assertion.getNotOnOrAfter();
            if (notOnOrAfter != null) {
                cert.checkValidity(notOnOrAfter);
            }
        } catch (CertificateNotYetValidException e) {
            String msg = "SAML NotOnOrAfter less than X.509 NotBefore";
            logger.error(msg);
            throw new CredentialException(msg, e);
        } catch (CertificateExpiredException e) {
            String msg = "SAML NotOnOrAfter greater than X.509 NotOnOrAfter";
            logger.error(msg);
            throw new CredentialException(msg, e);
        }

        return cred;
    }

    /**
     * General utility method to create a Globus proxy credential.
     * The lifetime of the proxy defaults to a reasonable value.
     *
     * @param credential the issuing credential
     * @param extension an extension to bind to the proxy
     *
     * @return a Globus proxy credential
     *
     * @exception org.globus.gsi.CredentialException
     *            If the credential can not be created
     *
     * @since 0.3.0
     */
    public static X509Credential createCredential(X509Credential credential,
                                                    X509Extension extension)
                                             throws CredentialException {

        return createCredential(credential, extension, DEFAULT_LIFETIME);
    }

    /**
     * General utility method to create a Globus proxy credential.
     *
     * @param credential the issuing credential
     * @param extension an extension to bind to the proxy
     * @param lifetime the desired lifetime of the proxy
     *
     * @return a Globus proxy credential
     *
     * @exception org.globus.gsi.CredentialException
     *            If the credential can not be created
     *
     * @since 0.3.0
     */
    public static X509Credential createCredential(X509Credential credential,
                                                    X509Extension extension,
                                                    int lifetime)
                                             throws CredentialException {

        X509ExtensionSet extensions = new X509ExtensionSet();
        extensions.add(extension);

        return createCredential(credential, extensions, lifetime);
    }

    /**
     * General utility method to create a Globus proxy credential.
     * The lifetime of the proxy defaults to a reasonable value.
     *
     * @param credential the issuing credential
     * @param extensions a set of extensions to bind to the proxy
     *
     * @return a Globus proxy credential
     *
     * @exception org.globus.gsi.CredentialException
     *            If the credential can not be created
     *
     * @since 0.3.0
     */
    public static X509Credential createCredential(X509Credential credential,
                                                    X509ExtensionSet extensions)
                                             throws CredentialException {

        return createCredential(credential, extensions, DEFAULT_LIFETIME);
    }

    /**
     * General utility method to create a Globus proxy credential.
     *
     * @param credential the issuing credential
     * @param extensions a set of extensions to bind to the proxy
     * @param lifetime the desired lifetime of the proxy
     *
     * @return a Globus proxy credential
     *
     * @exception org.globus.gsi.CredentialException
     *            If the credential can not be created
     */
    public static X509Credential createCredential(X509Credential credential,
                                                    X509ExtensionSet extensions,
                                                    int lifetime)
                                             throws CredentialException {
        GSIConstants.DelegationType proxyType = GSIConstants.DelegationType.FULL;

        try {
            return certFactory.createCredential(
                credential.getCertificateChain(),
                (PrivateKey)credential.getPrivateKey(),
                512,
                lifetime,
                proxyType,
                extensions, null);
        } catch (GeneralSecurityException e) {
            throw new CredentialException("Failed to load credentials.", e);
        }
    }

    /**
     * General utility method to create a Globus X.509 credential
     * from a Java KeyStore.
     * If either <code>keyStoreFile</code>, <code>keyStorePassword</code>,
     * or <code>keyStoreKeyAlias</code> is null, the method throws an
     * <code>IllegalArgumentException</code>.
     * If <code>keyStoreKeyPassword</code> is null, the
     * <code>keyStorePassword</code> is tried in its place.
     *
     * @param keyStoreFile the file containing the Java KeyStore
     * @param keyStorePassword the KeyStore password
     * @param keyStoreKeyAlias the alias of the private key
     * @param keyStoreKeyPassword the password that protects the private key
     *
     * @return a Globus credential
     *
     * @exception org.globus.gsi.CredentialException
     *            If the credential can not be created
     */
    public static X509Credential createCredential(File keyStoreFile,
                                                    char[] keyStorePassword,
                                                    String keyStoreKeyAlias,
                                                    char[] keyStoreKeyPassword)
                                             throws CredentialException {

        // validate arguments:
        if (keyStoreFile == null ||
            keyStorePassword == null ||
            keyStoreKeyAlias == null) {

            String msg = "Null argument";
            throw new IllegalArgumentException(msg);
        }
        if (keyStoreKeyPassword == null) {
            String msg = "Null keyStoreKeyPassword, trying keyStorePassword";
            logger.warn(msg);
            keyStoreKeyPassword = keyStorePassword;
        }

        // get an instance of KeyStore:
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            //keyStore = KeyStore.getInstance("JKS");
        } catch (KeyStoreException e) {
            throw new CredentialException("Failed to load credentials.", e);
        }

        // load the KeyStore:
        FileInputStream in = null;
        try {
            in = new FileInputStream(keyStoreFile);
            keyStore.load(in, keyStorePassword);
        } catch (IOException e) {
            throw new CredentialException("Failed to load credentials.", e);
        } catch (NoSuchAlgorithmException e) {
            throw new CredentialException("Algorithm not supported.", e);
        } catch (CertificateException e) {
            throw new CredentialException("Failed to load credentials.", e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) { }
            }
        }

        PrivateKey privateKey = null;
        try {
            privateKey =
                (PrivateKey)keyStore.getKey(keyStoreKeyAlias, keyStoreKeyPassword);
        } catch (KeyStoreException e) {
            throw new CredentialException("Failed to load credentials.", e);
        } catch (NoSuchAlgorithmException e) {
            throw new CredentialException("Algorithm not supported.", e);
        } catch (UnrecoverableKeyException e) {
            throw new CredentialException("Failed to load credentials.", e);
        }
        if (privateKey == null) {
            String msg = "No private key found";
            throw new CredentialException(msg);
        }

        // get the certificate chain:
        Certificate[] certs = null;
        try {
            certs = keyStore.getCertificateChain(keyStoreKeyAlias);
            if (certs == null || certs.length == 0) {
                Certificate cert = keyStore.getCertificate(keyStoreKeyAlias);
                if (cert == null) {
                    String msg = "No certificate found";
                    throw new CredentialException(msg);
                }
                certs = new Certificate[]{cert};
            }
        } catch (KeyStoreException e) {
            throw new CredentialException("Failed to load credentials.", e);
        }
        X509Certificate[] x509certs = new X509Certificate[certs.length];
        for (int i = 0; i < certs.length; i++) {
            if (certs[i] instanceof X509Certificate) {
                x509certs[i] = (X509Certificate)certs[i];
            } else {
                String msg = "Expected X.509 certificate type.";
                throw new CredentialException(msg);
            }
        }

        return new X509Credential(privateKey, x509certs);
    }

    /**
     * General utility method to get a Globus X.509 credential
     * (EEC or proxy) in the usual place.
     *
     * @return a Globus credential
     *
     * @exception org.globus.gsi.CredentialException
     *            If the credential can not be found or is expired
     *
     * @see org.globus.gsi.X509Credential#getDefaultCredential()
     */
    public static X509Credential getCredential()
                                          throws CredentialException {

        return X509Credential.getDefaultCredential();
    }

    /**
     * General utility method to get a Globus X.509 credential
     * (EEC or proxy).
     * If <code>inputFilename</code> is null, the method throws
     * an <code>IllegalArgumentException</code>.
     *
     * @param inputFilename a (non-null) path to the X.509
     *        credential
     *
     * @return a Globus credential
     *
     * @exception org.globus.gsi.CredentialException
     *            If the credential can not be found or is expired
     *
     * @see org.globus.wsrf.impl.security.util.SAMLUtil#getCredential(String)
     */
    public static X509Credential getCredential(String inputFilename)
                                          throws CredentialException {

        /* Note: The behavior of this method differs from the
         * corresponding method in SAMLUtil.  This method throws
         * an exception if the argument is null whereas the
         * method in SAMLUtil falls back on the default proxy
         * credential.
         */

        // validate argument:
        if (inputFilename == null) {
            String msg = "Null argument";
            throw new IllegalArgumentException(msg);
        }

        X509Credential credential = new X509Credential(inputFilename);

        /* The following line of code works around a Globus bug:
         *
         * http://bugzilla.globus.org/globus/show_bug.cgi?id=4923
         *
         * The above GlobusCredential constructor does not throw
         * an exception if the credential is expired.
         */
        credential.verify();

        return credential;
    }

    /**
     * General utility method to get a Globus X.509 credential
     * (EEC or proxy).
     * If <code>inputFile</code> is null, the method throws
     * an <code>IllegalArgumentException</code>.
     *
     * @param inputFile a (non-null) file containing the X.509
     *        credential
     *
     * @return a Globus credential
     *
     * @exception org.globus.gsi.CredentialException
     *            If the credential can not be found or is expired
     *
     * @since 0.3.0
     */
    public static X509Credential getCredential(File inputFile)
                                          throws CredentialException {

        // validate argument:
        if (inputFile == null) {
            String msg = "Null argument";
            throw new IllegalArgumentException(msg);
        }

        X509Credential credential =
            new X509Credential(inputFile.getPath());

        /* The following line of code works around a Globus bug:
         *
         * http://bugzilla.globus.org/globus/show_bug.cgi?id=4923
         *
         * The above GlobusCredential constructor does not throw
         * an exception if the credential is expired.
         */
        credential.verify();

        return credential;
    }

    /**
     * General utility method to get a Globus X.509 credential
     * (EEC or proxy).
     * If <code>inputstream</code> is null, the method throws
     * an <code>IllegalArgumentException</code>.
     *
     * @param inputstream a (non-null) input stream from which
     *        to read the X.509 credential
     *
     * @return a Globus credential
     *
     * @exception org.globus.gsi.CredentialException
     *            If the credential can not be found or is expired
     *
     * @since 0.3.0
     */
    public static X509Credential getCredential(InputStream inputstream)
                                          throws CredentialException {

        // validate argument:
        if (inputstream == null) {
            String msg = "Null argument";
            throw new IllegalArgumentException(msg);
        }

        X509Credential credential = new X509Credential(inputstream);

        /* The following line of code works around a Globus bug:
         *
         * http://bugzilla.globus.org/globus/show_bug.cgi?id=4923
         *
         * The above GlobusCredential constructor does not throw
         * an exception if the credential is expired.
         *
         * credential.verify() is inefficient for checking expiration and will
         * enforce trusted path validation (which is unimportant or may be
         * broken on the client).
         */
        if (credential.getTimeLeft() <= 0) {
            throw new CredentialException("Expired credentials");
        }

        return credential;
    }

    /**
     * General utility method to get a Globus X.509 credential
     * (EEC or proxy).
     * If either <code>certFile</code> or <code>keyFile</code>
     * is null, the method throws an
     * <code>IllegalArgumentException</code>.
     *
     * @param certFile the file containing the PEM-encoded certificate
     * @param keyFile the file containing the PEM-encoded private key (unencrypted)
     *
     * @return a Globus credential
     *
     * @exception org.globus.gsi.CredentialException
     *            If the credential can not be found or is expired
     */
    public static X509Credential getCredential(File certFile, File keyFile)
                                          throws CredentialException {

        // validate arguments:
        if (certFile == null || keyFile == null) {
            String msg = "Null argument";
            throw new IllegalArgumentException(msg);
        }

        return getCredential(certFile.getPath(), keyFile.getPath());
    }

    /**
     * General utility method to get a Globus X.509 credential
     * (EEC or proxy).
     * If either <code>certPath</code> or <code>keyPath</code>
     * is null, the method throws an
     * <code>IllegalArgumentException</code>.
     *
     * @param certPath the path to the PEM-encoded certificate
     * @param keyPath the path to the PEM-encoded private key (unencrypted)
     *
     * @return a Globus credential
     *
     * @exception org.globus.gsi.CredentialException
     *            If the credential can not be found or is expired
     */
    public static X509Credential getCredential(String certPath, String keyPath)
                                          throws CredentialException {

        // validate arguments:
        if (certPath == null || keyPath == null) {
            String msg = "Null argument";
            throw new IllegalArgumentException(msg);
        }

        X509Credential cred;

        try {
            cred = new X509Credential(certPath, keyPath);
        } catch (IOException e) {
            throw new CredentialException(e);
        }

        return cred;
    }

    /**
     * Gets the identity associated with the given
     * <code>GlobusCredential</code>.  The identity is the
     * subject DN of the first non-impersonation proxy (which
     * is usually an end-entity certificate) in the proxy
     * certificate chain.
     *
     * @param credential a <code>GlobusCredential</code> instance
     * @return the subject DN (in RFC2253 format) of the first
     *         non-impersonation proxy in the proxy certificate chain
     *
     * @exception org.globus.gsi.CredentialException
     *            If the identity of the credential can not be obtained
     *
     * @see org.globus.gsi.X509Credential#getIdentity()
     *
     * @since 0.5.0
     */
    public static String getIdentity(X509Credential credential)
                              throws CredentialException {

        X509Certificate eec = null;
        try {
            eec = CertUtil.getEEC(credential.getCertificateChain());
        } catch (CertificateException e) {
            String msg = "Unable to retrieve the EEC: unknown certificate type";
            logger.error(msg, e);
            throw new CredentialException(msg, e);
        }
        if (eec == null) {
            String msg = "Certificate chain contains no EEC";
            logger.error(msg);
            throw new CredentialException(msg);
        }
        X500Principal certSubject = eec.getSubjectX500Principal();
        return certSubject.getName(X500Principal.RFC2253);
    }

    /**
     * Gets the default SAML issuer associated with the given
     * <code>GlobusCredential</code>.  The default SAML issuer
     * is the subject DN of the last proxy certificate in the
     * proxy certificate chain.
     *
     * @param credential a <code>GlobusCredential</code> instance
     * @return the subject DN (in RFC2253 format) of the last
     *         proxy certificate in the proxy certificate chain
     *
     * @since 0.5.0
     */
    public static String getDefaultSAMLIssuer(X509Credential credential) {

        X509Certificate cert = credential.getCertificateChain()[0];
        X500Principal credentialSubject = cert.getSubjectX500Principal();
        return credentialSubject.getName(X500Principal.RFC2253);
    }

    /**
     * @see org.globus.wsrf.impl.security.util.SAMLUtil#writeCredentialToFile(GlobusCredential, String)
     */
    public static boolean writeCredentialToFile(X509Credential credential,
                                                String outputFilename)
                                         throws SecurityException,
                                                FileNotFoundException,
                                                IOException {

        if (outputFilename == null) {
            String msg = "Null argument (outputFilename)";
            throw new IllegalArgumentException(msg);
        }

        File outputFile = Util.createFile(outputFilename);
        return writeCredentialToFile(credential, outputFile);
    }

    /**
     * Writes the given credential to the indicated file.
     *
     * @param credential a Globus GSI credential.
     * @param outputFile the file to write the credential to.
     * @exception IOException if any error occurs during the
     *            write operation.
     *
     * @since 0.3.0
     */
    public static boolean writeCredentialToFile(X509Credential credential,
                                                File outputFile)
                                         throws SecurityException,
                                                FileNotFoundException,
                                                IOException {

        //if (credential == null) {
        //    String msg = "Null argument (credential)";
        //    throw new IllegalArgumentException(msg);
        //}
        if (outputFile == null) {
            String msg = "Null argument (outputFile)";
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
            //credential.save(out);
            saveCredential(credential, out);
        } finally {
            if (out != null) {
                try { out.close(); } catch (IOException e) { }
            }
        }

        return result;
    }

    /**
     * A convenience method that prints the given credential
     * on stdout.  Calling this method is equivalent to calling
     * <pre>saveCredential(credential, System.out);</pre>
     *
     * @param credential a Globus GSI credential.
     * @exception IOException if any error occurs during the
     *            print operation.
     *
     * @since 0.3.0
     */
    public static void printCredential(X509Credential credential)
                                throws IOException {

        //credential.save(System.out);
        saveCredential(credential, System.out);
    }

    /**
     * Writes the given credential to the indicated output stream.
     * The caller is responsible for ultimately closing the output
     * stream.
     * <p>
     * This method works around a Globus bug:
     * http://bugzilla.globus.org/globus/show_bug.cgi?id=5543
     *
     * @param credential a Globus GSI credential.
     * @param out the output stream to write the credential to.
     * @exception IOException if any error occurs during the
     *            save operation.
     *
     * @since 0.3.0
     */
    public static void saveCredential(X509Credential credential,
                                      OutputStream out)
                               throws IOException {

        if (credential == null) {
            String msg = "Null argument (credential)";
            throw new IllegalArgumentException(msg);
        }

        X509Certificate[] certs = credential.getCertificateChain();
        try {
            CertificateIOUtil.writeCertificate(out, certs[0]);
            OpenSSLKey key =
                new BouncyCastleOpenSSLKey((PrivateKey)credential.getPrivateKey());
            key.writeTo(out);
            for (int i = 1; i < certs.length; i++) {
                CertificateIOUtil.writeCertificate(out, certs[i]);
            }
        } catch (CertificateEncodingException e) {
            throw new ChainedIOException(e.getMessage(), e);
        } catch (CredentialException e) {
            throw new IOException(e);
        }
        out.flush();
    }

    /**
     * Convert a Globus credential to a GSS credential.
     *
     * @param cred a non-null Globus GSI credential
     * @return a GSS credential
     * @exception GSSException if unable to create a GSS credential
     *
     * @since 0.3.0
     */
    public static GSSCredential toGSSCredential(X509Credential cred)
                                         throws GSSException {

        if (cred == null) {
            String msg = "Null argument (cred)";
            throw new IllegalArgumentException(msg);
        }

        int usage = GSSCredential.INITIATE_AND_ACCEPT;
        return new GlobusGSSCredentialImpl(cred, usage);
    }

    /**
     * Convert a GSS credential to a Globus credential.
     *
     * @param gsscred a non-null GSS credential
     * @return a Globus GSI credential, which may be null if the
     *         given GSS credential is an anonymous credential
     * @exception GSSException if the given GSS credential is not
     *            of type <code>GlobusGSSCredentialImpl</code>
     *
     * @since 0.3.0
     */
    public static X509Credential toGlobusCredential(GSSCredential gsscred)
                                               throws GSSException {

        if (gsscred == null) {
            String msg = "Null argument (gsscred)";
            throw new IllegalArgumentException(msg);
        }

        if (gsscred instanceof GlobusGSSCredentialImpl) {
            return ((GlobusGSSCredentialImpl)gsscred).getX509Credential();
        }

        String msg = "Argument is not of type GlobusGSSCredentialImpl";
        throw new GSSException(GSSException.FAILURE,      // major code
                               GSSException.UNAVAILABLE,  // minor code
                               msg);
    }
}
