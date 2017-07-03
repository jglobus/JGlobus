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
package org.globus.gsi.provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class MockKeyStore extends KeyStoreSpi {

    private Hashtable<String, X509Certificate> certificateMap = new Hashtable();

    /**
     * Returns the key associated with the given alias, using the given password
     * to recover it.  The key must have been associated with the alias by a
     * call to <code>setKeyEntry</code>, or by a call to <code>setEntry</code>
     * with a <code>PrivateKeyEntry</code> or <code>SecretKeyEntry</code>.
     *
     * @param alias    the alias name
     * @param password the password for recovering the key
     * @return the requested key, or null if the given alias does not exist or
     *         does not identify a key-related entry.
     * @throws java.security.NoSuchAlgorithmException
     *          if the algorithm for recovering the key cannot be found
     * @throws java.security.UnrecoverableKeyException
     *          if the key cannot be recovered (e.g., the given password is
     *          wrong).
     */
    public Key engineGetKey(String alias, char[] password)
            throws NoSuchAlgorithmException, UnrecoverableKeyException {
        throw new UnsupportedOperationException();
    }

    /**
     * Returns the certificate chain associated with the given alias. The
     * certificate chain must have been associated with the alias by a call to
     * <code>setKeyEntry</code>, or by a call to <code>setEntry</code> with a
     * <code>PrivateKeyEntry</code>.
     *
     * @param alias the alias name
     * @return the certificate chain (ordered with the user's certificate first
     *         and the root certificate authority last), or null if the given
     *         alias does not exist or does not contain a certificate chain
     */
    public Certificate[] engineGetCertificateChain(String alias) {
        throw new UnsupportedOperationException();
    }

    /**
     * Returns the certificate associated with the given alias.
     * <p>
     * If the given alias name identifies an entry created by a call to
     * <code>setCertificateEntry</code>, or created by a call to
     * <code>setEntry</code> with a <code>TrustedCertificateEntry</code>, then
     * the trusted certificate contained in that entry is returned.
     * <p>
     * If the given alias name identifies an entry created by a call to
     * <code>setKeyEntry</code>, or created by a call to <code>setEntry</code>
     * with a <code>PrivateKeyEntry</code>, then the first element of the
     * certificate chain in that entry (if a chain exists) is returned.
     *
     * @param alias the alias name
     * @return the certificate, or null if the given alias does not exist or
     *         does not contain a certificate.
     */
    public Certificate engineGetCertificate(String alias) {
        return this.certificateMap.get(alias);
    }

    /**
     * Returns the creation date of the entry identified by the given alias.
     *
     * @param alias the alias name
     * @return the creation date of this entry, or null if the given alias does
     *         not exist
     */
    public Date engineGetCreationDate(String alias) {
        throw new UnsupportedOperationException();
    }

    /**
     * Assigns the given key to the given alias, protecting it with the given
     * password.
     * <p>
     * If the given key is of type <code>java.security.PrivateKey</code>, it
     * must be accompanied by a certificate chain certifying the corresponding
     * public key.
     * <p>
     * If the given alias already exists, the keystore information associated
     * with it is overridden by the given key (and possibly certificate chain).
     *
     * @param alias    the alias name
     * @param key      the key to be associated with the alias
     * @param password the password to protect the key
     * @param chain    the certificate chain for the corresponding public key
     *                 (only required if the given key is of type
     *                 <code>java.security.PrivateKey</code>).
     * @throws java.security.KeyStoreException
     *          if the given key cannot be protected, or this operation fails
     *          for some other reason
     */
    public void engineSetKeyEntry(String alias, Key key, char[] password,
                                  Certificate[] chain)
            throws KeyStoreException {
        throw new UnsupportedOperationException();
    }

    /**
     * Assigns the given key (that has already been protected) to the given
     * alias.
     * <p>
     * If the protected key is of type <code>java.security.PrivateKey</code>,
     * it must be accompanied by a certificate chain certifying the
     * corresponding public key.
     * <p>
     * If the given alias already exists, the keystore information associated
     * with it is overridden by the given key (and possibly certificate chain).
     *
     * @param alias the alias name
     * @param key   the key (in protected format) to be associated with the
     *              alias
     * @param chain the certificate chain for the corresponding public key (only
     *              useful if the protected key is of type <code>java.security.PrivateKey</code>).
     * @throws java.security.KeyStoreException
     *          if this operation fails.
     */
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain)
            throws KeyStoreException {
        throw new UnsupportedOperationException();
    }

    /**
     * Assigns the given certificate to the given alias.
     * <p>
     * If the given alias identifies an existing entry created by a call to
     * <code>setCertificateEntry</code>, or created by a call to
     * <code>setEntry</code> with a <code>TrustedCertificateEntry</code>, the
     * trusted certificate in the existing entry is overridden by the given
     * certificate.
     *
     * @param alias the alias name
     * @param cert  the certificate
     * @throws java.security.KeyStoreException
     *          if the given alias already exists and does not identify an entry
     *          containing a trusted certificate, or this operation fails for
     *          some other reason.
     */
    public void engineSetCertificateEntry(String alias, Certificate cert)
            throws KeyStoreException {
        if (cert == null) {
            return;
        }
        if (cert instanceof X509Certificate) {
            this.certificateMap.put(alias, (X509Certificate) cert);
        } else {
            throw new IllegalArgumentException(
                    "Certificate should be X509Cert");
        }

    }

    /**
     * Deletes the entry identified by the given alias from this keystore.
     *
     * @param alias the alias name
     * @throws java.security.KeyStoreException
     *          if the entry cannot be removed.
     */
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        this.certificateMap.remove(alias);
    }

    /**
     * Lists all the alias names of this keystore.
     *
     * @return enumeration of the alias names
     */
    public Enumeration<String> engineAliases() {
        return this.certificateMap.keys();
    }

    /**
     * Checks if the given alias exists in this keystore.
     *
     * @param alias the alias name
     * @return true if the alias exists, false otherwise
     */
    public boolean engineContainsAlias(String alias) {
        if (this.certificateMap.containsKey(alias)) {
            return true;
        }
        return false;
    }

    /**
     * Retrieves the number of entries in this keystore.
     *
     * @return the number of entries in this keystore
     */
    public int engineSize() {
        return this.certificateMap.size();
    }

    /**
     * Returns true if the entry identified by the given alias was created by a
     * call to <code>setKeyEntry</code>, or created by a call to
     * <code>setEntry</code> with a <code>PrivateKeyEntry</code> or a
     * <code>SecretKeyEntry</code>.
     *
     * @param alias the alias for the keystore entry to be checked
     * @return true if the entry identified by the given alias is a key-related,
     *         false otherwise.
     */
    public boolean engineIsKeyEntry(String alias) {
        return false;  //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

    /**
     * Returns true if the entry identified by the given alias was created by a
     * call to <code>setCertificateEntry</code>, or created by a call to
     * <code>setEntry</code> with a <code>TrustedCertificateEntry</code>.
     *
     * @param alias the alias for the keystore entry to be checked
     * @return true if the entry identified by the given alias contains a
     *         trusted certificate, false otherwise.
     */
    public boolean engineIsCertificateEntry(String alias) {
        if (engineContainsAlias(alias)) {
            return true;
        }
        return false;
    }

    /**
     * Returns the (alias) name of the first keystore entry whose certificate
     * matches the given certificate.
     * <p>
     * This method attempts to match the given certificate with each keystore
     * entry. If the entry being considered was created by a call to
     * <code>setCertificateEntry</code>, or created by a call to
     * <code>setEntry</code> with a <code>TrustedCertificateEntry</code>, then
     * the given certificate is compared to that entry's certificate.
     * <p>
     * If the entry being considered was created by a call to
     * <code>setKeyEntry</code>, or created by a call to <code>setEntry</code>
     * with a <code>PrivateKeyEntry</code>, then the given certificate is
     * compared to the first element of that entry's certificate chain.
     *
     * @param cert the certificate to match with.
     * @return the alias name of the first entry with matching certificate, or
     *         null if no such entry exists in this keystore.
     */
    public String engineGetCertificateAlias(Certificate cert) {
        throw new UnsupportedOperationException();
    }

    /**
     * Stores this keystore to the given output stream, and protects its
     * integrity with the given password.
     *
     * @param stream   the output stream to which this keystore is written.
     * @param password the password to generate the keystore integrity check
     * @throws java.io.IOException if there was an I/O problem with data
     * @throws java.security.NoSuchAlgorithmException
     *                             if the appropriate data integrity algorithm
     *                             could not be found
     * @throws java.security.cert.CertificateException
     *                             if any of the certificates included in the
     *                             keystore data could not be stored
     */
    public void engineStore(OutputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        throw new UnsupportedOperationException();
    }

    /**
     * Loads the keystore from the given input stream.
     * <p>
     * A password may be given to unlock the keystore (e.g. the keystore
     * resides on a hardware token device), or to check the integrity of the
     * keystore data. If a password is not given for integrity checking, then
     * integrity checking is not performed.
     *
     * @param stream   the input stream from which the keystore is loaded, or
     *                 <code>null</code>
     * @param password the password used to check the integrity of the keystore,
     *                 the password used to unlock the keystore, or
     *                 <code>null</code>
     * @throws java.io.IOException if there is an I/O or format problem with the
     *                             keystore data, if a password is required but
     *                             not given, or if the given password was
     *                             incorrect
     * @throws java.security.NoSuchAlgorithmException
     *                             if the algorithm used to check the integrity
     *                             of the keystore cannot be found
     * @throws java.security.cert.CertificateException
     *                             if any of the certificates in the keystore
     *                             could not be loaded
     */
    public void engineLoad(InputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        // To force keystore initialization
        // empty impl.
    }
}
