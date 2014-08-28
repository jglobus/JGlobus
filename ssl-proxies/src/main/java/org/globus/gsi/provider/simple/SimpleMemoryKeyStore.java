package org.globus.gsi.provider.simple;

import org.apache.commons.logging.Log;

import org.apache.commons.logging.LogFactory;

import java.security.KeyStore.LoadStoreParameter;

import java.util.Collections;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.security.cert.X509Certificate;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;
import java.security.KeyStoreSpi;

/**
 * @deprecated
 */
public class SimpleMemoryKeyStore extends KeyStoreSpi {

    private Log logger = LogFactory.getLog(SimpleMemoryKeyStore.class);
    private Map<String, X509Certificate> certMap;

    @Override
    public void engineLoad(LoadStoreParameter params) throws IOException, NoSuchAlgorithmException,
        CertificateException {
        logger.debug("creating cert store.");
        if (params == null) {
            throw new IllegalArgumentException("parameter null");
        } else if (!(params instanceof SimpleMemoryKeyStoreLoadStoreParameter)) {
            throw new IllegalArgumentException("Wrong parameter type");
        }
        X509Certificate[] certs = ((SimpleMemoryKeyStoreLoadStoreParameter) params).getCerts();
        this.certMap = new ConcurrentHashMap<String,X509Certificate>();
        if (certs != null) {
            for (X509Certificate cert : certs) {
                if (cert != null) {
                    logger.debug("adding cert " + cert.getSubjectDN().getName());
                    certMap.put(cert.getSubjectDN().getName(), cert);
                }
            }
        }
    }

    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(this.certMap.keySet());
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return this.certMap.containsKey(alias);
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        this.certMap.remove(alias);
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        return this.certMap.get(alias);
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        return engineContainsAlias(alias);

    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        return false;
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        if (cert == null) {
            return;
        }
        if (cert instanceof X509Certificate) {
            this.certMap.put(alias, (X509Certificate) cert);
        } else {
            throw new IllegalArgumentException("Certificate should be X509Cert");
        }
    }

    @Override
    public int engineSize() {
        return this.certMap.size();
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException,
        CertificateException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException,
        CertificateException {
        throw new UnsupportedOperationException();
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        throw new UnsupportedOperationException();
    }

}
