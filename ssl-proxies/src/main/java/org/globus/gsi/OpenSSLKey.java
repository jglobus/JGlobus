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

import org.globus.gsi.util.FileUtil;
import org.globus.gsi.util.PEMUtil;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.Serializable;
import java.io.Writer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.StringTokenizer;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.Arrays;

import org.bouncycastle.util.encoders.Base64;

/**
 * Represents a OpenSSL-style PEM-formatted private key. It supports encryption and decryption of the key. Currently,
 * only RSA keys are supported, and only TripleDES encryption is supported.
 * <p>
 * This is based on work done by Ming Yung at DSTC.
 *
 * @version ${version}
 * @since 1.0
 */
public abstract class OpenSSLKey implements Serializable {

    private static final String HEADER = "-----BEGIN RSA PRIVATE KEY-----";

    /* Key algorithm: RSA, DSA */
    private String keyAlg;
    /* Current state of this key class */
    private boolean isEncrypted;

    // base64 encoded key value
    private byte[] encodedKey;
    private PrivateKey intKey;
    private byte[] ivData;
    private transient IvParameterSpec initializationVector;

    /*
     * String representation of the encryption algorithm:
     * DES-EDE3-CBC, AES-256-CBC, etc.
     */
    private String encAlgStr;

    /*
     * Java string representation of the encryption algorithm:
     * DES, DESede, AES.
     */
    private String encAlg;
    private int keyLength = -1;
    private int ivLength = -1;

    // ASN.1 encoded key value
    private byte[] keyData;

    /**
     * Reads a OpenSSL private key from the specified input stream.
     * The private key must be PEM encoded and can be encrypted.
     *
     * @param is input stream with OpenSSL key in PEM format.
     * @throws IOException              if I/O problems.
     * @throws GeneralSecurityException if problems with the key
     */
    public OpenSSLKey(InputStream is) throws IOException, GeneralSecurityException {
        InputStreamReader isr = new InputStreamReader(is);
        try {
            readPEM(isr);
        } finally {
            isr.close();
        }
    }

    /**
     * Reads a OpenSSL private key from the specified file.
     * The private key must be PEM encoded and can be encrypted.
     *
     * @param file file containing the OpenSSL key in PEM format.
     * @throws IOException              if I/O problems.
     * @throws GeneralSecurityException if problems with the key
     */
    public OpenSSLKey(String file) throws IOException, GeneralSecurityException {
        FileReader f = new FileReader(file);
        try {
            readPEM(f);
        } finally {
            f.close();
        }
    }

    /**
     * Converts a RSAPrivateCrtKey into OpenSSL key.
     *
     * @param key private key - must be a RSAPrivateCrtKey
     */
    public OpenSSLKey(PrivateKey key) {
        this.intKey = key;
        this.isEncrypted = false;
        this.keyData = getEncoded(key);
        this.encodedKey = null;
    }

    /**
     * Initializes the OpenSSL key from raw byte array.
     *
     * @param algorithm the algorithm of the key. Currently only RSA algorithm is supported.
     * @param data      the DER encoded key data. If RSA algorithm, the key must be in PKCS#1 format.
     * @throws GeneralSecurityException if any security problems.
     */
    public OpenSSLKey(String algorithm, byte[] data) throws GeneralSecurityException {
        if (data == null) {
            throw new IllegalArgumentException("Data is null");
        }
        this.keyData = new byte[data.length];
        System.arraycopy(data, 0, this.keyData, 0, data.length);
        this.isEncrypted = false;
        this.intKey = getKey(algorithm, data);
    }

    protected byte[] getEncoded() {
        return this.keyData;
    }

    private void readPEM(Reader rd) throws IOException, GeneralSecurityException {
        StringBuilder builder = new StringBuilder();

        BufferedReader in = new BufferedReader(rd);
        try {
            parseKeyAlgorithm(in);
            builder.append(extractEncryptionInfo(in));
            builder.append(extractKey(in));
        } finally {
            in.close();
        }

        this.encodedKey = builder.toString().getBytes();

        if (isEncrypted()) {
            this.keyData = null;
        } else {
            if (keyAlg != "PKCS8") {
                this.keyData = Base64.decode(encodedKey);
                this.intKey = getKey(keyAlg, keyData);
            } else {
                // workaround for PKCS#8 encoded keys (only for keys without encryption)
                keyAlg = "RSA";
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.decode(encodedKey));
                KeyFactory kfac = KeyFactory.getInstance("RSA");
                this.intKey = kfac.generatePrivate(spec);
                this.keyData = getEncoded(this.intKey);
            }
        }
    }

    private String extractKey(BufferedReader in) throws IOException {
        StringBuilder builder = new StringBuilder();
        String next = in.readLine();
        while (next != null) {
            if (next.startsWith("-----END")) {
                break;
            }
            builder.append(next);
            next = in.readLine();
        }
        return builder.toString();
    }

    private String extractEncryptionInfo(BufferedReader in) throws IOException, GeneralSecurityException {
        StringBuilder sb = new StringBuilder();
        String next = in.readLine();
        if (next != null && next.startsWith("Proc-Type: 4,ENCRYPTED")) {
            this.isEncrypted = true;
            next = in.readLine();
            if (next != null) {
                parseEncryptionInfo(next);
            }
            in.readLine();
        } else {
            this.isEncrypted = false;
            sb.append(next);
        }
        return sb.toString();
    }

    private void parseKeyAlgorithm(BufferedReader in) throws IOException, InvalidKeyException {
        String next = in.readLine();
        while (next != null) {
            if (next.indexOf("BEGIN PRIVATE KEY") != -1) {
                keyAlg = "PKCS8";
                break;
            } else if (next.indexOf("PRIVATE KEY") != -1) {
                keyAlg = getKeyAlgorithm(next);
                break;
            }
            next = in.readLine();
        }

        if (next == null) {
            throw new InvalidKeyException("noPrivateKey");
        }

        if (keyAlg == null) {
            throw new InvalidKeyException("algNotSup");
        }
    }

    /**
     * Check if the key was encrypted or not.
     *
     * @return true if the key is encrypted, false
     *         otherwise.
     */
    public boolean isEncrypted() {
        return this.isEncrypted;
    }

    /**
     * Decrypts the private key with given password.
     * Does nothing if the key is not encrypted.
     *
     * @param password password to decrypt the key with.
     * @throws GeneralSecurityException whenever an error occurs during decryption.
     */
    public void decrypt(String password) throws GeneralSecurityException {
        decrypt(password.getBytes());
    }

    /**
     * Decrypts the private key with given password.
     * Does nothing if the key is not encrypted.
     *
     * @param password password to decrypt the key with.
     * @throws GeneralSecurityException whenever an error occurs during decryption.
     */
    public void decrypt(byte[] password) throws GeneralSecurityException {
        if (!isEncrypted()) {
            return;
        }

        byte[] enc = Base64.decode(this.encodedKey);

        SecretKeySpec key = getSecretKey(password, this.initializationVector.getIV());

        Cipher cipher = getCipher();
        cipher.init(Cipher.DECRYPT_MODE, key, this.initializationVector);
        enc = cipher.doFinal(enc);

        this.intKey = getKey(this.keyAlg, enc);
        this.keyData = enc;
        this.isEncrypted = false;
        this.encodedKey = null;
    }

    /**
     * Encrypts the private key with given password.
     * Does nothing if the key is encrypted already.
     *
     * @param password password to encrypt the key with.
     * @throws GeneralSecurityException whenever an error occurs during encryption.
     */
    public void encrypt(String password) throws GeneralSecurityException {
        encrypt(password.getBytes());
    }

    /**
     * Encrypts the private key with given password.
     * Does nothing if the key is encrypted already.
     *
     * @param password password to encrypt the key with.
     * @throws GeneralSecurityException whenever an error occurs during encryption.
     */
    public void encrypt(byte[] password) throws GeneralSecurityException {

        if (isEncrypted()) {
            return;
        }

        if (this.encAlg == null) {
            setEncryptionAlgorithm("DES-EDE3-CBC");
        }

        if (this.ivData == null) {
            generateIV();
        }

        Key key = getSecretKey(password, this.initializationVector.getIV());

        Cipher cipher = getCipher();
        cipher.init(Cipher.ENCRYPT_MODE, key, this.initializationVector);

        /* encrypt the raw PKCS11 */

        this.keyData = cipher.doFinal(getEncoded(this.intKey));
        this.isEncrypted = true;
        this.encodedKey = null;
    }

    /**
     * Sets algorithm for encryption.
     *
     * @param alg algorithm for encryption
     * @throws GeneralSecurityException if algorithm is not supported
     */
    public void setEncryptionAlgorithm(String alg) throws GeneralSecurityException {
        setAlgorithmSettings(alg);
    }

    /**
     * Returns the JCE (RSAPrivateCrtKey) key.
     *
     * @return the private key, null if the key
     *         was not decrypted yet.
     */
    public PrivateKey getPrivateKey() {
        return this.intKey;
    }

    /**
     * Writes the private key to the specified output stream in PEM
     * format. If the key was encrypted it will be encoded as an encrypted
     * RSA key. If not, it will be encoded as a regular RSA key.
     *
     * @param output output stream to write the key to.
     * @throws IOException if I/O problems writing the key
     */
    public void writeTo(OutputStream output) throws IOException {
        output.write(toPEM().getBytes());
    }

    /**
     * Writes the private key to the specified writer in PEM format.
     * If the key was encrypted it will be encoded as an encrypted
     * RSA key. If not, it will be encoded as a regular RSA key.
     *
     * @param w writer to output the key to.
     * @throws IOException if I/O problems writing the key
     */
    public void writeTo(Writer w) throws IOException {
        w.write(toPEM());
    }

    /**
     * Writes the private key to the specified file in PEM format.
     * If the key was encrypted it will be encoded as an encrypted
     * RSA key. If not, it will be encoded as a regular RSA key.
     *
     * @param file file to write the key to.
     * @throws IOException if I/O problems writing the key
     */
    public void writeTo(String file) throws IOException {
    	File privateKey = FileUtil.createFile(file);
        // JGLOBUS-96
        try{
        	privateKey.setReadable(false, true);//setOwnerAccessOnly(file);
        	privateKey.setWritable(false, true);//setOwnerAccessOnly(file);
        }catch(SecurityException e){

        }
        PrintWriter p = new PrintWriter(new FileOutputStream(privateKey));

        try {
            p.write(toPEM());
        } finally {
            p.close();
        }
    }

    /*
     * Returns DER encoded byte array (PKCS#1).
     */

    protected abstract byte[] getEncoded(PrivateKey key);

    /*
     * Returns PrivateKey object initialized from give byte array (in PKCS#1 format)
     */

    protected abstract PrivateKey getKey(String alg, byte[] data) throws GeneralSecurityException;

    protected String getProvider() {
        return null;
    }

    private Cipher getCipher() throws GeneralSecurityException {
        String provider = getProvider();
        if (provider == null) {
            return Cipher.getInstance(this.encAlg + "/CBC/PKCS5Padding");
        } else {
            return Cipher.getInstance(this.encAlg + "/CBC/PKCS5Padding",
                    provider);
        }
    }

    private String getKeyAlgorithm(String line) {
        if (line.contains("RSA")) {
            return "RSA";
        } else if (line.contains("DSA")) {
            return "DSA";
        } else {
            return null;
        }
    }

    private void parseEncryptionInfo(String line) throws GeneralSecurityException {
        // TODO: can make this better
        String keyInfo = line.substring(10);
        StringTokenizer tknz = new StringTokenizer(keyInfo, ",", false);
        // set algorithm settings
        setAlgorithmSettings(tknz.nextToken());
        // set IV
        setIV(tknz.nextToken());
    }

    private void setAlgorithmSettings(String alg) throws GeneralSecurityException {
        if (alg.equals("DES-EDE3-CBC")) {
            this.encAlg = "DESede";
            this.keyLength = OpenSSLKeyConstants.DES_EDE3_CBC_KEY_LENGTH;
            this.ivLength = OpenSSLKeyConstants.DES_EDE3_CBC_IV_LENGTH;
        } else if (alg.equals("AES-128-CBC")) {
            this.encAlg = "AES";
            this.keyLength = OpenSSLKeyConstants.AES_128_CBC_KEY_LENGTH;
            this.ivLength = OpenSSLKeyConstants.AES_128_CBC_IV_LENGTH;
        } else if (alg.equals("AES-192-CBC")) {
            this.encAlg = "AES";
            this.keyLength = OpenSSLKeyConstants.AES_192_CBC_KEY_LENGTH;
            this.ivLength = OpenSSLKeyConstants.AES_192_CBC_IV_LENGTH;
        } else if (alg.equals("AES-256-CBC")) {
            this.encAlg = "AES";
            this.keyLength = OpenSSLKeyConstants.AES_256_CBC_KEY_LENGTH;
            this.ivLength = OpenSSLKeyConstants.AES_256_CBC_IV_LENGTH;
        } else if (alg.equals("DES-CBC")) {
            this.encAlg = "DES";
            this.keyLength = OpenSSLKeyConstants.DES_CBC_KEY_LENGTH;
            this.ivLength = OpenSSLKeyConstants.DES_CBC_IV_LENGTH;
        } else {
            throw new GeneralSecurityException("unsupported Enc algorithm " + alg);
        }
        this.encAlgStr = alg;
    }

    private void setIV(String s) throws GeneralSecurityException {
        int len = s.length() / 2;
        if (len != this.ivLength) {
            String err = "ivLength";
            //JGLOBUS-91
            throw new GeneralSecurityException(err);
        }
        byte[] ivBytes = new byte[len];
        for (int j = 0; j < len; j++) {
            ivBytes[j] = (byte) Integer.parseInt(s.substring(j * 2, j * 2 + 2), 16);
        }
        setIV(ivBytes);
    }

    private void generateIV() {
        byte[] b = new byte[this.ivLength];
        SecureRandom sr = new SecureRandom(); //.getInstance("PRNG");
        sr.nextBytes(b);
        setIV(b);
    }

    private void setIV(byte[] data) {
        ivData = data;
        initializationVector = new IvParameterSpec(data);
    }

    private SecretKeySpec getSecretKey(byte[] pwd, byte[] keyInitializationVector) throws GeneralSecurityException {

        byte[] key = new byte[this.keyLength];
        int offset = 0;
        int bytesNeeded = this.keyLength;

        MessageDigest md5 = MessageDigest.getInstance("MD5");
        while (true) {
            md5.update(pwd);
            md5.update(keyInitializationVector, 0, 8);

            byte[] b = md5.digest();

            int len = (bytesNeeded > b.length) ? b.length : bytesNeeded;

            System.arraycopy(b, 0, key, offset, len);

            offset += len;

            // check if we need any more
            bytesNeeded = key.length - offset;
            if (bytesNeeded == 0) {
                break;
            }

            // do another round
            md5.reset();
            md5.update(b);
        }

        return new SecretKeySpec(key, this.encAlg);
    }

    // -------------------------------------------

    /*
     * Converts to PEM encoding.
     * Assumes keyData is initialized.
     */

    private String toPEM() {

        byte[] data = (this.keyData == null) ? this.encodedKey : Base64.encode(this.keyData);

        String header = HEADER;

        if (isEncrypted()) {
            StringBuffer buf = new StringBuffer(header);
            buf.append(PEMUtil.LINE_SEP);
            buf.append("Proc-Type: 4,ENCRYPTED");
            buf.append(PEMUtil.LINE_SEP);
            buf.append("DEK-Info: ").append(this.encAlgStr);
            buf.append(",").append(PEMUtil.toHex(initializationVector.getIV()));
            buf.append(PEMUtil.LINE_SEP);
            header = buf.toString();
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        try {
            PEMUtil.writeBase64(out,
                    header,
                    data,
                    "-----END RSA PRIVATE KEY-----");
        } catch (IOException e) {
            // JGLOBUS-91
            throw new RuntimeException("Unexpected error", e);
        }

        return new String(out.toByteArray());
    }

    private void readObject(ObjectInputStream s) throws IOException, ClassNotFoundException {
        s.defaultReadObject();

        if(ivData != null) {
            initializationVector = new IvParameterSpec(ivData);
        }
    }

    @Override
    public boolean equals(Object other) {
        if(other == this) {
            return true;
        }

        if(!(other instanceof OpenSSLKey)) {
            return false;
        }

        OpenSSLKey otherKey = (OpenSSLKey) other;

        return this.isEncrypted == otherKey.isEncrypted &&
                objectsEquals(this.keyAlg, otherKey.keyAlg) &&
                Arrays.areEqual(this.encodedKey, otherKey.encodedKey) &&
                objectsEquals(this.intKey, otherKey.intKey) &&
                Arrays.areEqual(this.ivData, otherKey.ivData) &&
                objectsEquals(this.encAlgStr, otherKey.encAlgStr) &&
                objectsEquals(this.encAlg, otherKey.encAlg) &&
                Arrays.areEqual(this.keyData, otherKey.keyData);
    }

    // Equivalent to Java 7 Objects#equals method; may be replaced when
    // Java 7 is adopted
    private static boolean objectsEquals(Object a, Object b) {
        return (a == b) || (a != null && a.equals(b));
    }

    @Override
    public int hashCode() {
        return (isEncrypted ? 1 : 0) ^
                (keyAlg == null ? 0 : keyAlg.hashCode()) ^
                (encodedKey == null ? 0 : encodedKey.hashCode()) ^
                (intKey == null ? 0 : intKey.hashCode()) ^
                (ivData == null ? 0 : ivData.hashCode()) ^
                (encAlgStr == null ? 0 : encAlgStr.hashCode()) ^
                (encAlg == null ? 0 : encAlg.hashCode()) ^
                (keyData == null ? 0 : keyData.hashCode());
    }
}
