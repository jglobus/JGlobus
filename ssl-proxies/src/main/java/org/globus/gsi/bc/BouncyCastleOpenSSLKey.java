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

import org.apache.commons.logging.LogFactory;

import org.apache.commons.logging.Log;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKeyStructure;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.globus.gsi.OpenSSLKey;

/**
 * BouncyCastle-based implementation of OpenSSLKey.
 *
 * @version ${version}
 * @since 1.0
 */
public class BouncyCastleOpenSSLKey extends OpenSSLKey {
	private static final long serialVersionUID = 1L;
	private Log logger = LogFactory.getLog(getClass().getCanonicalName());

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Reads a OpenSSL private key from the specified input stream. The private
	 * key must be PEM encoded and can be encrypted.
	 *
	 * @param is
	 *            input stream with OpenSSL key in PEM format.
	 * @throws IOException
	 *             if I/O problems.
	 * @throws GeneralSecurityException
	 *             if problems with the key
	 */
	public BouncyCastleOpenSSLKey(InputStream is) throws IOException,
			GeneralSecurityException {
		super(is);
	}

	/**
	 * Reads a OpenSSL private key from the specified file. The private key must
	 * be PEM encoded and can be encrypted.
	 *
	 * @param file
	 *            file containing the OpenSSL key in PEM format.
	 * @throws IOException
	 *             if I/O problems.
	 * @throws GeneralSecurityException
	 *             if problems with the key
	 */
	public BouncyCastleOpenSSLKey(String file) throws IOException,
			GeneralSecurityException {
		super(file);
	}

	/**
	 * Converts a RSAPrivateCrtKey into OpenSSL key.
	 *
	 * @param key
	 *            private key - must be a RSAPrivateCrtKey
	 */
	public BouncyCastleOpenSSLKey(PrivateKey key) {
		super(key);
	}

	/**
	 * Initializes the OpenSSL key from raw byte array.
	 *
	 * @param algorithm
	 *            the algorithm of the key. Currently only RSA algorithm is
	 *            supported.
	 * @param data
	 *            the DER encoded key data. If RSA algorithm, the key must be in
	 *            PKCS#1 format.
	 * @throws GeneralSecurityException
	 *             if any security problems.
	 */
	public BouncyCastleOpenSSLKey(String algorithm, byte[] data)
			throws GeneralSecurityException {
		super(algorithm, data);
	}

	protected PrivateKey getKey(String alg, byte[] data)
			throws GeneralSecurityException {
		if (alg.equals("RSA")) {
			try {
				if (data.length == 0) {
					throw new GeneralSecurityException(
							"Cannot process empty byte stream.");
				}
				ByteArrayInputStream bis = new ByteArrayInputStream(data);
				ASN1InputStream derin = new ASN1InputStream(bis);
				ASN1Primitive keyInfo = derin.readObject();

				ASN1ObjectIdentifier rsaOid = PKCSObjectIdentifiers.rsaEncryption;
				AlgorithmIdentifier rsa = new AlgorithmIdentifier(rsaOid);
				PrivateKeyInfo pkeyinfo = new PrivateKeyInfo(rsa, keyInfo);
				ASN1Primitive derkey = pkeyinfo.toASN1Primitive();
				byte[] keyData = BouncyCastleUtil.toByteArray(derkey);
				// The DER object needs to be mangled to
				// create a proper ProvateKeyInfo object
				PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyData);
				KeyFactory kfac = KeyFactory.getInstance("RSA");

				return kfac.generatePrivate(spec);
			} catch (IOException e) {
				// that should never happen
				return null;
			}

		} else {
			return null;
		}
	}

	protected byte[] getEncoded(PrivateKey key) {
		String format = key.getFormat();
		if (format != null
				&& (format.equalsIgnoreCase("PKCS#8") || format
						.equalsIgnoreCase("PKCS8"))) {
			try {
				ASN1Primitive keyInfo = BouncyCastleUtil.toASN1Primitive(key
						.getEncoded());
				PrivateKeyInfo pkey = new PrivateKeyInfo((ASN1Sequence) keyInfo);
				ASN1Primitive derKey = pkey.getPrivateKey();
				return BouncyCastleUtil.toByteArray(derKey);
			} catch (IOException e) {
				// that should never happen
				logger.warn("This shouldn't have happened.", e);
				return new byte[] {};
			}
		} else if (format != null && format.equalsIgnoreCase("PKCS#1")
				&& key instanceof RSAPrivateCrtKey) {
			// this condition will rarely be true
			RSAPrivateCrtKey pKey = (RSAPrivateCrtKey) key;
			RSAPrivateKeyStructure st = new RSAPrivateKeyStructure(pKey
					.getModulus(), pKey.getPublicExponent(), pKey
					.getPrivateExponent(), pKey.getPrimeP(), pKey.getPrimeQ(),
					pKey.getPrimeExponentP(), pKey.getPrimeExponentQ(), pKey
							.getCrtCoefficient());
			ASN1Primitive ob = st.toASN1Primitive();

			try {
				return BouncyCastleUtil.toByteArray(ob);
			} catch (IOException e) {
				// that should never happen
				return new byte[0];
			}
		} else {
			return new byte[0];
		}
	}

	protected String getProvider() {
		return "BC";
	}
}
