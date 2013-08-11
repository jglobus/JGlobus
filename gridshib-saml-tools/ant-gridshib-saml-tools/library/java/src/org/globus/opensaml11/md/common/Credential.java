/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
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

package org.globus.opensaml11.md.common;

import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateKey;

/**
 * Used to prove identity or integrity of transmitted messages.
 * 
 * @author Walter Hoehn
 */
public class Credential {

	public static int UNKNOWN = 0;
	public static int RSA = 1;
	public static int DSA = 2;

	private int type = UNKNOWN;
	private Key key;
	private X509Certificate[] certs;

	/**
	 * Creates a X509 credential.
	 * 
	 * @param certChain
	 *            certificate chain corresponding to the private key
	 * @param key
	 *            the RSA or DSA private key
	 */
	public Credential(X509Certificate[] certChain, PrivateKey key) {

		if (key instanceof RSAPrivateKey) {
			type = RSA;
		} else if (key instanceof DSAPrivateKey) {
			type = DSA;
		}
		certs = certChain;
		this.key = key;
	}

	public int getCredentialType() {

		return type;
	}

	public String getKeyAlgorithm() {

		return key.getAlgorithm();
	}

	public PrivateKey getPrivateKey() {

		if (key instanceof PrivateKey) { return (PrivateKey) key; }
		return null;
	}

	public boolean hasX509Certificate() {

		if (certs == null || certs.length == 0) { return false; }
		return true;
	}

	public X509Certificate getX509Certificate() {

		return certs[0];
	}

	public X509Certificate[] getX509CertificateChain() {

		return certs;
	}
}
