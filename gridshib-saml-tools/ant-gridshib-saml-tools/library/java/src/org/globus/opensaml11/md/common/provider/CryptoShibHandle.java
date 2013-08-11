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

package org.globus.opensaml11.md.common.provider;

import org.globus.opensaml11.md.common.IdentityProvider;
import org.globus.opensaml11.md.common.InvalidNameIdentifierException;
import org.globus.opensaml11.md.common.LocalPrincipal;
import org.globus.opensaml11.md.common.NameIdentifierMapping;
import org.globus.opensaml11.md.common.NameIdentifierMappingException;
import org.globus.opensaml11.md.common.ServiceProvider;
import org.globus.opensaml11.md.common.ShibResource;
import org.globus.opensaml11.md.utils.Base32;
import org.apache.log4j.Logger;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLNameIdentifier;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.StreamCorruptedException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * {@link NameIdentifierMapping}implementation that uses symmetric encryption to store principal data inside Shibboleth
 * Attribute Query Handles.
 * 
 * @author Walter Hoehn
 * @author Derek Morr
 */
public class CryptoShibHandle extends AQHNameIdentifierMapping implements NameIdentifierMapping {

	private static Logger log = Logger.getLogger(CryptoShibHandle.class.getName());
	protected SecretKey secret;
	private SecureRandom random = new SecureRandom();
	private String cipherAlgorithm = "DESede/CBC/PKCS5Padding";
	private String macAlgorithm = "HmacSHA1";
	private String storeType = "JCEKS";

	public CryptoShibHandle(Element config) throws NameIdentifierMappingException {

		super(config);
		try {

			String keyStorePath = getElementConfigData(config, "KeyStorePath", true);
			String keyStorePassword = getElementConfigData(config, "KeyStorePassword", true);
			String keyStoreKeyAlias = getElementConfigData(config, "KeyStoreKeyAlias", true);
			String keyStoreKeyPassword = getElementConfigData(config, "KeyStoreKeyPassword", true);

			String rawStoreType = getElementConfigData(config, "KeyStoreType", false);
			if (rawStoreType != null && !rawStoreType.equals("")) {
				storeType = rawStoreType;
			}
			String rawCipherAlgorithm = getElementConfigData(config, "Cipher", false);
			if (rawCipherAlgorithm != null && !rawCipherAlgorithm.equals("")) {
				cipherAlgorithm = rawCipherAlgorithm;
			}
			String rawMacAlgorithm = getElementConfigData(config, "MAC", false);
			if (rawMacAlgorithm != null && !rawMacAlgorithm.equals("")) {
				macAlgorithm = rawMacAlgorithm;
			}

			KeyStore keyStore = KeyStore.getInstance(storeType);
			keyStore.load(new ShibResource(keyStorePath, this.getClass()).getInputStream(), keyStorePassword
					.toCharArray());
			secret = (SecretKey) keyStore.getKey(keyStoreKeyAlias, keyStoreKeyPassword.toCharArray());

			// Before we finish initilization, make sure that things are working
			testEncryption();

			if (usingDefaultSecret()) {
				log.warn("You are running Crypto AQH Name Mapping with the "
						+ "default secret key.  This is UNSAFE!  Please change "
						+ "this configuration and restart the IdP.");
			}
		} catch (StreamCorruptedException e) {
			if (System.getProperty("java.version").startsWith("1.4.2")) {
				log.error("There is a bug in some versions of Java 1.4.2.x that "
						+ "prevent JCEKS keystores from being loaded properly.  "
						+ "You probably need to upgrade or downgrade your JVM in order to make this work.");
			}
			log.error("An error occurred while loading the java keystore.  Unable to initialize "
					+ "Crypto Name Mapping: " + e);
			throw new NameIdentifierMappingException(
					"An error occurred while loading the java keystore.  Unable to initialize Crypto "
							+ "Name Mapping.");
		} catch (KeyStoreException e) {
			log.error("An error occurred while loading the java keystore.  Unable to initialize Crypto "
					+ "Name Mapping: " + e);
			throw new NameIdentifierMappingException(
					"An error occurred while loading the java keystore.  Unable to initialize Crypto Name Mapping.");
		} catch (CertificateException e) {
			log.error("The java keystore contained corrupted data.  Unable to initialize Crypto Name Mapping: " + e);
			throw new NameIdentifierMappingException(
					"The java keystore contained corrupted data.  Unable to initialize Crypto Name Mapping.");
		} catch (NoSuchAlgorithmException e) {
			log.error("Appropriate JCE provider not found in the java environment. Unable "
					+ "to initialize Crypto Name Mapping: " + e);
			throw new NameIdentifierMappingException(
					"Appropriate JCE provider not found in the java environment. Unable to initialize Crypto Name Mapping.");
		} catch (IOException e) {
			log.error("An error accessing while loading the java keystore.  Unable to initialize Crypto Name "
					+ "Mapping: " + e);
			throw new NameIdentifierMappingException(
					"An error occurred while accessing the java keystore.  Unable to initialize Crypto Name Mapping.");
		} catch (UnrecoverableKeyException e) {
			log.error("Secret could not be loaded from the java keystore.  Verify that the alias and "
					+ "password are correct: " + e);
			throw new NameIdentifierMappingException(
					"Secret could not be loaded from the java keystore.  Verify that the alias and password are correct. ");
		}
	}

	/**
	 * Decode an encrypted handle inside a SAMLNameIdentifier back into a principal
	 */
    public Principal getPrincipal(SAMLNameIdentifier nameId, ServiceProvider sProv, IdentityProvider idProv)
        throws NameIdentifierMappingException, InvalidNameIdentifierException {
		verifyQualifier(nameId, idProv);
		return getPrincipal(nameId.getName());
    }

	/**
	 * Decode an encrypted handle string back into a principal
	 */
	public Principal getPrincipal(String name)
			throws NameIdentifierMappingException, InvalidNameIdentifierException {

		try {
			byte[] in = Base32.decode(name);

			Cipher cipher = Cipher.getInstance(cipherAlgorithm);
			int ivSize = cipher.getBlockSize();
			byte[] iv = new byte[ivSize];

			Mac mac = Mac.getInstance(macAlgorithm);
			mac.init(secret);
			int macSize = mac.getMacLength();

			if (in.length < ivSize) {
				log.error("Attribute Query Handle is malformed (not enough bytes).");
				throw new NameIdentifierMappingException("Attribute Query Handle is malformed (not enough bytes).");
			}

			// extract the IV, setup the cipher and extract the encrypted handle
			System.arraycopy(in, 0, iv, 0, ivSize);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.DECRYPT_MODE, secret, ivSpec);

			byte[] encryptedHandle = new byte[in.length - iv.length];
			System.arraycopy(in, ivSize, encryptedHandle, 0, in.length - iv.length);

			// decrypt the rest of the data and setup the streams
			byte[] decryptedBytes = cipher.doFinal(encryptedHandle);
			ByteArrayInputStream byteStream = new ByteArrayInputStream(decryptedBytes);
			GZIPInputStream compressedData = new GZIPInputStream(byteStream);
			DataInputStream dataStream = new DataInputStream(compressedData);

			// extract the components
			byte[] decodedMac = new byte[macSize];
			int bytesRead = dataStream.read(decodedMac);
			if (bytesRead != macSize) {
				log.error("Error parsing handle: Unable to extract HMAC.");
				throw new NameIdentifierMappingException("Error parsing handle: Unable to extract HMAC.");
			}
			long decodedExpirationTime = dataStream.readLong();
			String decodedPrincipal = dataStream.readUTF();

			HMACHandleEntry macHandleEntry = createHMACHandleEntry(new LocalPrincipal(decodedPrincipal));
			macHandleEntry.setExpirationTime(decodedExpirationTime);
			byte[] generatedMac = macHandleEntry.getMAC(mac);

			if (macHandleEntry.isExpired()) {
				log.debug("Attribute Query Handle is expired.");
				throw new InvalidNameIdentifierException("Attribute Query Handle is expired.", errorCodes);
			}

			if (!Arrays.equals(decodedMac, generatedMac)) {
				log.warn("Attribute Query Handle failed integrity check.");
				throw new NameIdentifierMappingException("Attribute Query Handle failed integrity check.");
			}

			log.debug("Attribute Query Handle recognized.");
			return macHandleEntry.principal;

		} catch (NoSuchAlgorithmException e) {
			log.error("Appropriate JCE provider not found in the java environment.  Could not load Algorithm: " + e);
			throw new NameIdentifierMappingException(
					"Appropriate JCE provider not found in the java environment.  Could not load Algorithm.");
		} catch (NoSuchPaddingException e) {
			log.error("Appropriate JCE provider not found in the java environment.  Could not load Padding "
					+ "method: " + e);
			throw new NameIdentifierMappingException(
					"Appropriate JCE provider not found in the java environment.  Could not load Padding method.");
		} catch (InvalidKeyException e) {
			log.error("Could not use the supplied secret key: " + e);
			throw new NameIdentifierMappingException("Could not use the supplied secret key.");
		} catch (GeneralSecurityException e) {
			log.warn("Unable to decrypt the supplied Attribute Query Handle: " + e);
			throw new NameIdentifierMappingException("Unable to decrypt the supplied Attribute Query Handle.");
		} catch (IOException e) {
			log.warn("IO error while decoding handle.");
			throw new NameIdentifierMappingException("IO error while decoding handle.");
		}
	}

	/**
	 * Encodes a principal into a cryptographic handle per the following method below, and then constructs
	 * a SAMLNameIdentifier out of it.
	 */
	public SAMLNameIdentifier getNameIdentifier(LocalPrincipal principal, ServiceProvider sProv,
			IdentityProvider idProv) throws NameIdentifierMappingException {
		try {
			SAMLNameIdentifier nameid = SAMLNameIdentifier.getInstance(getNameIdentifierFormat().toString());
			nameid.setName(getName(principal).replaceAll(System.getProperty("line.separator"), ""));
			nameid.setNameQualifier(idProv.getProviderId());
			return nameid;
		} catch (SAMLException e) {
			throw new NameIdentifierMappingException("Unable to generate Attribute Query Handle: " + e);
		}
	}

	/**
	 * Encodes a principal into a cryptographic handle Format of encoded handle: [IV][HMAC][TTL][principal] where: [IV] =
	 * the Initialization Vector; byte-array [HMAC] = the HMAC; byte array [exprTime] = expiration time of the handle; 8
	 * bytes; Big-endian [principal] = the principal; a UTF-8-encoded string The [HMAC][exprTime][princLen][principal]
	 * byte stream is GZIPped. The IV is pre-pended to this byte stream, and the result is Base32-encoded. We don't need
	 * to encode the IV or MAC's lengths. They can be obtained from Cipher.getBlockSize() and Mac.getMacLength(),
	 * respectively.
	 */
	public String getName(LocalPrincipal principal)
			throws NameIdentifierMappingException {

		if (principal == null) {
			log.error("A principal must be supplied for Attribute Query Handle creation.");
			throw new IllegalArgumentException("A principal must be supplied for Attribute Query Handle creation.");
		}

		try {

			Mac mac = Mac.getInstance(macAlgorithm);
			mac.init(secret);
			HMACHandleEntry macHandleEntry = createHMACHandleEntry(principal);

			Cipher cipher = Cipher.getInstance(cipherAlgorithm);
			byte[] iv = new byte[cipher.getBlockSize()];
			random.nextBytes(iv);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.ENCRYPT_MODE, secret, ivSpec);

			ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
			GZIPOutputStream compressedStream = new GZIPOutputStream(byteStream);
			DataOutputStream dataStream = new DataOutputStream(compressedStream);

			dataStream.write(macHandleEntry.getMAC(mac));
			dataStream.writeLong(macHandleEntry.getExpirationTime());
			dataStream.writeUTF(principal.getName());

			dataStream.flush();
			compressedStream.flush();
			compressedStream.finish();
			byteStream.flush();

			byte[] encryptedData = cipher.doFinal(byteStream.toByteArray());

			byte[] handleBytes = new byte[iv.length + encryptedData.length];
			System.arraycopy(iv, 0, handleBytes, 0, iv.length);
			System.arraycopy(encryptedData, 0, handleBytes, iv.length, encryptedData.length);

			return Base32.encode(handleBytes);

		} catch (KeyException e) {
			log.error("Could not use the supplied secret key: " + e);
			throw new NameIdentifierMappingException("Could not use the supplied secret key.");
		} catch (GeneralSecurityException e) {
			log.error("Appropriate JCE provider not found in the java environment.  Could not load Cipher: " + e);
			throw new NameIdentifierMappingException(
					"Appropriate JCE provider not found in the java environment.  Could not load Cipher.");
		} catch (IOException e) {
			log.error("IO error while decoding handle.");
			throw new NameIdentifierMappingException("IO error while decoding handle.");
		}

	}

	private String getElementConfigData(Element e, String itemName, boolean required)
			throws NameIdentifierMappingException {

		NodeList itemElements = e.getElementsByTagNameNS(NameIdentifierMapping.mappingNamespace, itemName);

		if (itemElements.getLength() < 1) {
			if (required) {
				log.error(itemName + " not specified.");
				throw new NameIdentifierMappingException("Crypto Name Mapping requires a <" + itemName
						+ "> specification.");
			} else {
				return null;
			}
		}

		if (itemElements.getLength() > 1) {
			log.error("Multiple " + itemName + " specifications, using first.");
		}

		Node tnode = itemElements.item(0).getFirstChild();
		String item = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			item = tnode.getNodeValue();
		}
		if (item == null || item.equals("")) {
			log.error(itemName + " not specified.");
			throw new NameIdentifierMappingException("Crypto Name Mapping requires a valid <" + itemName
					+ "> specification.");
		}
		return item;
	}

	private void testEncryption() throws NameIdentifierMappingException {

		String decrypted;
		try {
			Cipher cipher = Cipher.getInstance(cipherAlgorithm);
			byte[] iv = new byte[cipher.getBlockSize()];
			random.nextBytes(iv);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.ENCRYPT_MODE, secret, ivSpec);
			byte[] cipherText = cipher.doFinal("test".getBytes());
			cipher = Cipher.getInstance(cipherAlgorithm);
			cipher.init(Cipher.DECRYPT_MODE, secret, ivSpec);
			decrypted = new String(cipher.doFinal(cipherText));
		} catch (Exception e) {
			log.error("Round trip encryption/decryption test unsuccessful: " + e);
			throw new NameIdentifierMappingException("Round trip encryption/decryption test unsuccessful.");
		}

		if (decrypted == null || !decrypted.equals("test")) {
			log.error("Round trip encryption/decryption test unsuccessful.  Decrypted text did not match.");
			throw new NameIdentifierMappingException("Round trip encryption/decryption test unsuccessful.");
		}

		byte[] code;
		try {
			Mac mac = Mac.getInstance(macAlgorithm);
			mac.init(secret);
			mac.update("foo".getBytes());
			code = mac.doFinal();

		} catch (Exception e) {
			log.error("Message Authentication test unsuccessful: " + e);
			throw new NameIdentifierMappingException("Message Authentication test unsuccessful.");
		}

		if (code == null) {
			log.error("Message Authentication test unsuccessful.");
			throw new NameIdentifierMappingException("Message Authentication test unsuccessful.");
		}
	}

	private boolean usingDefaultSecret() {

		byte[] defaultKey = new byte[]{(byte) 0xC7, (byte) 0x49, (byte) 0x80, (byte) 0xD3, (byte) 0x02, (byte) 0x4A,
				(byte) 0x61, (byte) 0xEF, (byte) 0x25, (byte) 0x5D, (byte) 0xE3, (byte) 0x2F, (byte) 0x57, (byte) 0x51,
				(byte) 0x20, (byte) 0x15, (byte) 0xC7, (byte) 0x49, (byte) 0x80, (byte) 0xD3, (byte) 0x02, (byte) 0x4A,
				(byte) 0x61, (byte) 0xEF};
		byte[] encodedKey = secret.getEncoded();
		return Arrays.equals(defaultKey, encodedKey);
	}

	protected HMACHandleEntry createHMACHandleEntry(LocalPrincipal principal) {

		return new HMACHandleEntry(principal, handleTTL);
	}

}

/**
 * <code>HandleEntry</code> extension class that performs message authentication.
 */

class HMACHandleEntry extends HandleEntry {

	protected HMACHandleEntry(LocalPrincipal principal, long TTL) {

		super(principal, TTL);
	}

	private static byte[] getLongBytes(long longValue) {

		try {
			ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
			DataOutputStream dataStream = new DataOutputStream(byteStream);

			dataStream.writeLong(longValue);
			dataStream.flush();
			byteStream.flush();

			return byteStream.toByteArray();
		} catch (IOException ex) {
			return null;
		}
	}

	public byte[] getMAC(Mac mac) {

		mac.update(getLongBytes(expirationTime));
		mac.update(principal.getName().getBytes());

		return mac.doFinal();
	}
}
