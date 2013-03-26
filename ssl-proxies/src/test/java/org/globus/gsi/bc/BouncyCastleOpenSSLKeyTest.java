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

import org.globus.gsi.CertUtil;

import java.security.Provider;

import java.security.Security;

import org.globus.common.CoGProperties;

import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.io.StringWriter;
import java.io.ByteArrayInputStream;

import org.globus.gsi.OpenSSLKey;
import org.globus.gsi.bc.BouncyCastleOpenSSLKey;

import junit.framework.TestCase;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class BouncyCastleOpenSSLKeyTest extends TestCase {

    private static final String pwd = "testpwd";

    private Log logger = LogFactory.getLog(BouncyCastleOpenSSLKeyTest.class);
        
    private KeyPair getKeyPair() throws Exception {
    CertUtil.init();
        
	int bits = 512;
        
	KeyPairGenerator keyGen = null;
	keyGen = KeyPairGenerator.getInstance("RSA", "BC");
	keyGen.initialize(bits);
        
        return keyGen.genKeyPair();
    }

    public void testEncrypt() throws Exception {
        KeyPair keyPair = getKeyPair();

	OpenSSLKey key = new BouncyCastleOpenSSLKey(keyPair.getPrivate());
	
	assertTrue(!key.isEncrypted());

	key.encrypt(pwd);

	assertTrue(key.isEncrypted());
    }

    public void testEncryptAES() throws Exception {
        KeyPair keyPair = getKeyPair();

	OpenSSLKey key = new BouncyCastleOpenSSLKey(keyPair.getPrivate());
	
	assertTrue(!key.isEncrypted());

        key.setEncryptionAlgorithm("AES-128-CBC");

	key.encrypt(pwd);

	assertTrue(key.isEncrypted());

    }

    private String toString(OpenSSLKey key) throws Exception {
        StringWriter writer = new StringWriter();
        key.writeTo(writer);
        writer.close();
        String s = writer.toString();
        logger.debug(s);
        return s;
    }

    public void testDecryptedToString() throws Exception {
        KeyPair keyPair = getKeyPair();
	OpenSSLKey inKey = new BouncyCastleOpenSSLKey(keyPair.getPrivate());
	assertTrue(!inKey.isEncrypted());
        
        ByteArrayInputStream in = null;
        in = new ByteArrayInputStream(toString(inKey).getBytes());
        OpenSSLKey outKey = new BouncyCastleOpenSSLKey(in);
        assertTrue(!outKey.isEncrypted());

        in = new ByteArrayInputStream(toString(outKey).getBytes());
        OpenSSLKey outKey2 = new BouncyCastleOpenSSLKey(in);
        assertTrue(!outKey2.isEncrypted());
    }

    public void testEcryptedToString() throws Exception {
        KeyPair keyPair = getKeyPair();
	OpenSSLKey inKey = new BouncyCastleOpenSSLKey(keyPair.getPrivate());
	assertTrue(!inKey.isEncrypted());
	inKey.encrypt(pwd);
	assertTrue(inKey.isEncrypted());
        
        ByteArrayInputStream in = null;
        in = new ByteArrayInputStream(toString(inKey).getBytes());
        OpenSSLKey outKey = new BouncyCastleOpenSSLKey(in);
        assertTrue(outKey.isEncrypted());

        in = new ByteArrayInputStream(toString(outKey).getBytes());
        OpenSSLKey outKey2 = new BouncyCastleOpenSSLKey(in);
        assertTrue(outKey2.isEncrypted());
    }

}

