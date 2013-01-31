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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import org.globus.gsi.bc.BouncyCastleOpenSSLKey;
import org.globus.gsi.testutils.FileSetupUtil;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Created by IntelliJ IDEA. User: turtlebender Date: Dec 31, 2009 Time: 9:54:25
 * AM To change this template use File | Settings | File Templates.
 */
@Category( { SecurityTest.class })
public class OpenSSLKeyTest {

	static FileSetupUtil file;

	@BeforeClass
	public static void setup() throws Exception {
		file = new FileSetupUtil("key.pem");
		file.copyFileToTemp();
		file.getTempFile();
	}

	@AfterClass
	public static void cleanup() throws Exception {
		file.deleteFile();
	}

	@Test
	public void testOpenSSLKeyCreation() throws Exception {
		OpenSSLKey opensslkey = new BouncyCastleOpenSSLKey(file.getAbsoluteFilename());
		byte[] encoded = opensslkey.getEncoded();
		OpenSSLKey byteStreamInit = new BouncyCastleOpenSSLKey("RSA", encoded);
		assertThat(opensslkey.getEncoded(), is(byteStreamInit.getEncoded()));
		PrivateKey privateKey = opensslkey.getPrivateKey();
		OpenSSLKey privateKeyInit = new BouncyCastleOpenSSLKey(privateKey);
		assertThat(opensslkey.getEncoded(), is(privateKeyInit.getEncoded()));
		opensslkey.encrypt("password");
		assertThat(opensslkey.getEncoded(), is(not(encoded)));
		byteStreamInit.encrypt("password");
		opensslkey = new BouncyCastleOpenSSLKey(opensslkey.getPrivateKey());
		opensslkey.decrypt("password");
		byteStreamInit = new BouncyCastleOpenSSLKey(byteStreamInit.getPrivateKey());
		byteStreamInit.decrypt("password");
		assertThat(opensslkey.getEncoded(), is(byteStreamInit.getEncoded()));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testNullByteStream() throws Exception {
		new BouncyCastleOpenSSLKey("RSA", null);
	}

	@Test(expected = GeneralSecurityException.class)
	public void testEmptyByteStream() throws Exception {
		new BouncyCastleOpenSSLKey("RSA", new byte[] {});
	}

	// @Test
	// public void testNullAlgo() throws Exception{
	// new BouncyCastleOpenSSLKey(null, new byte[]{});
	// }


        @Test
        public void testEqualsNull() throws Exception
        {
		OpenSSLKey key =
                        new BouncyCastleOpenSSLKey(file.getAbsoluteFilename());
                assertThat(key, not(equalTo(null)));
        }

        @Test
        public void testEqualsReflexive() throws Exception
        {
		OpenSSLKey key =
                        new BouncyCastleOpenSSLKey(file.getAbsoluteFilename());

                assertThat(key, equalTo(key));
        }

        @Test
        public void testEqualsSymmetricForEqualKeys() throws Exception
        {
                OpenSSLKey key1 =
                        new BouncyCastleOpenSSLKey(file.getAbsoluteFilename());
                OpenSSLKey key2 =
                        new BouncyCastleOpenSSLKey(file.getAbsoluteFilename());

                assertThat(key2, equalTo(key1));
                assertThat(key1, equalTo(key2));
        }

        @Test
        public void testEqualsForKeysDifferingByEncrypted() throws Exception
        {
                OpenSSLKey key1 =
                        new BouncyCastleOpenSSLKey(file.getAbsoluteFilename());
                OpenSSLKey key2 =
                        new BouncyCastleOpenSSLKey(file.getAbsoluteFilename());
                key2.encrypt("too many secrets");

                assertThat(key2, not(equalTo(key1)));
        }


        @Test
        public void testSerializableUnencrypted() throws Exception {
		OpenSSLKey key =
                        new BouncyCastleOpenSSLKey(file.getAbsoluteFilename());
                OpenSSLKey copy = serialiseAndDeserialise(key);

                assertThat(copy, equalTo(key));
        }


        @Test
        public void testSerializableEncrypted() throws Exception {
		OpenSSLKey key =
                        new BouncyCastleOpenSSLKey(file.getAbsoluteFilename());
                key.encrypt("too many secrets");
                OpenSSLKey copy = serialiseAndDeserialise(key);

                assertThat(copy, equalTo(key));
        }


        private OpenSSLKey serialiseAndDeserialise(OpenSSLKey key) throws IOException, ClassNotFoundException {
                ByteArrayOutputStream storage = new ByteArrayOutputStream();
                new ObjectOutputStream(storage).writeObject(key);
                byte[] data = storage.toByteArray();

                ObjectInputStream in =
                        new ObjectInputStream(new ByteArrayInputStream(data));
                return (OpenSSLKey) in.readObject();
        }
}
