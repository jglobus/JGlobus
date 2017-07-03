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
package org.globus.gsi.jsse;

import static org.junit.Assert.assertEquals;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.globus.gsi.jsse.GlobusSSLConfigurationException;
import org.globus.gsi.jsse.SSLConfigurator;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.Security;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.globus.gsi.provider.GlobusProvider;
import org.globus.gsi.stores.ResourceSigningPolicyStore;
import org.globus.gsi.stores.Stores;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

public class SSLConfiguratorTest {

	private static SSLSocket sslsocket;
	private static SSLServerSocket serverSocket;
	private CountDownLatch latch = new CountDownLatch(1);
	private StringBuilder builder = new StringBuilder();

	@BeforeClass
	public static void setup() throws Exception {
		Security.addProvider(new GlobusProvider());
	}

	@Test
	public void testConfig() throws Exception {

		SSLConfigurator config = new SSLConfigurator();

		config.setCrlLocationPattern(null);
		config.setCrlStoreType(GlobusProvider.CERTSTORE_TYPE);
		config.setCredentialStoreLocation("classpath:/configuratorTest/mykeystore.properties");
		config.setCredentialStorePassword("password");
		config.setCredentialStoreType(GlobusProvider.KEYSTORE_TYPE);
		config.setTrustAnchorStoreLocation("classpath:/configuratorTest/mytruststore.properties");
		config.setTrustAnchorStorePassword("password");
		config.setTrustAnchorStoreType(GlobusProvider.KEYSTORE_TYPE);

		ResourceSigningPolicyStore policyStore = Stores.getSigningPolicyStore("classpath:/configuratorTest/TestCA1.signing_policy");

		config.setPolicyStore(policyStore);

		serverSocket = startServer(config);
		latch.await();
		sslsocket = runClient(config);
		OutputStream outputstream = sslsocket.getOutputStream();
		OutputStreamWriter outputstreamwriter = new OutputStreamWriter(outputstream);
		BufferedWriter bufferedwriter = new BufferedWriter(outputstreamwriter);
		bufferedwriter.write("hello");
		bufferedwriter.flush();
	}

	private SSLSocket runClient(SSLConfigurator config) throws IOException,
			GlobusSSLConfigurationException {
		SSLSocketFactory sslsocketfactory = config.createFactory();

		return (SSLSocket) sslsocketfactory.createSocket("localhost", 9991);
	}

	@AfterClass
	public static void stop() throws Exception {
		serverSocket.close();
		sslsocket.close();
	}

	Log logger = LogFactory.getLog(SSLConfiguratorTest.class);

	private SSLServerSocket startServer(SSLConfigurator config)
			throws GlobusSSLConfigurationException, IOException {
		SSLServerSocketFactory sslserversocketfactory = config
				.createServerFactory();
		final SSLServerSocket sslserversocket = (SSLServerSocket) sslserversocketfactory
				.createServerSocket(9991);

		ExecutorService executor = Executors.newFixedThreadPool(1);
		executor.execute(new Runnable() {
			/**
			 * When an object implementing interface <code>Runnable</code> is
			 * used to create a thread, starting the thread causes the object's
			 * <code>run</code> method to be called in that separately executing
			 * thread.
			 * <p>
			 * The general contract of the method <code>run</code> is that it
			 * may take any action whatsoever.
			 *
			 * @see Thread#run()
			 */
			public void run() {
				latch.countDown();
				try {
					SSLSocket sslsocket = (SSLSocket) sslserversocket.accept();
					InputStream inputstream = sslsocket.getInputStream();
					InputStreamReader inputstreamreader = new InputStreamReader(
							inputstream);
					BufferedReader bufferedreader = new BufferedReader(
							inputstreamreader);
					String line;
					while ((line = bufferedreader.readLine()) != null) {
						builder.append(line);
					}
					assertEquals(builder.toString().trim(), "hello");
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		});
		return sslserversocket;
	}
}
