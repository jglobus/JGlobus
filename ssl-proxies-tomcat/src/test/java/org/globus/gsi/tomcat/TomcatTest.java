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

package org.globus.gsi.tomcat;

import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.servlet.ServletException;
import org.apache.catalina.Context;
import org.apache.catalina.Engine;
import org.apache.catalina.Host;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.startup.Embedded;
import org.apache.catalina.valves.ValveBase;
import org.apache.coyote.InputBuffer;
import org.apache.coyote.http11.InternalInputBuffer;
import org.globus.gsi.testutils.FileSetupUtil;
import org.globus.gsi.testutils.container.ClientTest;
import org.globus.gsi.tomcat.GlobusSSLImplementation;
import org.globus.gsi.tomcat.GlobusSSLInputStream;
import org.globus.gsi.tomcat.GlobusSSLSocketFactory;
import org.globus.gsi.GlobusTLSContext;
import org.globus.gsi.provider.GlobusProvider;
import org.junit.After;
import org.junit.Before;

/**
 * This test embeds a Tomcat server with our test credentials and policies. It
 * then tests two clients, one with valid credentials, one with invalid
 * credentials.
 * 
 * @version 1.0
 * @since 1.0
 */
public class TomcatTest extends ClientTest {

	private Embedded embedded;
	FileSetupUtil validCert;
	FileSetupUtil validKey;

	static {
		Security.addProvider(new GlobusProvider());
	}

	/**
	 * Create and start the embedded tomcat server.
	 * 
	 * @throws Exception
	 *             If there is an error creating the server.
	 */
	@Before
	public void setup() throws Exception {
		embedded = new Embedded();
		Engine engine = embedded.createEngine();
		engine.setName("Catalina");
		engine.setDefaultHost("localhost");

		Host host = embedded.createHost("localhost", ".");
		engine.addChild(host);

		Context context = embedded.createContext("", "");
		host.addChild(context);
		embedded.addEngine(engine);

		Connector connector = embedded.createConnector("localhost", 5082, false);
		connector.setScheme("https");
		connector.setAttribute("sslImplementation", GlobusSSLImplementation.class);
		connector.setAttribute("socketFactory", GlobusSSLSocketFactory.class.getCanonicalName());
		validKey = new FileSetupUtil("mykeystore.properties");
		validKey.copyFileToTemp();
		connector.setAttribute("keystoreFile", validKey.getTempFile().getAbsolutePath());
		connector.setAttribute("keystoreType", GlobusProvider.KEYSTORE_TYPE);
		connector.setAttribute("keystorePassword", "password");
		validCert = new FileSetupUtil("mytruststore.properties");
		validCert.copyFileToTemp();
		connector.setAttribute("truststoreFile", validCert.getTempFile().getAbsolutePath());
		connector.setAttribute("truststoreType", GlobusProvider.KEYSTORE_TYPE);
		connector.setAttribute("truststorePassword", "password");
		connector.setAttribute("signingPolicyLocation", "classpath:/globus_ca.signing_policy");
		connector.setAttribute("crlLocation", "");
		connector.setAttribute("clientAuth", "true");
		embedded.addConnector(connector);
		ValveBase v = new ValveBase() {

			@Override
			public void invoke(Request request, Response arg1) throws IOException, ServletException {
				InputBuffer buffer = request.getCoyoteRequest().getInputBuffer();
				if (buffer instanceof InternalInputBuffer) {

					InternalInputBuffer iib = (InternalInputBuffer) buffer;
					InputStream is = null;
					if (iib != null) {
						is = iib.getInputStream();
					}
					if (is != null && is instanceof GlobusSSLInputStream) {
						GlobusSSLInputStream gsis = (GlobusSSLInputStream) is;
						SSLSocket socket = gsis.getSSLSocket();
						SSLSession session = socket.getSession();
						request.getRequest().setAttribute(GlobusTLSContext.class.getCanonicalName(), new GlobusTLSContext(session));
					}
				}
			}
		};
		host.getPipeline().addValve(v);
		embedded.start();
	}

	/**
	 * Stop the embedded tomcat server.
	 * 
	 * @throws Exception
	 *             If an error is thrown while stopping the server.
	 */
	@After
	public void stop() throws Exception {
		embedded.stop();
		validKey.deleteFile();
		validCert.deleteFile();
	}
}
