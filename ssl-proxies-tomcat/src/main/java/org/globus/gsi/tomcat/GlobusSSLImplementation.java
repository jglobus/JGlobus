package org.globus.gsi.tomcat;


import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.ServerSocketFactory;
import org.apache.tomcat.util.net.jsse.JSSEImplementation;

public class GlobusSSLImplementation extends JSSEImplementation {

	public GlobusSSLImplementation() throws ClassNotFoundException {

	}

	public String getImplementationName() {
		return "GlobusSSLImplementation";
	}

	public ServerSocketFactory getServerSocketFactory(AbstractEndpoint endpoint) {
		return new GlobusSSLSocketFactory(endpoint);
	}

}
