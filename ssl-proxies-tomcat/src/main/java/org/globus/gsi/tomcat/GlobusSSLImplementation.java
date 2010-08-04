package org.globus.gsi.tomcat;


import org.apache.tomcat.util.net.ServerSocketFactory;
import org.apache.tomcat.util.net.jsse.JSSEImplementation;

public class GlobusSSLImplementation extends JSSEImplementation {

	public GlobusSSLImplementation() throws ClassNotFoundException {

	}

	public String getImplementationName() {
		return "GlobusSSLImplementation";
	}

	public ServerSocketFactory getServerSocketFactory() {
		return new GlobusSSLSocketFactory();
	}

}
