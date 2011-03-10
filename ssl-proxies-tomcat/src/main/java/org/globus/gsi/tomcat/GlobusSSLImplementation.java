package org.globus.gsi.tomcat;


import java.net.Socket;

import javax.net.ssl.SSLSession;

import org.apache.tomcat.util.net.SSLSupport;
import org.apache.tomcat.util.net.ServerSocketFactory;
import org.apache.tomcat.util.net.jsse.JSSEImplementation;

public class GlobusSSLImplementation extends JSSEImplementation {

	private GlobusSSLFactory factory = null;

	public GlobusSSLImplementation() throws ClassNotFoundException {
		this.factory = new GlobusSSLFactory();
	}

	public String getImplementationName() {
		return "GlobusSSLImplementation";
	}

	public ServerSocketFactory getServerSocketFactory() {
		return this.factory.getSocketFactory();
	}

	public SSLSupport getSSLSupport(Socket s) {
		SSLSupport ssls = this.factory.getSSLSupport(s);
		return ssls;
	}

	public SSLSupport getSSLSupport(SSLSession session) {
		SSLSupport ssls = this.factory.getSSLSupport(session);
		return ssls;
	}
}
