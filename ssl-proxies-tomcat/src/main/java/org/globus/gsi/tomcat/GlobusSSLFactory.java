package org.globus.gsi.tomcat;

import org.apache.tomcat.util.net.ServerSocketFactory;
import org.apache.tomcat.util.net.jsse.JSSEFactory;

public class GlobusSSLFactory extends JSSEFactory{
	
	public ServerSocketFactory getSocketFactory() {
		return new GlobusSSLSocketFactory();
	}
}