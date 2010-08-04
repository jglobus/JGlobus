package org.globus.gsi.jetty;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;

public class JettySSLHandler extends AbstractHandler {

	private Log logger = LogFactory.getLog(getClass());

	public void handle(String arg0, Request arg1, HttpServletRequest arg2,
			HttpServletResponse arg3) throws IOException, ServletException {
		Connector[] connectors = this.getServer().getConnectors();
		for (Connector connector : connectors) {
			if (connector instanceof GlobusSslSocketConnector) {
				GlobusSslSocketConnector gssc = (GlobusSslSocketConnector) connector;
				// SSLSession session = gssc.getCurrentSession();
				// if (session != null) {
				// request.setAttribute("PEER_CERTS",
				// session.getPeerCertificateChain());
				// request.setAttribute("LOCAL_CERTS",
				// session.getLocalCertificates());
				// request.setAttribute("PEER_PRINCIPAL",
				// session.getPeerPrincipal());
				// request.setAttribute("LOCAL_PRINCIPAL",
				// session.getLocalPrincipal());
				// } else {
				// logger.info("No ssl session available");
				// }
			}
		}

	}
}
