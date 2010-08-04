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

package org.globus.gsi.jetty;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.jetty.http.HttpSchemes;
import org.eclipse.jetty.io.EndPoint;
import org.eclipse.jetty.io.bio.SocketEndPoint;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.bio.SocketConnector;
import org.eclipse.jetty.server.ssl.ServletSSL;
import org.globus.gsi.jsse.GlobusTLSContext;
import org.globus.gsi.jsse.SSLConfigurator;
import org.globus.gsi.provider.GlobusProvider;

/**
 * This is an implementation of the SslSocketConnector from Jetty, which allows a bit more sophisticated configuration,
 * specifically, it allows an SSLConfigurator to be used to configure the SSLServerSocketFactory.
 *
 * @version 1.0
 * @since 1.0
 */
public class GlobusSslSocketConnector extends SocketConnector {
    private static final String CACHED_INFO_ATTR = CachedInfo.class.getName();    

    static {
        Security.addProvider(new GlobusProvider());
    }
    
    private static InheritableThreadLocal<Map<String, Object>> session = new InheritableThreadLocal<Map<String, Object>>(); 

    private Log logger = LogFactory.getLog(getClass());

    private SSLConfigurator sslConfigurator;

    private boolean needClientAuth;

    private boolean wantClientAuth;

    private int handshakeTimeout = 0;

    private SSLServerSocketFactory factory;
    private SSLServerSocket socket;
    private String[] excludeCipherSuites;

    private boolean allowRenegotiate = false;

    /**
     * Create a Jetty SSL Socket Connector based on the provided SSLConfigurator.
     *
     * @param config The SSLConfiguration for the server.
     */
    public GlobusSslSocketConnector(SSLConfigurator config) {
        this.sslConfigurator = config;
    }
    
    public Map<String, Object> getCurrentSession(){
    	return GlobusSslSocketConnector.session.get();
    }

    /**
     * Copied from org.mortbay.jetty.security.SslSocketConnector.
     *
     * @param acceptorID
     * @throws IOException
     * @throws InterruptedException
     */
    @Override
    public void accept(int acceptorID) throws IOException, InterruptedException {
        Socket socket = _serverSocket.accept();
        configure(socket);
        SslConnection connection = new SslConnection(socket);
        connection.dispatch();
    }

    @Override
    protected ServerSocket newServerSocket(String host, int port, int backlog) throws IOException {
        try {        	
            factory = createFactory();
            socket = (SSLServerSocket) (host == null ? factory.createServerSocket(port, backlog) :
                    factory.createServerSocket(port, backlog, InetAddress.getByName(host)));
            if (wantClientAuth) socket.setWantClientAuth(wantClientAuth);
            if (needClientAuth) socket.setNeedClientAuth(needClientAuth);
            if (excludeCipherSuites != null && excludeCipherSuites.length > 0) {
                List<String> excludedCSList = Arrays.asList(excludeCipherSuites);
                String[] enabledCipherSuites = socket.getEnabledCipherSuites();
                List<String> enabledCSList = new ArrayList<String>(Arrays.asList(enabledCipherSuites));
                for (String cipherName : excludedCSList) {
                    if (enabledCSList.contains(cipherName)) {
                        enabledCSList.remove(cipherName);
                    }
                }
                enabledCipherSuites = enabledCSList.toArray(new String[enabledCSList.size()]);
                socket.setEnabledCipherSuites(enabledCipherSuites);
            }
        } catch (Exception e) {
            logger.warn(e.getLocalizedMessage(), e);
            throw new IOException("Could not create JsseListener: " + e.toString());
        }
        return socket;
    }

    private SSLServerSocketFactory createFactory() throws Exception {
        if (sslConfigurator != null) {
            return sslConfigurator.createServerFactory();
        }
        return null;
    }

    public String getProvider() {
        return sslConfigurator.getProvider();
    }

    public void setProvider(String provider) {
        sslConfigurator.setProvider(provider);
    }

    public String getProtocol() {
        return sslConfigurator.getProtocol();
    }

    public void setProtocol(String protocol) {
        sslConfigurator.setProtocol(protocol);
    }

    public String getSecureRandomAlgorithm() {
        return sslConfigurator.getSecureRandomAlgorithm();
    }

    public void setSecureRandomAlgorithm(String secureRandomAlgorithm) {
        sslConfigurator.setSecureRandomAlgorithm(secureRandomAlgorithm);
    }

    public int getHandshakeTimeout() {
        return handshakeTimeout;
    }

    public void setHandshakeTimeout(int handshakeTimeout) {
        this.handshakeTimeout = handshakeTimeout;
    }

    public boolean isNeedClientAuth() {
        return needClientAuth;
    }

    public void setNeedClientAuth(boolean needClientAuth) {
        this.needClientAuth = needClientAuth;
    }

    public boolean isWantClientAuth() {
        return wantClientAuth;
    }

    public void setWantClientAuth(boolean wantClientAuth) {
        this.wantClientAuth = wantClientAuth;
    }

    public SSLServerSocketFactory getFactory() {
        return factory;
    }

    public void setFactory(SSLServerSocketFactory factory) {
        this.factory = factory;
    }

    public SSLServerSocket getSocket() {
        return socket;
    }

    public void setSocket(SSLServerSocket socket) {
        this.socket = socket;
    }

    public String[] getExcludeCipherSuites() {
        return excludeCipherSuites;
    }

    public void setExcludeCipherSuites(String[] excludeCipherSuites) {
        this.excludeCipherSuites = excludeCipherSuites;
    }

    public boolean isAllowRenegotiate() {
        return allowRenegotiate;
    }

    public void setAllowRenegotiate(boolean allowRenegotiate) {
        this.allowRenegotiate = allowRenegotiate;
    }

    /**
     * Copied from org.mortbay.jetty.security.SslSocketConnector.
     *
     * @param endpoint
     * @param request
     * @throws IOException
     */
    public void customize(EndPoint endpoint, Request request) throws IOException {
        super.customize(endpoint, request);
        request.setScheme(HttpSchemes.HTTPS);
        SocketEndPoint socket_end_point = (SocketEndPoint) endpoint;
        SSLSocket sslSocket = (SSLSocket) socket_end_point.getTransport();
        try {
            SSLSession sslSession = sslSocket.getSession();
            String cipherSuite = sslSession.getCipherSuite();
            Integer keySize;
            X509Certificate[] certs;
            CachedInfo cachedInfo = (CachedInfo) sslSession.getValue(CACHED_INFO_ATTR);
            if (cachedInfo != null) {
                keySize = cachedInfo.getKeySize();
                certs = cachedInfo.getCerts();
            } else {
                keySize = new Integer(ServletSSL.deduceKeyLength(cipherSuite));
                certs = getPeerCertChain(sslSession);
                cachedInfo = new CachedInfo(keySize, certs);
                sslSession.putValue(CACHED_INFO_ATTR, cachedInfo);
            }
            if (certs != null) {
                request.setAttribute("javax.servlet.request.X509Certificate", certs);
            } else if (needClientAuth) {
                // Sanity check                throw new IllegalStateException("no client auth");
            }
            request.setAttribute(GlobusTLSContext.class.getCanonicalName(), new GlobusTLSContext(sslSession));
        } catch (Exception e) {
            logger.warn(e.getLocalizedMessage(), e);
        }
    }

    /**
     * Return the chain of X509 certificates used to negotiate the SSL Session.
     * <p/>
     * Note: in order to do this we must convert a javax.security.cert.X509Certificate[], as used by
     * JSSE to a java.security.cert.X509Certificate[],as required by the Servlet specs.
     *
     * @param sslSession the javax.net.ssl.SSLSession to use as the source of the cert chain.
     * @return the chain of java.security.cert.X509Certificates used to negotiate the SSL
     *         connection. <br>
     *         Will be null if the chain is missing or empty.
     */
    private X509Certificate[] getPeerCertChain(SSLSession sslSession) {
        try {
            javax.security.cert.X509Certificate javaxCerts[] = sslSession.getPeerCertificateChain();
            if (javaxCerts == null || javaxCerts.length == 0) return null;
            int length = javaxCerts.length;
            X509Certificate[] javaCerts = new X509Certificate[length];
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            for (int i = 0; i < length; i++) {
                byte bytes[] = javaxCerts[i].getEncoded();
                ByteArrayInputStream stream = new ByteArrayInputStream(bytes);
                javaCerts[i] = (X509Certificate) cf.generateCertificate(stream);
            }
            return javaCerts;
        } catch (SSLPeerUnverifiedException pue) {
            return null;
        } catch (Exception e) {
            logger.warn(e.getLocalizedMessage(), e);
            return null;
        }
    }



    /**
     * By default, we're confidential, given we speak SSL. But, if we've been told about an
     * confidential port, and said port is not our port, then we're not. This allows separation of
     * listeners providing INTEGRAL versus CONFIDENTIAL constraints, such as one SSL listener
     * configured to require client certs providing CONFIDENTIAL, whereas another SSL listener not
     * requiring client certs providing mere INTEGRAL constraints.
     */
    @Override
    public boolean isConfidential(Request request) {
        final int confidentialPort = getConfidentialPort();
        return confidentialPort == 0 || confidentialPort == request.getServerPort();
    }
    /* ------------------------------------------------------------ */

    /**
     * By default, we're integral, given we speak SSL. But, if we've been told about an integral
     * port, and said port is not our port, then we're not. This allows separation of listeners
     * providing INTEGRAL versus CONFIDENTIAL constraints, such as one SSL listener configured to
     * require client certs providing CONFIDENTIAL, whereas another SSL listener not requiring
     * client certs providing mere INTEGRAL constraints.
     */
    @Override
    public boolean isIntegral(Request request) {
        final int integralPort = getIntegralPort();
        return integralPort == 0 || integralPort == request.getServerPort();
    }

    class CachedInfo {
        private X509Certificate[] certs;
        private Integer keySize;

        CachedInfo(Integer inputKeySize, X509Certificate[] inputCerts) {
            this.keySize = inputKeySize;
            this.certs = inputCerts;
        }

        X509Certificate[] getCerts() {
            return certs;
        }

        Integer getKeySize() {
            return keySize;
        }
    }
    
    public SSLConfigurator getSSLConfigurator(){
    	return this.sslConfigurator;
    }

    class SslConnection extends ConnectorEndPoint {

        public SslConnection(Socket socket) throws IOException {
            super(socket);
        }

        public void run() {
            try {
                int handshakeTimeout = getHandshakeTimeout();
                int oldTimeout = _socket.getSoTimeout();
                if (handshakeTimeout > 0)
                    _socket.setSoTimeout(handshakeTimeout);

                final SSLSocket ssl = (SSLSocket) _socket;
                ssl.addHandshakeCompletedListener(new HandshakeCompletedListener() {
                    boolean handshook = false;

                    public void handshakeCompleted(HandshakeCompletedEvent event) {
                        if (handshook) {
                            if (!allowRenegotiate) {
                                logger.warn("SSL renegotiate denied: " + ssl);
                                try {
                                    ssl.close();
                                } catch (IOException e) {
                                    logger.warn(e.getLocalizedMessage(), e);
                                }
                            }
                        } else
                            handshook = true;
                    }
                });
                ssl.startHandshake();

                if (handshakeTimeout > 0)
                    _socket.setSoTimeout(oldTimeout);

                super.run();
            }
            catch (SSLException e) {
                logger.warn(e.getLocalizedMessage(), e);
                try {
                    close();
                }
                catch (IOException e2) {
                    logger.trace(e2.getLocalizedMessage(), e2);
                }
            }
            catch (IOException e) {
                logger.debug(e.getLocalizedMessage(), e);
                try {
                    close();
                }
                catch (IOException e2) {
                    logger.trace(e2.getLocalizedMessage(), e2);
                }
            }
        }
    }
}