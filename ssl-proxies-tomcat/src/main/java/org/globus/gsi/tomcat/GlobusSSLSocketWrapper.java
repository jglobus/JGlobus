package org.globus.gsi.tomcat;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.ServerSocketChannel;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

public class GlobusSSLSocketWrapper extends SSLServerSocket {

	private SSLServerSocket delegate;

	public GlobusSSLSocketWrapper(SSLServerSocket delegate) throws IOException {
		super();
		this.delegate = delegate;
	}

	public Socket accept() throws IOException {
		return new GlobusSSLSocket((SSLSocket) delegate.accept());
	}

	public void bind(SocketAddress endpoint, int backlog) throws IOException {
		delegate.bind(endpoint, backlog);
	}

	public void bind(SocketAddress endpoint) throws IOException {
		delegate.bind(endpoint);
	}

	public void close() throws IOException {
		delegate.close();
	}

	public boolean equals(Object obj) {
		return delegate.equals(obj);
	}

	public ServerSocketChannel getChannel() {
		return delegate.getChannel();
	}

	public String[] getEnabledCipherSuites() {
		return delegate.getEnabledCipherSuites();
	}

	public String[] getEnabledProtocols() {
		return delegate.getEnabledProtocols();
	}

	public boolean getEnableSessionCreation() {
		return delegate.getEnableSessionCreation();
	}

	public InetAddress getInetAddress() {
		return delegate.getInetAddress();
	}

	public int getLocalPort() {
		return delegate.getLocalPort();
	}

	public SocketAddress getLocalSocketAddress() {
		return delegate.getLocalSocketAddress();
	}

	public boolean getNeedClientAuth() {
		return delegate.getNeedClientAuth();
	}

	public int getReceiveBufferSize() throws SocketException {
		return delegate.getReceiveBufferSize();
	}

	public boolean getReuseAddress() throws SocketException {
		return delegate.getReuseAddress();
	}

	public int getSoTimeout() throws IOException {
		return delegate.getSoTimeout();
	}

	public String[] getSupportedCipherSuites() {
		return delegate.getSupportedCipherSuites();
	}

	public String[] getSupportedProtocols() {
		return delegate.getSupportedProtocols();
	}

	public boolean getUseClientMode() {
		return delegate.getUseClientMode();
	}

	public boolean getWantClientAuth() {
		return delegate.getWantClientAuth();
	}

	public int hashCode() {
		return delegate.hashCode();
	}

	public boolean isBound() {
		return delegate.isBound();
	}

	public boolean isClosed() {
		return delegate.isClosed();
	}

	public void setEnabledCipherSuites(String[] suites) {
		delegate.setEnabledCipherSuites(suites);
	}

	public void setEnabledProtocols(String[] protocols) {
		delegate.setEnabledProtocols(protocols);
	}

	public void setEnableSessionCreation(boolean flag) {
		delegate.setEnableSessionCreation(flag);
	}

	public void setNeedClientAuth(boolean need) {
		delegate.setNeedClientAuth(need);
	}

	public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
		delegate.setPerformancePreferences(connectionTime, latency, bandwidth);
	}

	public void setReceiveBufferSize(int size) throws SocketException {
		delegate.setReceiveBufferSize(size);
	}

	public void setReuseAddress(boolean on) throws SocketException {
		delegate.setReuseAddress(on);
	}

	public void setSoTimeout(int timeout) throws SocketException {
		delegate.setSoTimeout(timeout);
	}

	public void setUseClientMode(boolean mode) {
		delegate.setUseClientMode(mode);
	}

	public void setWantClientAuth(boolean want) {
		delegate.setWantClientAuth(want);
	}

	public String toString() {
		return delegate.toString();
	}
}
