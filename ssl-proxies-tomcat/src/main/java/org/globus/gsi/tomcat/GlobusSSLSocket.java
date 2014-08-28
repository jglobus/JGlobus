package org.globus.gsi.tomcat;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;


public class GlobusSSLSocket extends SSLSocket {

	private SSLSocket socket;

	public GlobusSSLSocket(SSLSocket socket){
		this.socket = socket;
	}

	public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
		socket.addHandshakeCompletedListener(listener);
	}

	public void bind(SocketAddress bindpoint) throws IOException {
		socket.bind(bindpoint);
	}

	public void close() throws IOException {
		socket.close();
	}

	public void connect(SocketAddress endpoint, int timeout) throws IOException {
		socket.connect(endpoint, timeout);
	}

	public void connect(SocketAddress endpoint) throws IOException {
		socket.connect(endpoint);
	}

	public boolean equals(Object obj) {
		return socket.equals(obj);
	}

	public SocketChannel getChannel() {
		return socket.getChannel();
	}

	public String[] getEnabledCipherSuites() {
		return socket.getEnabledCipherSuites();
	}

	public String[] getEnabledProtocols() {
		return socket.getEnabledProtocols();
	}

	public boolean getEnableSessionCreation() {
		return socket.getEnableSessionCreation();
	}

	public InetAddress getInetAddress() {
		return socket.getInetAddress();
	}

	public InputStream getInputStream() throws IOException {
		return new GlobusSSLInputStream(socket.getInputStream(), socket);
	}

	public boolean getKeepAlive() throws SocketException {
		return socket.getKeepAlive();
	}

	public InetAddress getLocalAddress() {
		return socket.getLocalAddress();
	}

	public int getLocalPort() {
		return socket.getLocalPort();
	}

	public SocketAddress getLocalSocketAddress() {
		return socket.getLocalSocketAddress();
	}

	public boolean getNeedClientAuth() {
		return socket.getNeedClientAuth();
	}

	public boolean getOOBInline() throws SocketException {
		return socket.getOOBInline();
	}

	public OutputStream getOutputStream() throws IOException {
		return socket.getOutputStream();
	}

	public int getPort() {
		return socket.getPort();
	}

	public int getReceiveBufferSize() throws SocketException {
		return socket.getReceiveBufferSize();
	}

	public SocketAddress getRemoteSocketAddress() {
		return socket.getRemoteSocketAddress();
	}

	public boolean getReuseAddress() throws SocketException {
		return socket.getReuseAddress();
	}

	public int getSendBufferSize() throws SocketException {
		return socket.getSendBufferSize();
	}

	public SSLSession getSession() {
		return socket.getSession();
	}

	public int getSoLinger() throws SocketException {
		return socket.getSoLinger();
	}

	public int getSoTimeout() throws SocketException {
		return socket.getSoTimeout();
	}

	public SSLParameters getSSLParameters() {
		return socket.getSSLParameters();
	}

	public String[] getSupportedCipherSuites() {
		return socket.getSupportedCipherSuites();
	}

	public String[] getSupportedProtocols() {
		return socket.getSupportedProtocols();
	}

	public boolean getTcpNoDelay() throws SocketException {
		return socket.getTcpNoDelay();
	}

	public int getTrafficClass() throws SocketException {
		return socket.getTrafficClass();
	}

	public boolean getUseClientMode() {
		return socket.getUseClientMode();
	}

	public boolean getWantClientAuth() {
		return socket.getWantClientAuth();
	}

	public int hashCode() {
		return socket.hashCode();
	}

	public boolean isBound() {
		return socket.isBound();
	}

	public boolean isClosed() {
		return socket.isClosed();
	}

	public boolean isConnected() {
		return socket.isConnected();
	}

	public boolean isInputShutdown() {
		return socket.isInputShutdown();
	}

	public boolean isOutputShutdown() {
		return socket.isOutputShutdown();
	}

	public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
		socket.removeHandshakeCompletedListener(listener);
	}

	public void sendUrgentData(int data) throws IOException {
		socket.sendUrgentData(data);
	}

	public void setEnabledCipherSuites(String[] suites) {
		socket.setEnabledCipherSuites(suites);
	}

	public void setEnabledProtocols(String[] protocols) {
		socket.setEnabledProtocols(protocols);
	}

	public void setEnableSessionCreation(boolean flag) {
		socket.setEnableSessionCreation(flag);
	}

	public void setKeepAlive(boolean on) throws SocketException {
		socket.setKeepAlive(on);
	}

	public void setNeedClientAuth(boolean need) {
		socket.setNeedClientAuth(need);
	}

	public void setOOBInline(boolean on) throws SocketException {
		socket.setOOBInline(on);
	}

	public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
		socket.setPerformancePreferences(connectionTime, latency, bandwidth);
	}

	public void setReceiveBufferSize(int size) throws SocketException {
		socket.setReceiveBufferSize(size);
	}

	public void setReuseAddress(boolean on) throws SocketException {
		socket.setReuseAddress(on);
	}

	public void setSendBufferSize(int size) throws SocketException {
		socket.setSendBufferSize(size);
	}

	public void setSoLinger(boolean on, int linger) throws SocketException {
		socket.setSoLinger(on, linger);
	}

	public void setSoTimeout(int timeout) throws SocketException {
		socket.setSoTimeout(timeout);
	}

	public void setSSLParameters(SSLParameters params) {
		socket.setSSLParameters(params);
	}

	public void setTcpNoDelay(boolean on) throws SocketException {
		socket.setTcpNoDelay(on);
	}

	public void setTrafficClass(int tc) throws SocketException {
		socket.setTrafficClass(tc);
	}

	public void setUseClientMode(boolean mode) {
		socket.setUseClientMode(mode);
	}

	public void setWantClientAuth(boolean want) {
		socket.setWantClientAuth(want);
	}

	public void shutdownInput() throws IOException {
		socket.shutdownInput();
	}

	public void shutdownOutput() throws IOException {
		socket.shutdownOutput();
	}

	public void startHandshake() throws IOException {
		socket.startHandshake();
	}




}
