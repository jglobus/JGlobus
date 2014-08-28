package org.globus.gsi.tomcat;

import java.io.IOException;
import java.io.InputStream;

import javax.net.ssl.SSLSocket;


public class GlobusSSLInputStream extends InputStream{
	private InputStream delegate;
	private SSLSocket sslSocket;

	public GlobusSSLInputStream(InputStream delegate, SSLSocket sslSocket) {
		this.delegate = delegate;
		this.sslSocket = sslSocket;
	}

	public SSLSocket getSSLSocket(){
		return sslSocket;
	}

	public int available() throws IOException {
		return delegate.available();
	}

	public void close() throws IOException {
		delegate.close();
	}

	public boolean equals(Object obj) {
		return delegate.equals(obj);
	}

	public int hashCode() {
		return delegate.hashCode();
	}

	public void mark(int readlimit) {
		delegate.mark(readlimit);
	}

	public boolean markSupported() {
		return delegate.markSupported();
	}

	public int read() throws IOException {
		return delegate.read();
	}

	public int read(byte[] b, int off, int len) throws IOException {
		return delegate.read(b, off, len);
	}

	public int read(byte[] b) throws IOException {
		return delegate.read(b);
	}

	public void reset() throws IOException {
		delegate.reset();
	}

	public long skip(long n) throws IOException {
		return delegate.skip(n);
	}

	public String toString() {
		return delegate.toString();
	}




}
