/*
 * Copyright 1999-2006 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.globus.axis.transport.commons.tests;

import java.io.IOException;
import java.io.OutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.net.ServerSocket;
import java.net.Socket;

import org.apache.commons.httpclient.HttpConnection;
import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.PostMethod;

import org.globus.axis.transport.commons.CommonsHttpConnectionManager;

import junit.framework.TestCase;
import junit.framework.Test;
import junit.framework.TestSuite;

public class CommonsHttpConnectionManagerTest extends TestCase {

    private static final String [] PARAMS = { "A", "B" };

    private Server server1 = null;
    private String address = "localhost";

    public CommonsHttpConnectionManagerTest(String name) {
	super(name);
    }

    public static void main (String[] args) {
	junit.textui.TestRunner.run (suite());
    }

    public static Test suite() {
	return new TestSuite(CommonsHttpConnectionManagerTest.class);
    }

    public void setUp() throws Exception {
        this.server1 = new Server();
    }

    public void tearDown() throws Exception {
        if (this.server1 != null) {
            this.server1.close();
        }
    }

    public void testConnectionReuseWithoutParams() throws Exception {
        CommonsHttpConnectionManager manager =
            new CommonsHttpConnectionManager(null);

        HostConfiguration h1 = new HostConfiguration();
        h1.setHost(address, server1.getLocalPort());

        HttpConnection c1 = manager.getConnection(h1);

        // new connection
        assertTrue(!c1.isOpen());

        c1.open();
        c1.releaseConnection();

        HostConfiguration h2 = new HostConfiguration();
        h2.setHost(address,  server1.getLocalPort());

        HttpConnection c2 = manager.getConnection(h2);

        // connection should have been released
        // so c2 is c1
        assertTrue(h2.equals(h1));
        assertTrue(c2 == c1);
        assertTrue(c2.isOpen());

        HttpConnection c3 = manager.getConnection(h2);

        // connection c2 was not released so new connection
        // c2 != c3
        assertTrue(!c3.isOpen());
        assertTrue(c3 != c2);
        assertTrue(c3 != c1);

        c2.releaseConnection();
        c3.releaseConnection();

        Server server2 = new Server();

        // it's a new port
        HostConfiguration h4 = new HostConfiguration();
        h4.setHost(address, server2.getLocalPort());

        HttpConnection c4 = manager.getConnection(h4);

        assertTrue(!c4.isOpen());
        assertTrue(c4 != c1);
        assertTrue(c4 != c2);
        assertTrue(c4 != c3);

        server2.close();
    }

    public void testConnectionReuseWithParams() throws Exception {
        CommonsHttpConnectionManager manager =
            new CommonsHttpConnectionManager(PARAMS);

        HostConfiguration h1 = new HostConfiguration();
        h1.setHost(address, server1.getLocalPort());
        h1.getParams().setParameter("A", "foo");
        h1.getParams().setParameter("B", "bar");
        h1.getParams().setParameter("C", "fff");

        HttpConnection c1 = manager.getConnection(h1);

        assertTrue(!c1.isOpen());
        c1.open();
        c1.releaseConnection();

        HostConfiguration h2 = new HostConfiguration();
        h2.setHost(address, server1.getLocalPort());
        h2.getParams().setParameter("A", "foo");
        h2.getParams().setParameter("B", "bar");
        // still should be reused since C is not checked param
        h2.getParams().setParameter("C", "ggg");

        HttpConnection c2 = manager.getConnection(h2);

        // connection should have been released
        // so c2 is c1
        assertTrue(h2.equals(h1));
        assertTrue(c2.isOpen());
        assertTrue(c2 == c1);

        HttpConnection c3 = manager.getConnection(h2);

        // new connection becuase it wasn't released
        assertTrue(c3 != c1);
        assertTrue(c3 != c2);
        assertTrue(!c3.isOpen());

        c2.releaseConnection();
        c3.releaseConnection();

        // this one does not have params
        HostConfiguration h4 = new HostConfiguration();
        h4.setHost(address, server1.getLocalPort());

        HttpConnection c4 = manager.getConnection(h4);

        // new connection
        assertTrue(c4 != c1);
        assertTrue(c4 != c2);
        assertTrue(c4 != c3);
        assertTrue(!c4.isOpen());

        c4.open();
        c4.releaseConnection();

        // this one only has B parameter
        HostConfiguration h5 = new HostConfiguration();
        h5.setHost(address, server1.getLocalPort());
        h5.getParams().setParameter("B", "bar");

        HttpConnection c5 = manager.getConnection(h5);

        // also a new connection
        assertTrue(c5 != c1);
        assertTrue(c5 != c2);
        assertTrue(c5 != c3);
        assertTrue(c5 != c4);
        assertTrue(!c5.isOpen());

        c5.open();
        c5.releaseConnection();

        // this one only has different B parameter
        HostConfiguration h6 = new HostConfiguration();
        h6.setHost(address, server1.getLocalPort());
        h6.getParams().setParameter("A", "fooo");
        h6.getParams().setParameter("B", "bar");

        HttpConnection c6 = manager.getConnection(h6);

        assertTrue(c6 != c1);
        assertTrue(c6 != c2);
        assertTrue(c6 != c3);
        assertTrue(c6 != c4);
        assertTrue(c6 != c5);
        assertTrue(!c6.isOpen());

        c6.open();
        c6.releaseConnection();
    }

    public void testIdleConnectionSweeper() throws Exception {
        CommonsHttpConnectionManager manager =
            new CommonsHttpConnectionManager(null);
        manager.setConnectionIdleTime(1000 * 2);

        HostConfiguration h1 = new HostConfiguration();
        h1.setHost(address, server1.getLocalPort());

        HttpConnection c1 = manager.getConnection(h1);

        // new connection
        assertTrue(!c1.isOpen());
        c1.open();

        Thread.sleep(1000);

        c1.releaseConnection();

        assertTrue(c1 == manager.getConnection(h1));
        assertTrue(c1.isOpen());
        c1.releaseConnection();

        Thread.sleep(1000 * 4);

        HttpConnection c2 = manager.getConnection(h1);

        assertTrue(c1 != c2);
    }

    public void testMultipleConnectionRelease() throws Exception {
        CommonsHttpConnectionManager manager =
            new CommonsHttpConnectionManager(null);

        HostConfiguration h1 = new HostConfiguration();
        h1.setHost(address, server1.getLocalPort());

        HttpConnection c1 = manager.getConnection(h1);

        assertTrue(!c1.isOpen());
        c1.open();

        c1.releaseConnection();
        c1.releaseConnection();

        HttpConnection c2 = manager.getConnection(h1);

        assertTrue(c1 == c2);

        HttpConnection c3 = manager.getConnection(h1);

        assertTrue(c3 != c2);
    }

    public void testHTTPContinue() throws Exception {
        HostConfiguration config = new HostConfiguration();
        config.setHost(address, server1.getLocalPort());

        HttpClient httpClient = new HttpClient();

        PostMethod method = new PostMethod("/foo/bar");
        method.setRequestBody("helloworld\r\n\r\n");

        int returnCode =
            httpClient.executeMethod(config, method, null);

        assertEquals(200, returnCode);
    }

    private static class Server implements Runnable {

        private ServerSocket server;
        private boolean stop = false;

        public Server() throws IOException {
            this.server = new ServerSocket(0);
            Thread t = new Thread(this);
            t.setDaemon(true);
            t.start();
        }

        public int getLocalPort() {
            return this.server.getLocalPort();
        }

        public void close() {
            this.stop = true;
            // this is to wake it up for sure
            try {
                Socket s = new Socket("localhost",
                                      getLocalPort());
                s.getInputStream();
                s.close();
            } catch (IOException e) {
            }
        }

        public void run() {
            try {
                while(!this.stop) {
                    Socket client = this.server.accept();
                    System.out.println("accepted connection");

                    OutputStream out = client.getOutputStream();
                    InputStream in = client.getInputStream();
                    BufferedReader reader = new BufferedReader(new InputStreamReader(in));
                    String line = null;


                    while( (line = reader.readLine()) != null ) {
                        if (line.length() == 0) {
                            break;
                        }
                        System.out.println("HEADER: " + line);
                    }

                    out.write("HTTP/1.1 100 Continue\r\n\r\n".getBytes());
                    out.flush();

                    while( (line = reader.readLine()) != null ) {
                        if (line.length() == 0) {
                            break;
                        }
                        System.out.println("BODY: " + line);
                    }

                    out.write("HTTP/1.1 200 Ok\r\nConnection: close\r\n\r\n".getBytes());
                    out.flush();

                    client.close();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }


    }

}

