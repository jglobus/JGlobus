/*
 *  Copyright 2001-2005 Internet2
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.globus.opensaml11.saml.provider;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.ProviderException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.apache.log4j.NDC;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.globus.opensaml11.saml.*;
import org.w3c.dom.*;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;


/**
 *  SOAP over HTTP binding implementation.
 *
 *  The following properties can be placed in the OpenSAML configuration
 *  file to enable SSL client-certificate authentication with the server.
 *  <ul>
 *    <li>org.globus.opensaml11.saml.ssl.keystore - path to the store that contains the client's key and certificate</li>
 *    <li>org.globus.opensaml11.saml.ssl.keystore-pwd - the password to the keystore</li>
 *    <li>org.globus.opensaml11.saml.ssl.key-pwd - the passphrase to the private key in the keystore</li>
 *    <li>org.globus.opensaml11.saml.ssl.keystore-type - the key store type, defaults to JKS if not set</li>
 *    <li>org.globus.opensaml11.saml.ssl.truststore - path to the store that contains the server/CA certs needed to validate the cert chain</li>
 *    <li>org.globus.opensaml11.saml.ssl.truststore-pwd - the password to the trust store</li>
 *    <li>org.globus.opensaml11.saml.ssl.truststore-type - the trust store type, defaults to JKS if not set</li>
 *  </ul>
 *
 *  Notes:
 *  <ul>
 *    <li>If the <tt>org.globus.opensaml11.saml.ssl.keystore</tt> property is set the remaing *key* properties must also be set.</li>
 *    <li>If the <tt>org.globus.opensaml11.saml.ssl.truststore</tt> property is set the remaing *trust* properties must also be set.</li>
 *    <li>The private key <strong>MUST</strong> be passphrase protected.</li>
 *    <li>The properties described above apply to <strong>ALL</strong> instances of this binding within a given VM.</li>
 *  </ul>
 *
 * @author     Scott Cantor (created November 25, 2001)
 */
public class SOAPHTTPBindingProvider extends SOAPBinding implements SAMLSOAPHTTPBinding
{
    private static SAMLConfig config = SAMLConfig.instance();
    private static SSLContext sslctx = null;

    private Logger log = Logger.getLogger(SOAPHTTPBindingProvider.class.getName());
    private Map /* <HTTPHook,Object> */ httpHooks = Collections.synchronizedMap(new HashMap(4));

    /**  Defeault constructor for a SAMLSOAPBinding object */
    public SOAPHTTPBindingProvider(String binding, Element e) throws SAMLException {
        if (!binding.equals(SOAP))
            throw new SAMLException("SOAPHTTPBindingProvider does not support requested binding (" + binding + ")");
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLSOAPHTTPBinding#addHook(org.globus.opensaml11.saml.SAMLSOAPHTTPBinding.HTTPHook)
     */
    public void addHook(HTTPHook h) {
        addHook(h, null);
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLSOAPHTTPBinding#addHook(org.globus.opensaml11.saml.SAMLSOAPHTTPBinding.HTTPHook, Object)
     */
    public void addHook(HTTPHook h, Object globalCtx) {
        httpHooks.put(h, globalCtx);
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLBinding#send(String, org.globus.opensaml11.saml.SAMLRequest, Object)
     */
    public SAMLResponse send(String endpoint, SAMLRequest request, Object callCtx)
        throws SAMLException
    {
        try {
            NDC.push("send");
            if(log.isDebugEnabled()) {
                log.debug("Preparing to send the following SAML request to " + endpoint + "\n" + request.toString());
            }

            // Use SOAP layer to package message.
            if(log.isDebugEnabled()) {
                log.debug("Wrapping request to " + endpoint + " in a SOAP envelope");
            }
            Element envelope = sendRequest(request, callCtx);

            // Connect to authority and setup basic headers.
            log.debug("Setting connection properties for connecting to " + endpoint);
            URLConnection conn=new URL(endpoint).openConnection();
            conn.setAllowUserInteraction(false);
            conn.setDoOutput(true);
            ((HttpURLConnection)conn).setInstanceFollowRedirects(false);
            ((HttpURLConnection)conn).setRequestMethod("POST");
            ((HttpURLConnection)conn).setRequestProperty("Content-Type","text/xml; charset=UTF-8");
            ((HttpURLConnection)conn).setRequestProperty("SOAPAction","http://www.oasis-open.org/committees/security");

            // For an SSL connection, we check for a custom configuration.
            if (conn instanceof javax.net.ssl.HttpsURLConnection && sslctx != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Connection to " + endpoint + " is an HTTPS connection, setting default SSL socket factory.");
                }
                ((javax.net.ssl.HttpsURLConnection)conn).setSSLSocketFactory(sslctx.getSocketFactory());
            }

            // Run the outgoing client-side HTTP hooks.
            if(log.isDebugEnabled()) {
                log.debug("Connection to " + endpoint + " set up, running " +  httpHooks.size() + " outgoing client-side HTTP hooks.");
            }
            for (Iterator hooks=httpHooks.entrySet().iterator(); hooks.hasNext();) {
                Entry h = (Entry)hooks.next();
                if (!((HTTPHook)h.getKey()).outgoing((HttpURLConnection)conn, h.getValue(), callCtx)) {
                    log.warn("HTTP processing hook returned false, aborting outgoing request");
                    throw new BindingException(SAMLException.REQUESTER,"SOAPHTTPBindingProvider.send() HTTP processing hook returned false, aborted outgoing request");
                }
            }

            // Send the message.
            if(log.isDebugEnabled()) {
                log.debug("Connecting to " + endpoint);
            }
            conn.connect();

            if(log.isDebugEnabled()) {
                log.debug("Canonicalizing SOAP envelope-wrapped request and sending it to " + endpoint);
            }
            Canonicalizer c = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
            conn.getOutputStream().write(c.canonicalizeSubtree(envelope));

            // Run the incoming client-side HTTP hooks.
            if(log.isDebugEnabled()) {
                log.debug("Message sent to " + endpoint + ", running " + httpHooks.size() + " incoming client-side HTTP hooks.");
            }
            for (Iterator hooks=httpHooks.entrySet().iterator(); hooks.hasNext();) {
                Entry h = (Entry)hooks.next();
                if (!((HTTPHook)h.getKey()).incoming((HttpURLConnection)conn, h.getValue(), callCtx)) {
                    log.warn("HTTP processing hook returned false, aborting incoming response");
                    throw new BindingException("SOAPHTTPBindingProvider.send() HTTP processing hook returned false, aborted incoming response");
                }
            }

            if(log.isDebugEnabled()) {
                log.debug("Starting to process response from " + endpoint);
            }

            String content_type=((HttpURLConnection)conn).getContentType();
            if(log.isDebugEnabled()) {
                log.debug("Response content type is " + content_type);
            }
            if (content_type == null || !content_type.startsWith("text/xml")) {
                log.error(
                    "received an invalid content type in the response ("
                    + (content_type!=null ? content_type : "none")
                    + "), with the following content:"
                    );
                BufferedReader reader=new BufferedReader(new InputStreamReader(conn.getInputStream()));
                log.error(reader.readLine());
                throw new BindingException(
                    "SOAPHTTPBindingProvider.send() detected an invalid content type ("
                        + (content_type!=null ? content_type : "none")
                        + ") in the response.");
            }

            // Parse the envelope using the specified SAML schema set.
            if(log.isDebugEnabled()) {
                log.debug("Unmarshalling response from " + endpoint + " into a DOM document.");
            }
            envelope=XML.parserPool.parse(
                    new InputSource(conn.getInputStream()),
                    (request.getMinorVersion()>0) ? XML.parserPool.getSchemaSAML11() : XML.parserPool.getSchemaSAML10()
                    ).getDocumentElement();

            // Process the SOAP envelope and check message correlation.
            if(log.isDebugEnabled()) {
                log.debug("Parsing and verifying SOAP response and retrieving SAML response from it.");
            }
            SAMLResponse ret = recvResponse(envelope, callCtx);
            if(log.isDebugEnabled()) {
                log.debug("Received the following SAML response as the response to the request to " + endpoint + "\n" + ret.toString());
            }

            if (!ret.getInResponseTo().equals(request.getId())) {
                log.error("Unable to match SAML InResponseTo value to request made to " + endpoint);
                throw new BindingException("SOAPHTTPBindingProvider.send() unable to match SAML InResponseTo value to request");
            }
            return ret;
        }
        catch (MalformedURLException ex) {
            throw new SAMLException("SAMLSOAPBinding.send() detected a malformed URL in the binding provided", ex);
        }
        catch (SAXException ex) {
            throw new SAMLException("SAMLSOAPBinding.send() caught an XML exception while parsing the response", ex);
        }
        catch (InvalidCanonicalizerException ex) {
            throw new SAMLException("SAMLSOAPBinding.send() caught a C14N exception while serializing the request", ex);
        }
        catch (CanonicalizationException ex) {
            throw new SAMLException("SAMLSOAPBinding.send() caught a C14N exception while serializing the request", ex);
        }
        catch (IOException ex) {
            throw new SAMLException("SAMLSOAPBinding.send() caught an I/O exception", ex);
        }
        finally {
            NDC.pop();
        }
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLBinding#receive(Object, Object, int)
     */
    public SAMLRequest receive(Object reqContext, Object callCtx, int minor)
        throws SAMLException
    {
        // The SAML SOAP binding requires that we receieve a SOAP envelope via
        // the POST method as text/xml.
        HttpServletRequest req = (HttpServletRequest)reqContext;
        if (!req.getMethod().equals("POST") || !req.getContentType().startsWith("text/xml"))
            throw new BindingException(SAMLException.REQUESTER, "SOAPHTTPBindingProvider.receive() found bad HTTP method or content type");

        // Run the incoming server-side HTTP hooks.
        for (Iterator hooks=httpHooks.entrySet().iterator(); hooks.hasNext();) {
            Entry h = (Entry)hooks.next();
            if (!((HTTPHook)h.getKey()).incoming(req, h.getValue(), callCtx)) {
                log.warn("HTTP processing hook returned false, aborting incoming request");
                throw new BindingException(SAMLException.REQUESTER,"SOAPHTTPBindingProvider.recvRequest() HTTP processing hook returned false, aborted incoming request");
            }
        }

        try {
            // The body of the POST contains the XML document to parse as a SOAP envelope.

            /* This is less than ideal because it assumes the envelope can be validated
               using the 2001/Schema namespace against the unofficial SOAP 1.1 schema. This isn't
               so terrible, except that if a SOAP toolkit used by a requester produces an envelope
               that explicitly sets the xsd or xsi namespaces to something older, we're screwed.
               (Apache SOAP parses without validating, so they can handle multiple schema levels.)
             */
            return recvRequest(
                XML.parserPool.parse(
                        new InputSource(req.getInputStream()),
                        (minor>0) ? XML.parserPool.getSchemaSAML11() : XML.parserPool.getSchemaSAML10()
                    ).getDocumentElement(),
                callCtx
                );
        }
        catch (SAXException e) {
            throw new SOAPException(SOAPException.CLIENT, "SOAPHTTPBindingProvider.receive() detected an XML parsing error: " + e.getMessage());
        }
        catch (IOException e) {
            throw new SOAPException(SOAPException.SERVER, "SOAPHTTPBindingProvider.receive() detected an I/O error: " + e.getMessage());
        }
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLBinding#respond(Object, org.globus.opensaml11.saml.SAMLResponse, org.globus.opensaml11.saml.SAMLException, Object)
     */
    public void respond(Object respContext, SAMLResponse response, SAMLException e, Object callCtx)
        throws SAMLException
    {
        HttpServletResponse resp=(HttpServletResponse)respContext;

        try {
            // Package response or error in SOAP envelope.
            Element env = sendResponse(response, e, callCtx);

            // Run the outgoing server-side HTTP hooks.
            for (Iterator hooks=httpHooks.entrySet().iterator(); hooks.hasNext();) {
                Entry h = (Entry)hooks.next();
                if (!((HTTPHook)h.getKey()).outgoing(resp, h.getValue(), callCtx)) {
                    log.warn("HTTP processing hook returned false, aborting outgoing response");
                    throw new BindingException("SOAPHTTPBindingProvider.respond() HTTP processing hook returned false, aborted outgoing response");
                }
            }

            // If all went well, send the envelope back.
            Canonicalizer c = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
            if (e != null)
                resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.setContentType("text/xml; charset=UTF-8");
            resp.getOutputStream().write(c.canonicalizeSubtree(env));
        }
        catch (InvalidCanonicalizerException ex) {
            ex.printStackTrace();
            try {
                resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "SAMLSOAPBinding.respond() unable to serialize XML document instance");
            }
            catch (IOException e1) {
                throw new SAMLException("SAMLSOAPBinding.respond() caught I/O exception while sending error response", e1);
            }
        }
        catch (CanonicalizationException ex) {
            ex.printStackTrace();
            try {
                resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "SAMLSOAPBinding.respond() unable to serialize XML document instance");
            }
            catch (IOException e1) {
                throw new SAMLException("SAMLSOAPBinding.respond() caught I/O exception while sending error response", e1);
            }
        }
        catch (IOException ex) {
            ex.printStackTrace();
            throw new SAMLException("SAMLSOAPBinding.respond() caught I/O exception while sending error response", ex);
        }
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLBinding#send(String, org.globus.opensaml11.saml.SAMLRequest)
     */
    public SAMLResponse send(String endpoint, SAMLRequest request) throws SAMLException {
        return send(endpoint, request, null);
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLBinding#receive(Object, int)
     */
    public SAMLRequest receive(Object reqContext, int minor) throws SAMLException {
        return receive(reqContext, null, minor);
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLBinding#respond(Object, org.globus.opensaml11.saml.SAMLResponse, org.globus.opensaml11.saml.SAMLException)
     */
    public void respond(Object respContext, SAMLResponse response, SAMLException e) throws SAMLException {
        respond(respContext, response, e, null);
    }

    static {
        try {
            // See if we need to setup a custom SSL context.
            String ks_path=config.getProperty("org.globus.opensaml11.saml.ssl.keystore");
            String ts_path = config.getProperty("org.globus.opensaml11.saml.ssl.truststore");
            if (ks_path != null || ts_path != null) {
                KeyManagerFactory kmf = null;
                TrustManagerFactory tmf = null;
                if (ks_path != null) {
                    String ks_pwd=config.getProperty("org.globus.opensaml11.saml.ssl.keystore-pwd");
                    String key_pwd=config.getProperty("org.globus.opensaml11.saml.ssl.key-pwd");
                    String ks_type = config.getProperty("org.globus.opensaml11.saml.ssl.keystore-type");
                    KeyStore ks = KeyStore.getInstance(ks_type != null ? ks_type : "JKS");
                    ks.load(new FileInputStream(ks_path),(ks_pwd!=null) ? ks_pwd.toCharArray() : null);
                    kmf=KeyManagerFactory.getInstance("SunX509");
                    kmf.init(ks,(key_pwd!=null) ? key_pwd.toCharArray() : null);
                }

                if (ts_path != null) {
                    String ts_pwd = config.getProperty("org.globus.opensaml11.saml.ssl.truststore-pwd");
                    String ts_type = config.getProperty("org.globus.opensaml11.saml.ssl.truststore-type");
                    KeyStore ts = KeyStore.getInstance(ts_type != null ? ts_type : "JKS");
                    ts.load(new FileInputStream(ts_path),(ts_pwd!=null) ? ts_pwd.toCharArray() : null);
                    tmf = TrustManagerFactory.getInstance("SunX509");
                    tmf.init(ts);
                }
                sslctx=SSLContext.getInstance("SSL");
                sslctx.init(kmf != null ? kmf.getKeyManagers() : null, tmf != null ? tmf.getTrustManagers() : null, null);
            }
        }
        catch (IOException e) {
            throw new ProviderException("SOAPHTTPBindingProvider caught I/O error initializing SSL context: " + e.getMessage());
        }
        catch (GeneralSecurityException e) {
            throw new ProviderException("SOAPHTTPBindingProvider caught security exception initializing SSL context: " + e.getMessage());
        }
    }
}
