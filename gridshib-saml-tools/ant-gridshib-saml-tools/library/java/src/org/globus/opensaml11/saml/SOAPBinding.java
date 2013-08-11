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

package org.globus.opensaml11.saml;

import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import javax.xml.namespace.QName;
import org.apache.log4j.Logger;
import org.apache.log4j.NDC;
import org.w3c.dom.*;


/**
 *  Implementation of SOAP binding packaging methods, useful as a base class
 *  for full binding implementations once a transport protocol is added by
 *  implementing the actual binding methods.
 *
 * @author     Scott Cantor (created February 12, 2005)
 */
public abstract class SOAPBinding implements SAMLSOAPBinding
{
    private static SAMLConfig config = SAMLConfig.instance();

    private Logger log = Logger.getLogger(SOAPBinding.class.getName());
    private Map /* <SOAPHook,Object> */ soapHooks = Collections.synchronizedMap(new HashMap(4));

    /**
     * @see SAMLSOAPBinding#addHook(org.globus.opensaml11.saml.SAMLSOAPBinding.SOAPHook)
     */
    public void addHook(SOAPHook h) {
        addHook(h, null);
    }

    /**
     * @see SAMLSOAPBinding#addHook(org.globus.opensaml11.saml.SAMLSOAPBinding.SOAPHook, Object)
     */
    public void addHook(SOAPHook h, Object globalCtx) {
        soapHooks.put(h, globalCtx);
    }

    /**
     * @see SAMLSOAPBinding#sendRequest(SAMLRequest, Object)
     */
    public Element sendRequest(SAMLRequest request, Object callCtx) throws SAMLException {
        NDC.push("sendRequest");

        try {
            // Turn the request into a DOM, and use its document for the SOAP nodes.
            Document doc=request.toDOM().getOwnerDocument();

            // Build a SOAP envelope and body.
            Element e=doc.createElementNS(XML.SOAP11ENV_NS, "Envelope");
            e.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SOAP11ENV_NS);
            Element body=doc.createElementNS(XML.SOAP11ENV_NS, "Body");
            e.appendChild(body);

            // Attach SAML request.
            body.appendChild(request.toDOM());

            if (doc.getDocumentElement()==null)
                doc.appendChild(e);
            else
                doc.replaceChild(e, doc.getDocumentElement());

            // Run the outgoing client-side SOAP hooks.
            for (Iterator hooks=soapHooks.entrySet().iterator(); hooks.hasNext();) {
                Entry h = (Entry)hooks.next();
                if (!((SOAPHook)h.getKey()).outgoing(e, h.getValue(), callCtx)) {
                    body.removeChild(request.toDOM());
                    log.warn("SOAP processing hook returned false, aborting outgoing request");
                    throw new BindingException(SAMLException.REQUESTER,"SOAPBinding.sendRequest() SOAP processing hook returned false, aborted outgoing request");
                }
            }

            return e;
        }
        finally {
            NDC.pop();
        }
    }

    /**
     * @see SAMLSOAPBinding#recvResponse(org.w3c.dom.Element, Object)
     */
    public SAMLResponse recvResponse(Element envelope, Object callCtx) throws SAMLException {
        NDC.push("recvResponse");

        try {
            // The root must be a SOAP 1.1 envelope.
            if (!XML.isElementNamed(envelope,XML.SOAP11ENV_NS,"Envelope"))
                throw new BindingException("SOAPBinding.recvResponse() detected an incompatible or missing SOAP envelope");

            // Run the incoming client-side SOAP hooks.
            for (Iterator hooks=soapHooks.entrySet().iterator(); hooks.hasNext();) {
                Entry h = (Entry)hooks.next();
                if (!((SOAPHook)h.getKey()).incoming(envelope, h.getValue(), callCtx)) {
                    log.warn("SOAP processing hook returned false, aborting incoming response");
                    throw new BindingException(SAMLException.REQUESTER,"SOAPBinding.recvResponse() SOAP processing hook returned false, aborted incoming response");
                }
            }

            Element n = XML.getFirstChildElement(envelope);
            if (XML.isElementNamed(n,XML.SOAP11ENV_NS,"Header")) {
                // Did somebody get a look at the headers for us?
                if (soapHooks.isEmpty()) {
                    /* Walk the children. If we encounter any headers with mustUnderstand, we have to bail.
                     * The thinking here is, we're not a "real" SOAP processor, but we have to emulate one that
                     * understands no headers. For now, assume we're the recipient.
                     */
                    Element header=XML.getFirstChildElement(n);
                    while (header!=null) {
                        if (((Element)header).getAttributeNS(XML.SOAP11ENV_NS,"mustUnderstand")!=null &&
                            ((Element)header).getAttributeNS(XML.SOAP11ENV_NS,"mustUnderstand").equals("1"))
                            throw new SOAPException(SOAPException.MUSTUNDERSTAND,"SOAPBinding.recvResponse() detected a mandatory SOAP header");
                        header=XML.getNextSiblingElement(header);
                    }
                }
                n = XML.getNextSiblingElement(n);   // advance to body
            }

            if (n != null) {
                // Get the first (and only) child element of the Body.
                n = XML.getFirstChildElement(n);
                if (n != null) {
                    // Is it a fault?
                    if (XML.isElementNamed(n,XML.SOAP11ENV_NS,"Fault")) {
                        // Find the faultstring element and use it in the message.
                        NodeList nlist = n.getElementsByTagNameNS(null,"faultstring");
                        String msg;
                        if (nlist != null && nlist.getLength() > 0)
                            msg = nlist.item(0).getFirstChild().getNodeValue();
                        else
                            msg = "SAMLSOAPBinding.recvResponse() detected a SOAP fault";

                        nlist = n.getElementsByTagNameNS(null,"faultstring");
                        if (nlist != null && nlist.getLength() > 0)
                            throw new SOAPException(XML.getQNameTextNode((Text)nlist.item(0).getFirstChild()),msg);
                        else
                            throw new SOAPException(SOAPException.SERVER,msg);
                    }

                    return new SAMLResponse(n);
                }
            }
            throw new SOAPException(SOAPException.SERVER,"SOAPBinding.recvResponse() unable to find a SAML response or fault in SOAP body");
        }
        finally {
            NDC.pop();
        }
    }

    /**
     * @see SAMLSOAPBinding#recvRequest(org.w3c.dom.Element, Object)
     */
    public SAMLRequest recvRequest(Element envelope, Object callCtx) throws SAMLException {
        NDC.push("recvRequest");

        try {
            // The root must be a SOAP 1.1 envelope.
            if (!XML.isElementNamed(envelope,XML.SOAP11ENV_NS,"Envelope"))
                throw new SOAPException(SOAPException.VERSION, "SOAPBinding.recvRequest() detected an incompatible or missing SOAP envelope");

            // Run the incoming server-side SOAP hooks.
            for (Iterator hooks=soapHooks.entrySet().iterator(); hooks.hasNext();) {
                Entry h = (Entry)hooks.next();
                if (!((SOAPHook)h.getKey()).incoming(envelope, h.getValue(), callCtx)) {
                    log.warn("SOAP processing hook returned false, aborting incoming request");
                    throw new BindingException(SAMLException.REQUESTER,"SOAPBinding.recvRequest() SOAP processing hook returned false, aborted incoming request");
                }
            }

            Element child = XML.getFirstChildElement(envelope);
            if (XML.isElementNamed(child,XML.SOAP11ENV_NS,"Header")) {
                // Did somebody get a look at the headers for us?
                if (soapHooks.isEmpty()) {
                    /* Walk the children. If we encounter any headers with mustUnderstand, we have to bail.
                     * The thinking here is, we're not a "real" SOAP processor, but we have to emulate one that
                     * understands no headers. For now, assume we're the recipient.
                     */
                    Element header = XML.getFirstChildElement(child);
                    while (header != null) {
                        if (header.getAttributeNS(XML.SOAP11ENV_NS, "mustUnderstand").equals("1"))
                            throw new SOAPException(SOAPException.MUSTUNDERSTAND, "SOAPBinding.recvRequest() detected a mandatory SOAP header");
                        header = XML.getNextSiblingElement(header);
                    }
                }

                // Advance to the Body element.
                child = XML.getNextSiblingElement(child);
            }

            /* The element after the optional Header is the mandatory Body (the meat). The SAML
               SOAP binding specifies the samlp:Request be immediately inside the body. Until
               we locate a Request (which we know validated), we're still in SOAP land. A SOAP
               envelope without a samlp:Request inside it is treated as a SOAP Client fault.
             */
            if (child != null)
                child = XML.getFirstChildElement(child);

            return new SAMLRequest(child);
        }
        finally {
            NDC.pop();
        }
    }

    /**
     * @see SAMLSOAPBinding#sendResponse(SAMLResponse, SAMLException, Object)
     */
    public Element sendResponse(SAMLResponse response, SAMLException e, Object callCtx) throws SAMLException {
        NDC.push("sendResponse");

        try {
            Document doc = (e==null) ? response.toDOM().getOwnerDocument() : XML.parserPool.newDocument();

            // Build the SOAP envelope and body for the response.
            Element env = doc.createElementNS(XML.SOAP11ENV_NS, "soap:Envelope");
            env.setAttributeNS(XML.XMLNS_NS,"xmlns:soap", XML.SOAP11ENV_NS);
            env.setAttributeNS(XML.XMLNS_NS,"xmlns:xsd", XML.XSD_NS);
            env.setAttributeNS(XML.XMLNS_NS,"xmlns:xsi", XML.XSI_NS);
            if (doc.getDocumentElement()==null)
                doc.appendChild(env);
            else
                doc.replaceChild(env, doc.getDocumentElement());
            Element body = doc.createElementNS(XML.SOAP11ENV_NS, "soap:Body");
            env.appendChild(body);

            // If we're handed an exception, turn it into a SOAP fault.
            if (e != null) {
                Element fault = doc.createElementNS(XML.SOAP11ENV_NS, "soap:Fault");
                body.appendChild(fault);
                Element elem = doc.createElementNS(null,"faultcode");
                if (e instanceof SOAPException) {
                    Iterator codes = e.getCodes();
                    if (codes.hasNext())
                        elem.appendChild(doc.createTextNode("soap:" + ((QName)codes.next()).getLocalPart()));
                    else
                        elem.appendChild(doc.createTextNode("soap:" + SOAPException.SERVER.getLocalPart()));
                }
                else
                    elem.appendChild(doc.createTextNode("soap:" + SOAPException.SERVER.getLocalPart()));
                fault.appendChild(elem);

                elem = doc.createElementNS(null,"faultstring");
                fault.appendChild(elem).appendChild(doc.createTextNode(e.getMessage()));
            }
            else {
                // Attach the SAML response.
                body.appendChild(response.toDOM());
            }

            // Run the outgoing server-side SOAP hooks.
            for (Iterator hooks=soapHooks.entrySet().iterator(); hooks.hasNext();) {
                Entry h = (Entry)hooks.next();
                if (!((SOAPHook)h.getKey()).outgoing(env, h.getValue(), callCtx)) {
                    body.removeChild(response.toDOM());
                    log.warn("SOAP processing hook returned false, aborting outgoing response");
                    throw new BindingException("SOAPBinding.sendResponse() SOAP processing hook returned false, aborted outgoing response");
                }
            }

            return env;
        }
        finally {
            NDC.pop();
        }
    }
}
