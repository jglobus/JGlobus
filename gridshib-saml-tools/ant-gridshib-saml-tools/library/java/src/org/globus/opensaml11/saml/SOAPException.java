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

import java.util.Collection;

import javax.xml.namespace.QName;

import org.w3c.dom.*;

/**
 *  Indicates that a SOAP processing error occurred in the context of the SAML
 *  SOAP binding. This subclass signals a binding implementation to return a
 *  SOAP fault instead of a SAML error.
 *
 * @author     Scott Cantor (created January 15, 2002)
 */
public class SOAPException extends BindingException implements Cloneable
{
    /**  SOAP Client fault code */
    public final static QName CLIENT = new QName(XML.SOAP11ENV_NS, "Client");

    /**  SOAP Server fault code */
    public final static QName SERVER = new QName(XML.SOAP11ENV_NS, "Server");

    /**  SOAP MustUnderstand fault code */
    public final static QName MUSTUNDERSTAND = new QName(XML.SOAP11ENV_NS, "MustUnderstand");

    /**  SOAP Version Mismatch status code */
    public final static QName VERSION = new QName(XML.SOAP11ENV_NS, "VersionMismatch");

    /**
     *  Creates a new SOAPException
     *
     * @param  e    The root of a DOM tree
     * @exception  org.globus.opensaml11.saml.SAMLException   Raised if an exception occurs while constructing
     *                              the object.
     */
    protected SOAPException(Element e)
        throws SAMLException
    {
        super(e);
    }

    /**
     *  Creates a new SOAPException
     *
     * @param  msg    The detail message
     */
    public SOAPException(String msg)
    {
        super(msg);
    }

    /**
     *  Creates a new SOAPException
     *
     * @param  msg    The detail message
     * @param  e      The exception to be wrapped in a SOAPException
     */
    public SOAPException(String msg, Exception e)
    {
        super(msg,e);
    }

    /**
     *  Creates a new SOAPException
     *
     * @param  codes  A collection of QNames
     * @param  msg    The detail message
     */
    public SOAPException(Collection codes, String msg)
    {
        super(codes,msg);
    }

    /**
     *  Creates a new SOAPException wrapping an existing exception <p>
     *
     *  The existing exception will be embedded in the new one, and its message
     *  will become the default message for the SOAPException.</p>
     *
     * @param  codes  A collection of QNames
     * @param  e      The exception to be wrapped in a SOAPException
     */
    public SOAPException(Collection codes, Exception e)
    {
        super(codes,e);
    }

    /**
     *  Creates a new SOAPException from an existing exception. <p>
     *
     *  The existing exception will be embedded in the new one, but the new
     *  exception will have its own message.</p>
     *
     * @param  codes  A collection of QNames
     * @param  msg    The detail message
     * @param  e      The exception to be wrapped in a SOAPException
     */
    public SOAPException(Collection codes, String msg, Exception e)
    {
        super(codes,msg,e);
    }

    /**
     *  Creates a new SOAPException
     *
     * @param  code   A status code
     * @param  msg    The detail message
     */
    public SOAPException(QName code, String msg)
    {
        super(code,msg);
    }

    /**
     *  Creates a new SOAPException wrapping an existing exception <p>
     *
     *  The existing exception will be embedded in the new one, and its message
     *  will become the default message for the SOAPException.</p>
     *
     * @param  code   A status code
     * @param  e      The exception to be wrapped in a SOAPException
     */
    public SOAPException(QName code, Exception e)
    {
        super(code,e);
    }

    /**
     *  Creates a new SOAPException from an existing exception. <p>
     *
     *  The existing exception will be embedded in the new one, but the new
     *  exception will have its own message.</p>
     *
     * @param  code   A status code
     * @param  msg    The detail message
     * @param  e      The exception to be wrapped in a SOAPException
     */
    public SOAPException(QName code, String msg, Exception e)
    {
        super(code,msg,e);
    }

    /**
     *  Handles initialization of exceptions from a DOM element
     *
     * @param  e
     * @exception  org.globus.opensaml11.saml.SAMLException  Raised if an exception occurs while initializing the object
     */
    public void fromDOM(Element e)
        throws SAMLException
    {
        if (e==null)
            throw new MalformedException("SOAPException.fromDOM() given an empty DOM");
        root = e;

        if (config.getBooleanProperty("org.globus.opensaml11.saml.strict-dom-checking") && !XML.isElementNamed(e,XML.SOAP11ENV_NS,"Fault"))
            throw new MalformedException(SAMLException.RESPONDER,"SOAPException.fromDOM() requires soap:Fault at root");

        // Get the first child, the faultcode.
        Node code=e.getFirstChild();
        while (code!=null && code.getNodeType()!=Node.ELEMENT_NODE)
            code=code.getNextSibling();

        QName q=XML.getQNameTextNode((Text)code.getFirstChild());
        if (q!=null)
            codes.add(q);
        else
            throw new MalformedException(SAMLException.RESPONDER,"SAMLException.fromDOM() unable to evaluate faultcode value");

        // Extract the status message.
        Node m=code.getNextSibling();
        while (m!=null && (m.getNodeType()!=Node.ELEMENT_NODE || !XML.isElementNamed(e,null,"faultstring")))
            m=m.getNextSibling();
        if (m!=null)
            msg=m.getFirstChild().getNodeValue();
    }

    /**
     *  Transforms the object into a DOM tree using an existing document context
     *
     * @param  doc               A Document object to use in manufacturing the
     *      tree
     * @return                   Root element node of the DOM tree capturing the
     *      object
     * @exception  org.w3c.dom.DOMException  Raised if an XML exception is detected
     */
    public Node toDOM(Document doc)
        throws DOMException
    {
        if (root != null)
        {
            // If the DOM tree is already generated, compare the Documents.
            if (root.getOwnerDocument() != doc)
            {
                // We already built a tree. Just import it into the new document.
                root = doc.adoptNode(root);
            }
        }
        else
        {
            // Construct a Fault element.
            Element s=doc.createElementNS(XML.SOAP11ENV_NS,"Fault");
            s.setAttributeNS(XML.XMLNS_NS,"xmlns:soap",XML.SOAP11ENV_NS);

            Element sc=doc.createElementNS(null,"faultcode");
            if (codes==null || codes.isEmpty())
                sc.appendChild(doc.createTextNode("soap:Server"));
            else
                sc.appendChild(doc.createTextNode("soap:" + ((QName)(codes.get(0))).getLocalPart()));
            s.appendChild(sc);

            if (getMessage() != null)
            {
                Element msg=doc.createElementNS(null,"faultstring");
                msg.appendChild(doc.createTextNode(getMessage()));
                s.appendChild(msg);
            }
            root = s;
        }

        return root;
    }
}

