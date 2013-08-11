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

import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.TimeZone;

import javax.xml.namespace.QName;

import org.w3c.dom.*;

/**
 *  Represents a SAML Authentication Statement
 *
 * @author     Scott Cantor (created March 25, 2002)
 */
public class SAMLAuthenticationStatement extends SAMLSubjectStatement implements Cloneable
{
    protected String subjectIP = null;
    protected String subjectDNS = null;
    protected String authMethod = null;
    protected Date authInstant = null;
    protected ArrayList bindings = new ArrayList();

    /** The authentication was performed by means of a password. */
    public static final String AuthenticationMethod_Password = "urn:oasis:names:tc:SAML:1.0:am:password";

    /** The authentication was performed by means of the Kerberos protocol [RFC 1510],
     * an instantiation of the Needham-Schroeder symmetric key authentication mechanism [Needham78]. */
    public static final String AuthenticationMethod_Kerberos = "urn:ietf:rfc:1510";

    /** The authentication was performed by means of Secure Remote Password protocol as specified in [RFC 2945]. */
    public static final String AuthenticationMethod_SRP = "urn:ietf:rfc:2945";

    /** The authentication was performed by means of an unspecified hardware token. */
    public static final String AuthenticationMethod_HardwareToken = "urn:oasis:names:tc:SAML:1.0:am:HardwareToken";

    /** The authentication was performed using either the SSL or TLS protocol with certificate based client
     * authentication. TLS is described in [RFC 2246]. */
    public static final String AuthenticationMethod_SSL_TLS_Client = "urn:ietf:rfc:2246";

    /** The authentication was performed by some (unspecified) mechanism on a key authenticated by means of an
     * X.509 PKI [X.500][PKIX]. It may have been one of the mechanisms for which a more specific identifier
     * has been defined. */
    public static final String AuthenticationMethod_X509_PublicKey = "urn:oasis:names:tc:SAML:1.0:am:X509-PKI";

    /** The authentication was performed by some (unspecified) mechanism on a key authenticated by means of
     * a PGP web of trust [PGP]. It may have been one of the mechanisms for which a more specific identifier
     * has been defined. */
    public static final String AuthenticationMethod_PGP_PublicKey = "urn:oasis:names:tc:SAML:1.0:am:PGP";

    /** The authentication was performed by some (unspecified) mechanism on a key authenticated by means of a
     * SPKI PKI [SPKI]. It may have been one of the mechanisms for which a more specific identifier has been
     * defined. */
    public static final String AuthenticationMethod_SPKI_PublicKey = "urn:oasis:names:tc:SAML:1.0:am:SPKI";

    /** The authentication was performed by some (unspecified) mechanism on a key authenticated by means of a
     * XKMS trust service [XKMS]. It may have been one of the mechanisms for which a more specific identifier
     * has been defined. */
    public static final String AuthenticationMethod_XKMS_PublicKey = "urn:oasis:names:tc:SAML:1.0:am:XKMS";

    /** The authentication was performed by means of an XML digital signature [RFC 3075]. */
    public static final String AuthenticationMethod_XML_DSig = "urn:ietf:rfc:3075";

    /** The authentication was performed by an unspecified means. */
    public static final String AuthenticationMethod_Unspecified = "urn:oasis:names:tc:SAML:1.0:am:unspecified";

    /**
     *  Default constructor
     */
    public SAMLAuthenticationStatement() {
    }

    /**
     *  Builds a statement out of its component parts
     *
     * @param  subject            Subject of statement
     * @param  authMethod         URI of authentication method
     * @param  authInstant        Datetime of authentication
     * @param  subjectIP          IP address of subject in dotted decimal
     *      notation (optional)
     * @param  subjectDNS         DNS address of subject (optional)
     * @param  bindings           Collection of SAMLAuthorityBinding objects to
     *      reference SAML responders (optional)
     * @exception  SAMLException  Raised if a statement cannot be constructed
     *      from the supplied information
     */
    public SAMLAuthenticationStatement(
            SAMLSubject subject,
            String authMethod,
            Date authInstant,
            String subjectIP,
            String subjectDNS,
            Collection bindings
            ) throws SAMLException {

        super(subject);

        this.subjectIP = XML.assign(subjectIP);
        this.subjectDNS = XML.assign(subjectDNS);
        this.authMethod = XML.assign(authMethod);
        this.authInstant = authInstant;
        if (bindings != null) {
            for (Iterator i = bindings.iterator(); i.hasNext(); )
                this.bindings.add(((SAMLAuthorityBinding)i.next()).setParent(this));
        }
    }

    /**
     *  Builds a statement out of its component parts
     *
     * @param  subject            Subject of statement
     * @param  authInstant        Datetime of authentication
     * @param  subjectIP          IP address of subject in dotted decimal
     *      notation (optional)
     * @param  subjectDNS         DNS address of subject (optional)
     * @param  bindings           Collection of SAMLAuthorityBinding objects to
     *      reference SAML responders (optional)
     * @exception  SAMLException  Raised if a statement cannot be constructed
     *      from the supplied information
     */
    public SAMLAuthenticationStatement(
            SAMLSubject subject,
            Date authInstant,
            String subjectIP,
            String subjectDNS,
            Collection bindings
            ) throws SAMLException {
        this(subject,SAMLAuthenticationStatement.AuthenticationMethod_Unspecified,authInstant,subjectIP,subjectDNS, bindings);
    }

    /**
     *  Reconstructs a statement from a DOM tree
     *
     * @param  e                  The root of a DOM tree
     * @exception  SAMLException  Thrown if the object cannot be constructed
     */
    public SAMLAuthenticationStatement(Element e) throws SAMLException {
        fromDOM(e);
    }

    /**
     *  Reconstructs a statement from a stream
     *
     * @param  in                   A stream containing XML
     * @exception  SAMLException  Raised if an exception occurs while constructing
     *                              the object.
     */
    public SAMLAuthenticationStatement(InputStream in) throws SAMLException {
        fromDOM(fromStream(in));
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#fromDOM(org.w3c.dom.Element)
     */
    public void fromDOM(Element e) throws SAMLException {
        super.fromDOM(e);

        if (config.getBooleanProperty("org.globus.opensaml11.saml.strict-dom-checking") && !XML.isElementNamed(e,XML.SAML_NS,"AuthenticationStatement"))
        {
            QName q=XML.getQNameAttribute(e,XML.XSI_NS,"type");
            if (!(XML.isElementNamed(e,XML.SAML_NS,"Statement") || XML.isElementNamed(e,XML.SAML_NS,"SubjectStatement")) || q==null || !XML.SAML_NS.equals(q.getNamespaceURI()) || !"AuthenticationStatementType".equals(q.getLocalPart()))
                throw new MalformedException(SAMLException.RESPONDER, "SAMLAuthenticationStatement() requires saml:AuthenticationStatement at root");
        }

        authMethod = XML.assign(e.getAttributeNS(null,"AuthenticationMethod"));

        try {
            SimpleDateFormat formatter = null;
            String dateTime = XML.assign(e.getAttributeNS(null, "AuthenticationInstant"));
            int dot = dateTime.indexOf('.');
            if (dot > 0) {
                formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
            }
            else {
                formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            }
            formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
            authInstant = formatter.parse(dateTime);
        }
        catch (java.text.ParseException ex) {
            throw new MalformedException(SAMLException.RESPONDER, "SAMLAuthenticationStatement() detected an invalid datetime while parsing statement", ex);
        }

        // Check for locality
        Element n = XML.getFirstChildElement(root, XML.SAML_NS, "SubjectLocality");
        if (n != null) {
            subjectIP = XML.assign(n.getAttributeNS(null, "IPAddress"));
            subjectDNS = XML.assign(n.getAttributeNS(null, "DNSAddress"));
            n = XML.getNextSiblingElement(n);
        }

        // Extract bindings.
        n = XML.getFirstChildElement(root, XML.SAML_NS, "AuthorityBinding");
        while (n != null) {
            bindings.add(new SAMLAuthorityBinding(n).setParent(this));
            n = XML.getNextSiblingElement(n, XML.SAML_NS, "AuthorityBinding");
        }

        checkValidity();
    }

    /**
     *  Gets the subject's IP address
     *
     * @return    The subject's IP address in dotted decimal notation
     */
    public String getSubjectIP() {
        return subjectIP;
    }

    /**
     *  Sets the subject's IP address
     *
     * @param   subjectIP   The subject's IP address
     */
    public void setSubjectIP(String subjectIP) {
        this.subjectIP = XML.assign(subjectIP);
        setDirty(true);
    }

    /**
     *  Gets the subject's DNS address
     *
     * @return    The subject's DNS address
     */
    public String getSubjectDNS() {
        return subjectDNS;
    }

    /**
     *  Sets the subject's DNS address
     *
     * @param   subjectDNS  The subject's DNS address
     */
    public void setSubjectDNS(String subjectDNS) {
        this.subjectDNS = XML.assign(subjectDNS);
        setDirty(true);
    }

    /**
     *  Gets the authentication method
     *
     * @return    The authentication method URI
     */
    public String getAuthMethod() {
        return authMethod;
    }

    /**
     *  Sets the authentication method
     *
     * @param   authMethod    The authentication method URI
     */
    public void setAuthMethod(String authMethod) {
        if (XML.isEmpty(authMethod))
            throw new IllegalArgumentException("authMethod cannot be null");
        this.authMethod = authMethod;
        setDirty(true);
    }

    /**
     *  Gets the datetime of authentication
     *
     * @return    The date and time of authentication
     */
    public Date getAuthInstant() {
        return authInstant;
    }

    /**
     *  Sets the datetime of authentication
     *
     * @param   authInstant    The date and time of authentication
     */
    public void setAuthInstant(Date authInstant) {
        if (authInstant == null)
            throw new IllegalArgumentException("authInstant cannot be null");
        this.authInstant = authInstant;
        setDirty(true);
    }

    /**
     *  Gets SAML authority binding information
     *
     * @return    An iterator of bindings
     */
    public Iterator getBindings() {
        return bindings.iterator();
    }

    /**
     *  Sets SAML authority binding information
     *
     * @param bindings    The bindings to include
     * @throws SAMLException    Raised if any of the bindings are invalid
     */
    public void setBindings(Collection bindings) throws SAMLException {
        this.bindings.clear();
        if (bindings != null) {
            for (Iterator i = bindings.iterator(); i.hasNext(); )
                this.bindings.add(((SAMLAuthorityBinding)i.next()).setParent(this));
        }
        setDirty(true);
    }

    /**
     *  Adds SAML authority binding information
     *
     * @param binding    The binding to add
     * @exception SAMLException     Raised if the binding is invalid
     */
    public void addBinding(SAMLAuthorityBinding binding) throws SAMLException {
        if (binding != null) {
            bindings.add(binding.setParent(this));
            setDirty(true);
        }
        else
            throw new IllegalArgumentException("binding cannot be null");
    }

    /**
     *  Removes a binding by position (zero-based)
     *
     * @param   index   The position of the binding to remove
     */
    public void removeBinding(int index) {
        bindings.remove(index);
        setDirty(true);
    }

    /**
     *  @see org.globus.opensaml11.saml.SAMLObject#buildRoot(org.w3c.dom.Document,boolean)
     */
    protected Element buildRoot(Document doc, boolean xmlns) {
        Element s = doc.createElementNS(XML.SAML_NS, "AuthenticationStatement");
        if (xmlns)
            s.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
        return s;
    }

    /**
     *  @see org.globus.opensaml11.saml.SAMLObject#toDOM(org.w3c.dom.Document,boolean)
     */
    public Node toDOM(Document doc, boolean xmlns) throws SAMLException {
        // Let the base build/verify the DOM root.
        super.toDOM(doc, xmlns);
        Element statement = (Element)root;

        if (dirty) {
            SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
            formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
            statement.setAttributeNS(null, "AuthenticationInstant", formatter.format(authInstant));
            statement.setAttributeNS(null, "AuthenticationMethod", authMethod);

            if (!XML.isEmpty(subjectIP) || !XML.isEmpty(subjectDNS)) {
                Element locality = doc.createElementNS(XML.SAML_NS, "SubjectLocality");
                if (!XML.isEmpty(subjectIP))
                    locality.setAttributeNS(null,"IPAddress", subjectIP);
                if (!XML.isEmpty(subjectDNS))
                    locality.setAttributeNS(null,"DNSAddress", subjectDNS);
                statement.appendChild(locality);
            }

            for (Iterator i=bindings.iterator(); i.hasNext(); )
                statement.appendChild(((SAMLAuthorityBinding)i.next()).toDOM(doc, false));

            setDirty(false);
        }
        else if (xmlns) {
            statement.setAttributeNS(XML.XMLNS_NS, "xmlns", XML.SAML_NS);
        }
        return root;
    }

    /**
     * @see org.globus.opensaml11.saml.SAMLObject#checkValidity()
     */
    public void checkValidity() throws SAMLException {
        super.checkValidity();
        if (XML.isEmpty(authMethod)) {
            String msg = "AuthenticationStatement is invalid, " +
                         "requires AuthenticationMethod";
            throw new MalformedException(msg);
        }
        try {
            new URI(authMethod);
        } catch (URISyntaxException e) {
            String msg = "AuthenticationStatement is invalid, " +
                         "AuthenticationMethod must be a URI";
            throw new MalformedException(msg);
        }
        if (authInstant == null) {
            String msg = "AuthenticationStatement is invalid, " +
                         "requires AuthenticationInstant";
            throw new MalformedException(msg);
        }
    }

    /**
     *  Copies a SAML object such that no dependencies exist between the original
     *  and the copy
     *
     * @return      The new object
     * @see Object#clone()
     */
    public Object clone() throws CloneNotSupportedException {
        SAMLAuthenticationStatement dup=(SAMLAuthenticationStatement)super.clone();

        try {
            // Clone the embedded objects.
            dup.bindings = new ArrayList();
            for (Iterator i = bindings.iterator(); i.hasNext(); )
                dup.bindings.add(((SAMLAuthorityBinding)((SAMLAuthorityBinding)i.next()).clone()).setParent(dup));
        }
        catch (SAMLException e) {
            throw new CloneNotSupportedException(e.getMessage());
        }

        return dup;
    }
}

