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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.w3c.dom.*;
import org.xml.sax.SAXException;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.InclusiveNamespaces;

/**
 *  Abstract base class for all SAML objects that can be signed
 *
 * @author     Scott Cantor (created March 25, 2002)
 */
public abstract class SAMLSignedObject extends SAMLObject implements Cloneable
{
    private XMLSignature sig = null;
    private boolean sig_from_parse = false;

    /**
     *  Debugging aid to access the internal XML Signature implementation
     *
     * @return      Returns a Java object corresponding to the native class
     *              used by the underlying XML Signature implementation to represent
     *              a signature. Be careful using this method, unless you're debugging
     *              or know what you're doing.
     */
    public Object getNativeSignature() {
        return sig;
    }

    /**
     *  Gets the ID of the signed object
     *
     * @return    The XML ID
     */
    public abstract String getId();


    /**
     * @see SAMLObject#fromDOM(org.w3c.dom.Element e)
     */
    public void fromDOM(Element e) throws SAMLException {
        super.fromDOM(e);

        // Locate the Signature beneath the root.
        Element n = XML.getFirstChildElement(e, XML.XMLSIG_NS, "Signature");
        if (n!=null) {
            try {
                sig=new XMLSignature((Element)n,"");
                sig_from_parse = true;
            }
            catch (XMLSecurityException ex) {
                throw new InvalidCryptoException("SAMLSignedObject.fromDOM() detected an XML security exception: " + ex.getMessage(),ex);
            }
        }
    }

    /**
     * @see SAMLObject#toDOM(boolean xmlns)
     */
    public Node toDOM(boolean xmlns) throws SAMLException {
        if (root == null) {
            // The purpose of the override is to reuse the document used to create
            // the signature, if we have one.
            if (sig != null)
                return toDOM(sig.getDocument(),xmlns);
        }

        // If no signature, just let the base class handle it.
        return super.toDOM(xmlns);
    }

    /**
     *  Places the signature into the object's DOM to prepare for signing<p>
     *
     *  Must be overridden by subclass that knows where to place it</p>

     * @throws org.globus.opensaml11.saml.SAMLException    Thrown if an error occurs while placing the signature
     */
    protected abstract void insertSignature() throws SAMLException;

    /**
     *  Get the DOM element containing the signature
     *
     * @return  The ds:Signature element of a signature
     */
    protected Element getSignatureElement()
    {
        return (sig!=null) ? sig.getElement() : null;
    }

    /**
     * @see SAMLObject#setDirty(boolean)
     */
    protected void setDirty(boolean flag) {
        if (flag)
            unsign();
        super.setDirty(flag);
    }

    /**
     *  Remove the signature and turn this into an unsigned object.
     *  Modifying an object after signing will automatically unsign it.
     */
    public void unsign() {
        if (sig != null && sig.getElement().getParentNode() != null)
            sig.getElement().getParentNode().removeChild(sig.getElement());
        sig = null;
    }

    /**
     *  Sign the SAML object according to the input parameters, using a default
     *  digest algorithm.
     *
     * @param sigalg           The XML signature algorithm to apply
     * @param k             The secret or private key to sign the resulting digest
     * @param certs         The public key certificate(s) to embed in the object, if any
     * @throws org.globus.opensaml11.saml.SAMLException    Thrown if an error occurs while constructing the signature
     */
    public void sign(String sigalg, Key k, Collection certs)
        throws SAMLException {
        sign(sigalg,null,k,certs);
    }

    /**
     *  Sign the SAML object according to the input parameters
     *
     * @param sigalg           The XML signature algorithm to apply
     * @param digalg           The digest algorithm to apply
     * @param k             The secret or private key to sign the resulting digest
     * @param certs         The public key certificate(s) to embed in the object, if any
     * @throws org.globus.opensaml11.saml.SAMLException    Thrown if an error occurs while constructing the signature
     */
    public void sign(String sigalg, String digalg, Key k, Collection certs)
        throws SAMLException
    {
        unsign();

        // Generate the DOM if not already built, and anchor the DOM in the document.
        toDOM();
        plantRoot();

        try
        {
            // Build the empty signature.
            sig=new XMLSignature(root.getOwnerDocument(),"",sigalg,Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

            // Have the object place it in the proper place.
            insertSignature();

            Transforms transforms = new Transforms(sig.getDocument());
            transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
            transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
            transforms.item(1).getElement().appendChild(
                    new InclusiveNamespaces(root.getOwnerDocument(),config.getProperty("org.globus.opensaml11.saml.inclusive-namespace-prefixes")).getElement()
                    );

            if (config.getBooleanProperty("org.globus.opensaml11.saml.compatibility-mode"))
                sig.addDocument("",transforms,(digalg!=null) ? digalg : MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1);
            else
                sig.addDocument("#" + getId(),transforms,(digalg!=null) ? digalg : MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1);

            // Add any X.509 certificates provided.
            X509Data x509 = new X509Data(root.getOwnerDocument());
            if (certs!=null)
            {
                int count = 0;
                Iterator i=certs.iterator();
                while (i.hasNext())
                {
                    Object cert=i.next();
                    if (cert instanceof X509Certificate) {
                        if (!i.hasNext() && count > 0) {
                            // Last (but not only) cert in chain. Only add if it's not self-signed.
                            if (((X509Certificate)cert).getSubjectDN().equals(((X509Certificate)cert).getIssuerDN()))
                                break;
                        }
                        x509.addCertificate((X509Certificate)cert);
                    }
                    count++;
                }
            }
            if (x509.lengthCertificate()>0)
            {
                KeyInfo keyinfo = new KeyInfo(root.getOwnerDocument());
                keyinfo.add(x509);
                sig.getElement().appendChild(keyinfo.getElement());
            }

            // Finally, sign the thing.
            sig.sign(k);
        }
        catch (XMLSecurityException e)
        {
            unsign();
            throw new InvalidCryptoException("SAMLSignedObject.sign() detected an XML security exception: " + e.getMessage(),e);
        }
    }

    /**
     *  Verifies the signature using only the keying material included within it
     *
     * @throws org.globus.opensaml11.saml.SAMLException    Thrown if the signature is invalid or if an error occurs
     */
    public void verify()
        throws SAMLException
    {
        verify((Key)null);
    }

    /**
     *  Verifies the signature using the keying material provided
     *
     * @param cert          A public key certificate to use in verifying the signature
     * @throws org.globus.opensaml11.saml.SAMLException    Thrown if the signature is invalid or if an error occurs
     */
    public void verify(Certificate cert)
        throws SAMLException
    {
        verify(cert.getPublicKey());
    }

    /**
     *  Verifies the signature using the keying material provided
     *
     * @param k             A secret or public key to use in verifying the signature
     * @throws org.globus.opensaml11.saml.SAMLException    Thrown if the signature is invalid or if an error occurs
     */
    public void verify(Key k)
        throws SAMLException
    {
        if (!isSigned())
            throw new InvalidCryptoException("SAMLSignedObject.verify() can't verify unsigned object");

        try
        {
            // Validate the signature content by checking for specific Transforms.
            boolean valid=false;
            SignedInfo si=sig.getSignedInfo();
            if (si.getLength()==1)
            {
                Reference ref = si.item(0);
                if (ref.getURI() == null || ref.getURI().equals("") || ref.getURI().equals("#" + getId()))
                {
                    Transforms trans = ref.getTransforms();
                    for (int i=0; i < trans.getLength(); i++)
                    {
                        if (trans.item(i).getURI().equals(Transforms.TRANSFORM_ENVELOPED_SIGNATURE))
                            valid = true;
                        else if (!trans.item(i).getURI().equals(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS))
                        {
                            valid = false;
                            break;
                        }
                    }
                }
            }

            if (!valid)
                throw new InvalidCryptoException("SAMLSignedObject.verify() detected an invalid signature profile");

            // If k is null, try and find a key inside the signature.
            if (k == null)
            {
                if (sig_from_parse)
                    k=sig.getKeyInfo().getPublicKey();
                else
                {
                    // This is really, ugly, but when the signature hasn't been fully built from a DOM,
                    // none of the interesting bits of keying material are reachable via the API.
                    // We have to serialize out the KeyInfo piece, and reparse it.
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    Canonicalizer c = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
                    out.write(c.canonicalizeSubtree(sig.getElement().getLastChild()));
                    ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
                    KeyInfo temp = new KeyInfo(XML.parserPool.parse(in).getDocumentElement(),"");
                    k=temp.getPublicKey();
                }
            }

            if (!sig.checkSignatureValue(k))
                throw new InvalidCryptoException("SAMLSignedObject.verify() failed to validate signature value");
        }
        catch (XMLSecurityException e)
        {
            throw new InvalidCryptoException("SAMLSignedObject.verify() detected an XML security exception: " + e.getMessage(),e);
        }
        catch (java.io.IOException e)
        {
            throw new InvalidCryptoException("SAMLSignedObject.verify() detected an I/O exception: " + e.getMessage(),e);
        }
        catch (SAXException e)
        {
            throw new InvalidCryptoException("SAMLSignedObject.verify() detected a XML parsing exception: " + e.getMessage(),e);
        }
    }

    /**
     *  Returns an iterator over the X.509 certificates included in the signature, if any
     *
     * @return      Provides access to the certificates
     * @throws org.globus.opensaml11.saml.SAMLException    Thrown if the signature is missing
     */
    public Iterator getX509Certificates() throws SAMLException
    {
        if (isSigned()) {
            KeyInfo ki=sig.getKeyInfo();
            if (ki!=null && ki.containsX509Data()) {
                try {
                    for (int i=0; i<ki.lengthX509Data(); i++) {
                        X509Data x509 = ki.itemX509Data(i);
                        if (x509.containsCertificate()) {
                            ArrayList certs=new ArrayList(x509.lengthCertificate());
                            for (int j=0; j<x509.lengthCertificate(); j++)
                                certs.add(x509.itemCertificate(j).getX509Certificate());
                            return certs.iterator();
                        }
                    }
                }
                catch (XMLSecurityException e) {
                    throw new InvalidCryptoException("SAMLSignedObject.getX509Certificates() detected an XML security exception: " + e.getMessage(),e);
                }
            }
            throw new InvalidCryptoException("SAMLSignedObject.getX509Certificates() can't find any X.509 certificates in signature");
        }
        throw new InvalidCryptoException("SAMLSignedObject.getX509Certificates() can't examine unsigned object");
    }

    /**
     *  Returns the signing algorithm identifier from the signature
     *
     * @return      The algorithm identifier
     * @throws org.globus.opensaml11.saml.SAMLException    Thrown if the signature is missing
     */
    public String getSignatureAlgorithm()
        throws SAMLException
    {
        if (isSigned())
            return sig.getSignedInfo().getSignatureMethodURI();
        throw new InvalidCryptoException("SAMLSignedObject.getSignatureAlgorithm() can't examine unsigned object");
    }

    /**
     *  Returns the digest algorithm identifier from the signature
     *
     * @return      The algorithm identifier
     * @throws org.globus.opensaml11.saml.SAMLException    Thrown if the signature is missing
     */
    public String getDigestAlgorithm()
        throws SAMLException
    {
        if (isSigned()) {
            SignedInfo si=sig.getSignedInfo();
            if (si.getLength()==1) {
                Reference ref;
                try {
                    ref = si.item(0);
                    return ref.getMessageDigestAlgorithm().getAlgorithmURI();
                }
                catch (XMLSecurityException e) {
                    throw new InvalidCryptoException("SAMLSignedObject.getDigestAlgorithm() detected an XML security exception: " + e.getMessage(),e);
                }
            }
        }
        throw new InvalidCryptoException("SAMLSignedObject.getDigestAlgorithm() can't examine unsigned or improperly signed object");
    }

    /**
     *  Returns true iff the object contains a signature
     *
     * @return      true iff the object contains a signature
     */
    public boolean isSigned()
    {
        return (sig!=null);
    }

    /**
     *  Copies a SAML object such that no dependencies exist between the original
     *  and the copy.
     *
     * @return      The new object
     * @see Object#clone()
     */
    protected Object clone()
        throws CloneNotSupportedException
    {
        SAMLSignedObject dup=(SAMLSignedObject)super.clone();

        // Clear the signature before returning the copy.
        dup.sig = null;

        return dup;
    }
}
