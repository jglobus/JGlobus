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
package org.globus.gsi.proxy.ext;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * Represents the policy part of the ProxyCertInfo extension. <BR> <PRE>
 * ProxyPolicy ::= SEQUENCE { policyLanguage    OBJECT IDENTIFIER, policy OCTET STRING OPTIONAL } </PRE>
 */
public class ProxyPolicy implements ASN1Encodable {

    /**
     * Impersonation proxy OID
     */
    public static final ASN1ObjectIdentifier IMPERSONATION = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.21.1");

    /**
     * Independent proxy OID
     */
    public static final ASN1ObjectIdentifier INDEPENDENT = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.21.2");

    /**
     * Limited proxy OID
     */
    public static final ASN1ObjectIdentifier LIMITED = new ASN1ObjectIdentifier("1.3.6.1.4.1.3536.1.1.1.9");

    private ASN1ObjectIdentifier policyLanguage;
    private DEROctetString policy;

    /**
     * Creates a new instance of the ProxyPolicy object from given ASN1Sequence object.
     *
     * @param seq ASN1Sequence object to create the instance from.
     */
    public ProxyPolicy(ASN1Sequence seq) {
        if (seq.size() < 1) {
            throw new IllegalArgumentException();
        }
        this.policyLanguage = (ASN1ObjectIdentifier) seq.getObjectAt(0);
        if (seq.size() > 1) {
            ASN1Encodable obj = seq.getObjectAt(1);
            if (obj instanceof DERTaggedObject) {
                obj = ((DERTaggedObject) obj).getObject();
            }
            this.policy = (DEROctetString) obj;
        }
        checkConstraints();
    }


    /**
     * Creates a new instance of the ProxyPolicy object.
     *
     * @param policyLanguage the language policy Oid.
     * @param policy         the policy.
     */
    public ProxyPolicy(
            ASN1ObjectIdentifier policyLanguage,
            byte[] policy) {
        if (policyLanguage == null) {
            throw new IllegalArgumentException();
        }
        this.policyLanguage = policyLanguage;
        if (policy != null) {
            this.policy = new DEROctetString(policy);
        }
        checkConstraints();
    }

    /**
     * Creates a new instance of the ProxyPolicy object.
     *
     * @param policyLanguageOid the language policy Oid.
     * @param policy            the policy.
     */
    public ProxyPolicy(
            String policyLanguageOid,
            byte[] policy) {
        if (policyLanguageOid == null) {
            throw new IllegalArgumentException();
        }
        this.policyLanguage = new ASN1ObjectIdentifier(policyLanguageOid);
        if (policy != null) {
            this.policy = new DEROctetString(policy);
        }
        checkConstraints();
    }

    /**
     * Creates a new instance of the ProxyPolicy object.
     *
     * @param policyLanguage the language policy Oid.
     * @param policy         the policy.
     */
    public ProxyPolicy(
            ASN1ObjectIdentifier policyLanguage,
            String policy) {
        this(policyLanguage, (policy != null) ? policy.getBytes() : null);
    }

    /**
     * Creates a new instance of the ProxyPolicy object with no policy.
     *
     * @param policyLanguage the language policy Oid.
     */
    public ProxyPolicy(ASN1ObjectIdentifier policyLanguage) {
        this(policyLanguage, (byte[]) null);
    }

    /**
     * Returns the DER-encoded ASN.1 representation of proxy policy.
     *
     * @return <code>DERObject</code> the encoded representation of the proxy
     *         policy.
     */
    public ASN1Primitive toASN1Primitive() {

        ASN1EncodableVector vec = new ASN1EncodableVector();

        vec.add(this.policyLanguage);

        if (this.policy != null) {
            vec.add(this.policy);
        }

        return new DERSequence(vec);
    }

    protected void checkConstraints() {
        if ((this.policyLanguage.equals(IMPERSONATION)
                || this.policyLanguage.equals(INDEPENDENT))
                && this.policy != null) {
            throw new IllegalArgumentException();
        }
    }

    /**
     * Returns the actual policy embedded in the ProxyPolicy object.
     *
     * @return the policy in bytes. Might be null.
     */
    public byte[] getPolicy() {
        return (this.policy != null) ? this.policy.getOctets() : new byte[0];
    }

    /**
     * Returns the actual policy embedded in the ProxyPolicy object.
     *
     * @return the policy as String. Might be null.
     */
    @SuppressWarnings("PMD.StringInstantiation")
    public String getPolicyAsString() {
        return (this.policy != null) ? new String(this.policy.getOctets()) : null;
    }

    /**
     * Returns the policy language of the ProxyPolicy.
     *
     * @return the policy language Oid.
     */
    public ASN1ObjectIdentifier getPolicyLanguage() {
        return this.policyLanguage;
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        buf.append("ProxyPolicy: ");
        buf.append(this.policyLanguage.getId());
        if (this.policy != null) {
            buf.append(System.getProperty("line.separator"));
            buf.append(getPolicyAsString());
        }
        return buf.toString();
    }
}
