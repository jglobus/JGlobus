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

import org.globus.gsi.util.CertificateUtil;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;

/**
 * Represents ProxyCertInfo extension. <BR>
 * <p>
 * <PRE>
 * ProxyCertInfo ::= SEQUENCE { pCPathLenConstraint      INTEGER (0..MAX) OPTIONAL, proxyPolicy ProxyPolicy }
 * </PRE>
 */
public class ProxyCertInfo implements ASN1Encodable {

    /** ProxyCertInfo extension OID */
    public static final ASN1ObjectIdentifier OID
        = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.14");
    public static final ASN1ObjectIdentifier OLD_OID
        = new ASN1ObjectIdentifier("1.3.6.1.4.1.3536.1.222");

    private DERInteger pathLenConstraint;
    private ProxyPolicy proxyPolicy;

    /**
     * Creates a new instance of the ProxyCertInfo extension from given ASN1Sequence object.
     *
     * @param seq ASN1Sequence object to create the instance from.
     */
    public ProxyCertInfo(ASN1Sequence seq) {
        if (seq.size() < 1) {
            throw new IllegalArgumentException();
        }

        int seqPos = 0;

        if (seq.getObjectAt(seqPos) instanceof DERInteger) {
            this.pathLenConstraint = (DERInteger) seq.getObjectAt(seqPos);
            seqPos++;
        }

        ASN1Sequence policy =
                (ASN1Sequence) seq.getObjectAt(seqPos);

        this.proxyPolicy = new ProxyPolicy(policy);
    }

    /**
     * Creates a new instance of the ProxyCertInfo extension.
     *
     * @param pathLenConstraint the path length constraint of the extension.
     * @param policy            the policy of the extension.
     */
    public ProxyCertInfo(int pathLenConstraint, ProxyPolicy policy) {
        if (policy == null) {
            throw new IllegalArgumentException();
        }
        this.pathLenConstraint = new DERInteger(pathLenConstraint);
        this.proxyPolicy = policy;
    }

    /**
     * Creates a new instance of the ProxyCertInfo extension with no path length constraint.
     *
     * @param policy the policy of the extension.
     */
    public ProxyCertInfo(ProxyPolicy policy) {
        if (policy == null) {
            throw new IllegalArgumentException();
        }
        this.pathLenConstraint = null;
        this.proxyPolicy = policy;
    }

    /**
     * Returns an instance of <code>ProxyCertInfo</code> from given object.
     *
     * @param obj the object to create the instance from.
     * @return <code>ProxyCertInfo</code> instance.
     * @throws IllegalArgumentException if unable to convert the object to <code>ProxyCertInfo</code> instance.
     */
    public static ProxyCertInfo getInstance(Object obj) {

//        String err = obj.getClass().getName();

        if (obj instanceof ProxyCertInfo) {
            return (ProxyCertInfo) obj;
        } else if (obj instanceof ASN1Sequence) {
            return new ProxyCertInfo((ASN1Sequence) obj);
        } else if (obj instanceof byte[]) {
            ASN1Primitive derObj;
            try {
                derObj = CertificateUtil.toASN1Primitive((byte[]) obj);
            } catch (IOException e) {
                throw new IllegalArgumentException(e.getMessage(), e);
            }
            if (derObj instanceof ASN1Sequence) {
                return new ProxyCertInfo((ASN1Sequence) derObj);
            }
        }
        throw new IllegalArgumentException();
    }

    /**
     * Returns the DER-encoded ASN.1 representation of the extension.
     *
     * @return <code>DERObject</code> the encoded representation of the extension.
     */
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector();

        if (this.pathLenConstraint != null) {
            vec.add(this.pathLenConstraint);
        }

        vec.add(this.proxyPolicy.toASN1Primitive());

        return new DERSequence(vec);
    }

    /**
     * Returns the policy object in the proxy.
     *
     * @return <code>ProxyPolicy</code> the policy object
     */
    public ProxyPolicy getProxyPolicy() {
        return this.proxyPolicy;
    }

    /**
     * Returns the maximum depth of the path of proxy certificates that can be signed by this proxy certificate.
     *
     * @return the maximum depth of the path of proxy certificates that can be
     *         signed by this proxy certificate. If 0 then this certificate must
     *         not be used to sign a proxy certificate. If the path length
     *         constraint field is not defined <code>Integer.MAX_VALUE</code> is
     *         returned.
     */
    public int getPathLenConstraint() {
        if (this.pathLenConstraint != null) {
            return this.pathLenConstraint.getValue().intValue();
        }
        return Integer.MAX_VALUE;
    }

}

