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
package org.globus.gsi;

/** 
 * Defines common constants used by GSI.
 */
// COMMENT: 2 ways to defined a certificate type: integer and enum. 
public interface GSIConstants {
    
    /** The character sent on the wire to request delegation */
    public static final char DELEGATION_CHAR = 'D';

    /** Null ciphersuite supported in older Globus servers */
    public static final String[] GLOBUS_CIPHER  = {"SSL_RSA_WITH_NULL_MD5"};

    /** Indicates no delegation
     * @deprecated Use DelegationType.NONE instead
     */
    public static final int DELEGATION_NONE = 1;

    /** Indicates limited delegation. 
     * Depending on the settings it might mean GSI-2 limited delegation
     * or GSI-3 limited delegation.
     * @deprecated Use DelegationType.LIMITED instead
     */
    public static final int DELEGATION_LIMITED = 2;

    /** Indicates full delegation. 
     * Depending on the settings it might mean GSI-2 full delegation
     * or GSI-3 impersonation delegation.
     * @deprecated Use DelegationType.FULL instead
     */
    public static final int DELEGATION_FULL = 3;

    /** Indicates GSI mode (allows for delegation during authentication). 
     */
    public static final Integer MODE_GSI = 1;
    
    /** Indicates SSL compatibility mode (does not allow for delegation 
     * during authentication). */
    public static final Integer MODE_SSL = 2;
    
    /** Indicates full delegation. */
    public static final Integer DELEGATION_TYPE_FULL 
    = GSIConstants.DELEGATION_FULL;
    
    /** Indicates limited delegation. */
    public static final Integer DELEGATION_TYPE_LIMITED 
    = GSIConstants.DELEGATION_LIMITED;
    
    /** Indicates End-Entity Certificate, e.g. user certificate
     * @deprecated Use CertificateType.EEC instead
     */
    public static final int EEC = 3;

    /** Indicates Certificate Authority certificate 
     * @deprecated Use CertificateType.CA instead
     */
    public static final int CA = 4;
    
    /** Indicates legacy full Globus proxy
     * @deprecated Use CertificateType.GSI_2_PROXY instead
     */
    public static final int GSI_2_PROXY         = 10;

    /** Indicates legacy limited Globus proxy
     * @deprecated Use CertificateType.GSI_2_LIMITED_PROXY instead
     */
    public static final int GSI_2_LIMITED_PROXY = 11;

    /** Indicates proxy draft compliant restricted proxy.
     * A proxy with embedded policy.
     * @deprecated Use CertificateType.GSI_3_RESTRICTED_PROXY instead
     */
    public static final int GSI_3_RESTRICTED_PROXY    = 12;

    /** Indicates proxy draft compliant independent proxy.
     * A proxy with {@link org.globus.gsi.proxy.ext.ProxyPolicy#INDEPENDENT
     * ProxyPolicy.INDEPENDENT} policy language OID.
     * @deprecated Use CertificateType.GSI_3_INDEPENDENT_PROXY instead
     */
    public static final int GSI_3_INDEPENDENT_PROXY   = 13;

    /** Indicates proxy draft compliant impersonation proxy.
     * A proxy with {@link org.globus.gsi.proxy.ext.ProxyPolicy#IMPERSONATION 
     * ProxyPolicy.IMPERSONATION} policy language OID.
     * @deprecated Use CertificateType.GSI_3_IMPERSONATION_PROXY instead
     */
    public static final int GSI_3_IMPERSONATION_PROXY = 14;

    /** Indicates proxy draft compliant limited impersonation proxy.
     * A proxy with {@link org.globus.gsi.proxy.ext.ProxyPolicy#LIMITED 
     * ProxyPolicy.LIMITED} policy language OID.
     * @deprecated Use CertificateType.GSI_3_RESTRICTED_PROXY instead
     */
    public static final int GSI_3_LIMITED_PROXY       = 15;

    /** Indicates RFC 3820 compliant restricted proxy.
     * A proxy with embedded policy.
     * @deprecated Use CertificateType.GSI_4_RESTRICTED_PROXY instead
     */
    public static final int GSI_4_RESTRICTED_PROXY    = 16;

    /** Indicates RFC 3820 compliant independent proxy.
     * A proxy with {@link org.globus.gsi.proxy.ext.ProxyPolicy#INDEPENDENT
     * ProxyPolicy.INDEPENDENT} policy language OID.
     * @deprecated Use CertificateType.GSI_4_INDEPENDENT_PROXY instead
     */
    public static final int GSI_4_INDEPENDENT_PROXY   = 17;

    /** Indicates RFC 3820 compliant impersonation proxy.
     * A proxy with {@link org.globus.gsi.proxy.ext.ProxyPolicy#IMPERSONATION 
     * ProxyPolicy.IMPERSONATION} policy language OID.
     * @deprecated Use CertificateType.GSI_4_IMPERSONATION_PROXY instead
     */
    public static final int GSI_4_IMPERSONATION_PROXY = 18;

    /** Indicates RFC 3820 compliant limited impersonation proxy.
     * A proxy with {@link org.globus.gsi.proxy.ext.ProxyPolicy#LIMITED 
     * ProxyPolicy.LIMITED} policy language OID.
     * @deprecated Use CertificateType.GSI_4_LIMITED_PROXY instead
     */
    public static final int GSI_4_LIMITED_PROXY       = 19;

    /** GSI Transport protection method type
     * that will be used or was used to protect the request.
     * Can be set to:
     * {@link GSIConstants#SIGNATURE SIGNATURE} or
     * {@link GSIConstants#ENCRYPTION ENCRYPTION} or
     * {@link GSIConstants#NONE NONE}.
     */
    public static final String GSI_TRANSPORT =
        "org.globus.security.transport.type";

    /** integrity message protection method. */
    public static final Integer SIGNATURE
        = 1;

    /** privacy message protection method. */
    public static final Integer ENCRYPTION
        = 2;

    /** none message protection method. */
    public static final Integer NONE =
            Integer.MAX_VALUE;

    /**
     * It is used to set a list of trusted certificates
     * to use during authentication (by default, the trusted certificates
     * are loaded from a standard location) The value is an instance of
     * {@link org.globus.gsi.TrustedCertificates TrustedCertificates}
     */
    public static final String TRUSTED_CERTIFICATES = 
        "org.globus.security.trustedCertifictes";

    /** 
     * It is set to a Boolean value and if false,
     * client authorization requirement with delegation is disabled. By
     * default, client side authorization (to authorize the server) is
     * required for delegation of credentials.
     */
    public static final String AUTHZ_REQUIRED_WITH_DELEGATION = 
        "org.globus.security.authz.required.delegation";
    
    /**
     * Enumeration of Certificate types used by the Globus security provider.
     */
    // COMMENT: TODO: replace the the cert type constants with this enum
    public enum CertificateType {
        EEC(3), CA(4), GSI_2_PROXY(10), GSI_2_LIMITED_PROXY(11), GSI_3_RESTRICTED_PROXY(12),
        GSI_3_INDEPENDENT_PROXY(13), GSI_3_IMPERSONATION_PROXY(14), GSI_3_LIMITED_PROXY(15),
        GSI_4_RESTRICTED_PROXY(16), GSI_4_INDEPENDENT_PROXY(17), GSI_4_IMPERSONATION_PROXY(18), 
        GSI_4_LIMITED_PROXY(19), UNDEFINED(-1);
        
        private int code;

        private CertificateType(int c) {
            code = c;
        }

        public int getCode() {
            return code;
        }
        
        public static CertificateType get(int code) {
            for (CertificateType tmp : CertificateType.values()) {
                if (tmp.getCode() == code) {
                    return tmp;
                }
            }
            throw new IllegalArgumentException("invalid certificate type code");
        }
    }

    /**
     * Enumeration of Certificate types used by the Globus security provider.
     */
    // COMMENT: TODO: replace the the delegation type constants with this enum
    public enum DelegationType {
        NONE(1), LIMITED(2), FULL(3);
        
        private int code;

        private DelegationType(int c) {
            code = c;
        }

        public int getCode() {
            return code;
        }
        
        public static DelegationType get(int code) {
            for (DelegationType tmp : DelegationType.values()) {
                if (tmp.getCode() == code) {
                    return tmp;
                }
            }
            throw new IllegalArgumentException("invalid delegation type code");
        }
    }

}
