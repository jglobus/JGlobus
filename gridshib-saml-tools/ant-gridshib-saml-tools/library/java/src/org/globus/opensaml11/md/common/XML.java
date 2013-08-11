/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
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

package org.globus.opensaml11.md.common;

/**
 * Utility class for XML constants
 *
 * @author Scott Cantor (created January 2, 2002)
 */
public class XML {

    /** SAMLv2 Metadata XML namespace */
    public final static String SAML2META_NS = "urn:oasis:names:tc:SAML:2.0:metadata";

    /** SAMLv2 Metadata Extension XML namespace */
    public final static String SAML2METAEXT_NS = "urn:oasis:names:tc:SAML:metadata:extension";

    /** SAMLv2 Assertion XML namespace */
    public final static String SAML2ASSERT_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

    /** Shibboleth XML namespace */
    public final static String SHIB_NS = "urn:mace:shibboleth:1.0";

    /** Shibboleth Metadata XML namespace */
    public final static String SHIBMETA_NS = "urn:mace:shibboleth:metadata:1.0";

    /** Shibboleth trust metadata XML namespace */
    public final static String TRUST_NS = "urn:mace:shibboleth:trust:1.0";

    /** XML Encryption namespace */
    public final static String XMLENC_NS = "http://www.w3.org/2001/04/xmlenc#";

    public final static String MAIN_SHEMA_ID = "shibboleth-targetconfig-1.0.xsd";
    public final static String IDP_SHEMA_ID = "shibboleth-idpconfig-1.0.xsd";
}
