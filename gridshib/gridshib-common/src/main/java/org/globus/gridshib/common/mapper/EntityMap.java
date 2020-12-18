/*
 * Copyright 2007-2009 University of Illinois
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.globus.gridshib.common.mapper;

import java.security.cert.X509Certificate;
import java.util.Set;

/**
 * A simple mapping abstraction that maps a SAML
 * entityID to various security-related metadata
 * bits such as one or more X.500 distinguished
 * names (DN), scopes, or X.509 certificates.
 */
public interface EntityMap {

    /**
     * Determines whether the SAML entity represented
     * by the given <code>entityID</code> has metadata,
     * that is, if the relying party has consumed
     * metadata for that entity.
     *
     * @param entityID the unique identifier of the entity
     * @return         true if and only if the given entity
     *                 has metadata
     */
    public boolean hasMetadata(String entityID);

    /**
     * Gets all the trusted X.500 distinguished names (DNs)
     * associated with the given SAML entity.  The set of
     * DNs returned by this method may or may not contain
     * the DN bound to the certificate obtained by invoking
     * method {@link #getX509Certificate(String)}.
     *
     * @param entityID the unique identifier of the entity
     * @return         a (possibly empty) set of <code>String</code>
     *                 instances representing the trusted DNs
     *                 associated with the given entity (each in
     *                 RFC2253 format), or null if this entity has
     *                 no metadata
     *
     * @see #getX509Certificate(String)
     *
     * @since 0.6.0
     */
    public Set getDNs(String entityID);

    /**
     * Gets a trusted X.500 distinguished name (DN) for the
     * given SAML entity.  The DN so obtained is guaranteed
     * to be an element of the set of DNs returned by method
     * {@link #getDNs(String)}.  It is an implementation choice
     * as to which DN from the set is returned.
     *
     * @param entityID the unique identifier of the entity
     * @return         a distinguished name (DN) in RFC2253
     *                 format, or null if no such DN exists
     *
     * @see #getDNs(String)
     */
    public String getDN(String entityID);

    /**
     * Gets a trusted X.509 certificate for the given
     * SAML entity.
     *
     * @param entityID the unique identifier of the entity
     * @return         the corresponding trusted certificate,
     *                 or null if no such certificate exists
     */
    public X509Certificate getX509Certificate(String entityID);
}
