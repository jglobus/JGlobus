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

package org.globus.gridshib.security;

/**
 * Every component of a security context must implement
 * this interface.
 */
public interface IssuedSecurityItem {

    /**
     * Get the unique ID of this issued security item.
     *
     * @return the unique identifier of this item
     *
     * @since 0.3.0
     */
    public String getId();

    /**
     * Set the unique ID of this issued security item.
     *
     * @param id the unique identifier of this item
     *
     * @since 0.3.0
     *
     * @deprecated As of version&nbsp;0.5.4, implement but do not use
     *             this setter method.  This method interface and its
     *             implementation will be removed in a future version
     *             of GridShib SAML Tools.
     */
    public void setId(String id);

    /**
     * Get the issuer of this issued security item.
     *
     * @return the unique identifier of this issuer
     */
    public String getIssuer();

    /**
     * Set the issuer of this issued security item.
     *
     * @param issuer the unique identifier of the issuer
     *
     * @deprecated As of version&nbsp;0.5.4, implement but do not use
     *             this setter method.  This method interface and its
     *             implementation will be removed in a future version
     *             of GridShib SAML Tools.
     */
    public void setIssuer(String issuer);

    /**
     * Indicates whether or not the issued security item
     * is trusted.
     *
     * @return true if and only the issued security item
     *         is trusted
     *
     * @since 0.3.0
     */
    public boolean isTrusted();

    /**
     * Marks this issued security item as trusted.
     *
     * @param trusted indicates whether or not the issued
     *        security item is trusted
     *
     * @since 0.3.0
     */
    public void setTrusted(boolean trusted);

    /**
     * Compare this issued security item with the
     * given object.
     */
    public boolean equals(Object o);

    /**
     * Compute the hash code of this issued security item.
     */
    public int hashCode();

    /**
     * A string representation of this issued security item,
     * suitable for logging.
     */
    public String toString();
}
