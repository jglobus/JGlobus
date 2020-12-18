/*
 * Copyright 2008-2009 University of Illinois
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * An abstraction for a SAML principal.  Corresponds to an
 * unqualified SAML name identifier string value or an
 * identity attribute string value (i.e., an attribute whose
 * string values are globally unique principal names, such
 * as an e-mail address).
 * <p>
 * A <code>SAMLPrincipal</code> is trusted by definition.
 * Therefore, do not call the setter methods of the superclass.
 * <p>
 * This class implements the <code>SecurityAttributes</code>
 * interface by virtue of the superclass
 * <code>DecoratedSecurityItem</code>.  The name and value
 * of the security attribute are the type and name of
 * this <code>SAMLPrincipal</code> instance, respectively.
 * Note that the security attribute associated with this
 * <code>SAMLPrincipal</code> instance is single-valued.
 *
 * @see org.globus.gridshib.security.DecoratedSecurityItem
 * @see org.globus.gridshib.security.SecurityPrincipal
 * @see org.globus.gridshib.security.SecurityAttributes
 *
 * @since 0.5.0
 */
public class SAMLPrincipal extends DecoratedSecurityItem
                        implements SecurityPrincipal {

    static Log logger =
        LogFactory.getLog(SAMLPrincipal.class.getName());

    private String name;
    private String type;

    /**
     * @deprecated As of version&nbsp;0.5.4, use
     *             {@link #SAMLPrincipal(String, String, String, String)}
     *             instead.
     */
    protected SAMLPrincipal(String id, String issuer, String name) {

        this(id, issuer, name, "unknown");
    }

    /**
     * @exception java.lang.IllegalArgumentException
     *            if any parameter is null
     *
     * @since 0.5.4
     */
    protected SAMLPrincipal(String id, String issuer, String name,
                                                      String type) {

        super(id, issuer);

        if (name == null) {
            throw new IllegalArgumentException("Null name argument");
        }

        if (type == null) {
            throw new IllegalArgumentException("Null type argument");
        }

        this.name = name;
        this.type = type;

        this.addAttributeValue(this.type, this.name);

        this.setTrusted(true);
    }

    public String getName() {
        return this.name;
    }

    /**
     * @since 0.5.4
     */
    public String getType() {
        return this.type;
    }

    public boolean equals(Object o) {

        if (this == o) return true;
        if (!(o instanceof SAMLPrincipal)) return false;

        SAMLPrincipal principal = (SAMLPrincipal)o;

        assert (this.getIssuer() != null);
        if (!this.getIssuer().equals(principal.getIssuer())) return false;

        assert (this.name != null);
        if (!this.name.equals(principal.getName())) return false;

        return true;
    }

    public int hashCode() {
        return this.getIssuer().hashCode() & this.name.hashCode();
    }

    public String toString() {

        StringBuffer buf = new StringBuffer("SAMLPrincipal ");
        buf.append("{\n  id='").append(this.getId());
        buf.append("'\n  issuer='").append(this.getIssuer());
        buf.append("'\n  name='").append(this.name);
        buf.append("'\n}");

        return buf.toString();
    }
}
