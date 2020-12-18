/*
 * Copyright 2009 University of Illinois
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

package org.teragrid.ncsa.gridshib.security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.security.SAMLPrincipal;

import org.globus.opensaml11.saml.nameid.TeraGridPrincipalNameIdentifier;

/**
 * A TeraGrid principal is a type of SAML principal.
 *
 * @see org.globus.gridshib.security.SAMLPrincipal
 *
 * @since 0.5.4
 */
public class TeraGridPrincipal extends SAMLPrincipal {

    static Log logger =
        LogFactory.getLog(TeraGridPrincipal.class.getName());

    /**
     * The formal name of the
     * <a href="http://www.teragridforum.org/mediawiki/index.php?title=SAML_NameIDs_for_TeraGrid"><code>TeraGridPrincipalName</code></a>
     * identifier, used as the value of XML attribute
     * <code>NameIdentifier/@Format</code>
     * in a SAML token issued by a science gateway.
     */
    final private static String TGPN =
        TeraGridPrincipalNameIdentifier.FORMAT_TGPN;

    TeraGridPrincipal(String id, String issuer, String name) {

        super(id, issuer, name, TGPN);
    }

    public boolean equals(Object o) {

        if (this == o) return true;
        if (!(o instanceof TeraGridPrincipal)) return false;

        TeraGridPrincipal principal = (TeraGridPrincipal)o;

        assert (this.getIssuer() != null);
        if (!this.getIssuer().equals(principal.getIssuer())) return false;

        assert (this.getName() != null);
        if (!this.getName().equals(principal.getName())) return false;

        return true;
    }

    public int hashCode() {
        return this.getIssuer().hashCode() & this.getName().hashCode();
    }

    public String toString() {

        StringBuffer buf = new StringBuffer("TeraGridPrincipal ");
        buf.append("{\n  id='").append(this.getId());
        buf.append("'\n  issuer='").append(this.getIssuer());
        buf.append("'\n  name='").append(this.getName());
        buf.append("'\n}");

        return buf.toString();
    }
}
