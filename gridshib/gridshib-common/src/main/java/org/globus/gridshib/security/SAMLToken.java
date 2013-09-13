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

package org.globus.gridshib.security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.opensaml11.saml.SAMLSubjectAssertion;

/**
 * A SAML token is a type of security token.  Other types
 * of tokens include X.509 tokens and VOMS tokens.
 *
 * @since 0.5.4
 */
public class SAMLToken extends BaseSecurityItem {

    static Log logger =
        LogFactory.getLog(SAMLToken.class.getName());

    private Object token;

    public SAMLToken(SAMLSubjectAssertion assertion) {

        super(assertion.getId(), assertion.getIssuer());

        this.token = assertion;
        setTrusted(false);
    }

    public boolean equals(Object o) {

        if (this == o) return true;
        if (!(o instanceof SAMLToken)) return false;

        SAMLToken token = (SAMLToken)o;

        if (!this.getId().equals(token.getId())) return false;

        return true;
    }

    public int hashCode() {
        return this.getId().hashCode();
    }

    public String toString() {

        return this.toString(false);
    }

    public String toString(boolean verbose) {

        StringBuffer buf = new StringBuffer(
            ((isTrusted()) ? "" : "(untrusted) ") + "SAMLToken ");
        buf.append("{\n  id='").append(this.getId());
        buf.append("'\n  issuer='").append(this.getIssuer());
        if (verbose) {
            buf.append("'\n  token='").append(this.token.toString());
        }
        buf.append("'\n}");

        return buf.toString();
    }
}
