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

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import javax.security.auth.Subject;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.security.SecurityContextLogger;

/**
 * This class is used to log the complete security context.
 * The format of the output is optimized for automated
 * processing, not human readability.
 *
 * @since 0.5.4
 */
public class SAMLSecurityContextLogger implements SecurityContextLogger {

    static Log logger =
        LogFactory.getLog(SAMLSecurityContextLogger.class.getName());

    /**
     * Logs the security context associated with the
     * given subject at the INFO level.  The following
     * security items are logged:
     * <ul>
     *   <li>SAMLToken</li>
     *   <li>SecurityPrincipal</li>
     *   <li>SAMLIdentity</li>
     *   <li>SAMLAuthnContext</li>
     *   <li>SAMLAttribute</li>
     * </ul>
     * The general syntax of a line of log output is
     *
     * <pre>  &lt;prefix&gt; (&lt;name&gt;=&lt;value&gt;)+</pre>
     *
     * where
     *
     * <pre>  &lt;prefix&gt;        ::= SAMLToken|SecurityPrincipal|SAMLIdentity|SAMLAuthnContext|SAMLAttribute
     *  &lt;name&gt;          ::= [^ \t=]+
     *  &lt;value&gt;         ::= &lt;quoted_form&gt;|&lt;unquoted_form&gt;
     *  &lt;unquoted_form&gt; ::= [^ \t]+
     *  &lt;quoted_form&gt;   ::= "([^"\\]*(?:\\.[^"\\]*)*)"</pre>
     *
     * To produce a quoted form, the {@link #quote(String)}
     * method is used.
     *
     * @param callerID a string identifier for the caller of this method
     * @param subject  the authenticated subject
     *
     * @see org.globus.gridshib.security.SAMLToken
     * @see org.globus.gridshib.security.SecurityPrincipal
     * @see org.globus.gridshib.security.SAMLIdentity
     * @see org.globus.gridshib.security.SAMLAuthnContext
     * @see org.globus.gridshib.security.BasicAttribute
     */
    public void log(String callerID, Subject subject) {

        SAMLSecurityContext secCtx =
           SAMLSecurityContext.getSAMLSecurityContext(subject);

        SimpleDateFormat formatter =
            new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));

        /* A SAMLToken is assumed to be a SAML V1.1 subject assertion.
         * Once support for SAML V2.0 is added, SAMLTokens must
         * be distinguishable as V1.1 or V2.0 assertions. [By URI?]
         */
        SAMLToken[] tokens = secCtx.getSAMLTokens();
        assert (tokens != null);
        for (int i = 0; i < tokens.length; i++) {
            String msg = "CallerID=" + quote(callerID) +
                         " SAMLToken" +
                         " ID=" + tokens[i].getId() +
                         " Issuer=" + quote(tokens[i].getIssuer());
            logger.info(msg);
        }

        /*
         * Note: There is one security principal for each
         * <strong>trusted</strong> SAML identity and
         * one or more security principals for each
         * <strong>trusted</strong> identity attribute.
         */
        SecurityPrincipal[] principals = secCtx.getSecurityPrincipals();
        assert (principals != null);
        for (int i = 0; i < principals.length; i++) {
            String msg = "CallerID=" + quote(callerID) +
                         " SecurityPrincipal" +
                         " ID=" + principals[i].getId() +
                         " Trusted=" +
                           (principals[i].isTrusted() ? "true" : "false") +
                         " Name=" +
                           quote(principals[i].getName()) +
                         " Type=" +
                           principals[i].getType();
            logger.info(msg);
        }

        /* Note: Two SAML identities are equal if and only if all
         * three properties (Name, NameQualifier, and Format) are
         * equal (by string comparison).
         */
        SAMLIdentity[] identities = secCtx.getSAMLIdentities();
        assert (identities != null);
        for (int i = 0; i < identities.length; i++) {
            String qualifier = identities[i].getNameQualifier();
            String msg = "CallerID=" + quote(callerID) +
                         " SAMLIdentity" +
                         " ID=" + identities[i].getId() +
                         " Trusted=" +
                           (identities[i].isTrusted() ? "true" : "false") +
                         " Name=" +
                           quote(identities[i].getName()) +
                         " NameQualifier=" +
                           (qualifier == null ? "" : quote(qualifier)) +
                         " Format=" +
                           identities[i].getFormat();
            logger.info(msg);
        }

        /* The AuthenticationMethod attribute is strictly a SAML V1.1
         * construct.  In SAML V2.0, the AuthenticationMethod attribute
         * is replaced by the AuthnContext element.
         */
        SAMLAuthnContext[] authnContexts = secCtx.getSAMLAuthnContexts();
        assert (authnContexts != null);
        for (int i = 0; i < authnContexts.length; i++) {
            assert (authnContexts[i].getAuthnMethod() != null);
            assert (authnContexts[i].getAuthnInstant() != null);
            Date date = authnContexts[i].getAuthnInstant();
            String ipAddress = authnContexts[i].getIPAddress();
            String dnsName = authnContexts[i].getDNSName();
            String msg = "CallerID=" + quote(callerID) +
                         " SAMLAuthnContext" +
                         " ID=" + authnContexts[i].getId() +
                         " Trusted=" +
                           (authnContexts[i].isTrusted() ? "true" : "false") +
                         " AuthnMethod=" +
                           authnContexts[i].getAuthnMethod().toString() +
                         " AuthnInstant=" +
                           formatter.format(date) +
                         " Address=" +
                           (ipAddress == null ? "" : ipAddress) +
                         " DNSName=" +
                           (dnsName == null ? "" : dnsName);
            logger.info(msg);
        }

        BasicAttribute[] attributes = secCtx.getAttributes();
        assert (attributes != null);
        for (int i = 0; i < attributes.length; i++) {
            String msg = "CallerID=" + quote(callerID) +
                         " SAMLAttribute" +
                         " ID=" + attributes[i].getId() +
                         " Trusted=" +
                           (attributes[i].isTrusted() ? "true" : "false") +
                         " Name=" +
                           quote(attributes[i].getName()) +
                         " NameFormat=" +
                           attributes[i].getNameFormat();
            String[] values = attributes[i].getValues();
            for (int j = 0; j < values.length; j++) {
                msg += " Value=" + quote(values[j]);
            }
            logger.info(msg);
        }
    }

    /**
     * Produces a <em>quoted form</em> by escaping all
     * backslashes and quotes (in that order) in the
     * given input string.
     *
     * @param value a string value to be quoted
     * @return the quoted string
     *
     * @since 0.4.3
     */
    public static String quote(String value) {

        assert (value != null);

        String s = value.replaceAll("\\\\", "\\\\");
        s = s.replaceAll("\"", "\\\"");
        return "\"" + s + "\"";
    }
}

