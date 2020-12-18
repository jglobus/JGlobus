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

package org.teragrid.ncsa.gridshib.security.x509;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.security.saml.GlobusSAMLException;
import org.globus.gridshib.security.saml.SimpleAttribute;
import org.globus.gridshib.security.x509.GlobusSAMLCredential;

import org.globus.opensaml11.saml.SAMLException;

/**
 * A <code>GatewayCredential</code> is a proxy credential
 * with a SAML assertion bound to a non-critical certificate
 * extension.  A <code>GatewayCredential</code> is a special
 * type of <code>GlobusSAMLCredential</code> having a mail
 * attribute and other distinguishing characteristics.
 *
 * @see org.globus.gridshib.security.x509.GlobusSAMLCredential
 *
 * @since 0.3.0
 */
public class GatewayCredential extends GlobusSAMLCredential {

    protected static Log logger =
        LogFactory.getLog(GatewayCredential.class.getName());

    /**
     * The <code>MAIL</code> constant is the formal name of
     * the attribute that holds the user's e-mail address.
     * This attribute name is based on an OID defined by the
     * <a href="http://www.educause.edu/eduperson/">eduPerson</a>
     * specification and the
     * <a href="http://middleware.internet2.edu/dir/docs/draft-internet2-mace-dir-saml-attributes-latest.pdf">MACE-Dir
     * Attribute Profile for SAML&nbsp;1.x</a>.
     * <p>
     * The legacy name of this attribute is
     * <pre>urn:mace:dir:attribute-def:mail</pre>
     * Hence, this attribute has the following
     * "friendly name":
     * <pre>FriendlyName="mail"</pre>.
     */
    final public static String MAIL =
        "urn:oid:0.9.2342.19200300.100.1.3";

    final private static String ISMEMBEROF =
        "urn:oid:1.3.6.1.4.1.5923.1.5.1.1";

    /**
     * Creates a gateway credential instance.
     *
     * @param username the name of the authenticated user,
     *        usually the portal login name
     *
     * @exception org.globus.gridshib.security.saml.GlobusSAMLException
     *            if unable to create the credential
     */
    public GatewayCredential(String username) throws GlobusSAMLException {

        super(username, GlobusSAMLCredential.SENDER_VOUCHES);
    }

    /**
     * Formulates the given e-mail address as a single-valued
     * SAML attribute and adds this attribute to this
     * <code>GatewayCredential</code> instance.
     *
     * @param emailAddress a (non-null) e-mail address
     * @return true if and only if the SAML attribute
     *         is actually added
     * @exception java.lang.IllegalArgumentException
     *            if the given e-mail address is null
     */
    public boolean addEmailAddress(String emailAddress) {

        if (emailAddress == null) {
            String msg = "Null argument (emailAddress)";
            throw new IllegalArgumentException(msg);
        }
        logger.debug("emailAddress: " + emailAddress);

        SimpleAttribute attribute = null;
        try {
            attribute = new SimpleAttribute(MAIL, emailAddress);
        } catch (SAMLException e) {
            String msg = "Unable to create attribute: " + MAIL;
            logger.error(msg, e);
            return false;
        }

        return this.addAttribute(attribute);
    }

    /**
     * Formulates the given e-mail addresses as a multi-valued
     * SAML attribute and adds this attribute to this
     * <code>GatewayCredential</code> instance.  If only one
     * e-mail address is provided, this method calls
     * {@link #addEmailAddress(String)} instead.
     *
     * @param emailAddresses a (non-null and nonempty) array
     *        of e-mail addresses
     * @return true if and only if the SAML attribute
     *         is actually added
     * @exception java.lang.IllegalArgumentException
     *            if the given array of e-mail addresses
     *            is null or empty
     *
     * @since 0.4.1
     */
    public boolean addEmailAddresses(String[] emailAddresses) {

        if (emailAddresses == null) {
            String msg = "Null argument (emailAddresses)";
            throw new IllegalArgumentException(msg);
        }
        int n = emailAddresses.length;
        if (n == 0) {
            String msg = "Empty array argument (emailAddresses)";
            throw new IllegalArgumentException(msg);
        }

        if (logger.isDebugEnabled()) {
            StringBuffer buf = new StringBuffer("[");
            buf.append(emailAddresses[0]);
            for (int i = 1; i < n; i++) {
                buf.append(", ");
                buf.append(emailAddresses[i]);
            }
            buf.append("]");
            logger.debug("Found " + n + " e-mail address" +
                         ((n == 1) ? ": " : "es: ") + buf.toString());
        }

        if (n == 1) {
            return this.addEmailAddress(emailAddresses[0]);
        }

        SimpleAttribute attribute = null;
        try {
            attribute = new SimpleAttribute(MAIL, emailAddresses);
        } catch (SAMLException e) {
            String msg = "Unable to create attribute: " + MAIL;
            logger.error(msg, e);
            return false;
        }

        return this.addAttribute(attribute);
    }
}
