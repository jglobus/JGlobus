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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.opensaml11.saml.SAMLNameIdentifier;

/**
 * An abstraction for a SAML identity.
 * <p>
 * This class maintains the following invariant:
 * <em>There is a one-to-one correspondence between SAML
 * principals and trusted, unqualified SAML identities</em>.
 * (An <em>unqualified SAML identity</em> is one whose
 * corresponding SAML name identifier has a null
 * <code>NameQualifier</code> attribute.) A getter method
 * to obtain the SAML principal associated with this
 * <code>SAMLIdentity</code> instance is provided, but a
 * setter method is not provided since the invariant is
 * maintained internally.
 * <p>
 * This class implements the <code>SecurityAttributes</code>
 * interface by virtue of the superclass
 * <code>DecoratedSecurityItem</code>.  The name and value
 * of the security attribute are the format and name of
 * this <code>SAMLIdentity</code> instance, respectively.
 * Note that the security attribute associated with this
 * <code>SAMLIdentity</code> instance is single-valued.
 *
 * @see org.globus.gridshib.security.DecoratedSecurityItem
 * @see org.globus.gridshib.security.SecurityAttributes
 */
public class SAMLIdentity extends DecoratedSecurityItem {

    static Log logger =
        LogFactory.getLog(SAMLIdentity.class.getName());

    private SAMLNameIdentifier nameID;
    private String name;
    private String nameQualifier;
    private String format;

    /**
     * @exception java.lang.IllegalArgumentException
     *            if any input parameter is null
     *
     * @since 0.5.4
     */
    public SAMLIdentity(String id,
                        String issuer,
                        String name,
                        String nameQualifier,
                        String format) {

        super(id, issuer);

        if (name == null) {
            throw new IllegalArgumentException("Null name argument");
        }

        if (format == null) {
            throw new IllegalArgumentException("Null format argument");
        }

        this.name = name;
        this.nameQualifier = nameQualifier;
        this.format = format;

        this.setTrusted(false);
    }

    /**
     * @since 0.3.0
     *
     * @deprecated As of version&nbsp;0.5.4, use
     *             {@link #SAMLIdentity(String, String, String, String, String)}
     *             instead.
     */
    public SAMLIdentity(String id,
                        String issuer,
                        SAMLNameIdentifier nameID) {

        this(id, issuer, nameID.getName(),
                         nameID.getNameQualifier(),
                         nameID.getFormat());

        this.nameID = nameID;
    }

    /**
     * @since 0.5.4
     */
    public String getName() {
        return this.name;
    }

    /**
     * @since 0.5.4
     */
    public String getNameQualifier() {
        return this.nameQualifier;
    }

    /**
     * @since 0.5.4
     */
    public String getFormat() {
        return this.format;
    }

    /**
     * This method performs two operations:
     * <ol>
     *   <li>calls the corresponding method of the superclass</li>
     *   <li>adds a security attribute</li>
     * </ol>
     * A security attribute is added only if this
     * <code>SAMLIdentity</code> instance changes state
     * from an untrusted to a trusted security item.
     *
     * @param trusted indicates whether or not
     *        this <code>SAMLIdentity</code> is trusted
     *
     * @exception java.lang.IllegalArgumentException
     *            if the <code>trusted</code> field is true
     *            and the value of the <code>trusted</code>
     *            argument is false.
     *
     * @since 0.4.3
     */
    public void setTrusted(boolean trusted) {

        super.setTrusted(trusted);

        if (this.isTrusted() && trusted) {

            // a one-time operation:
            if (this.addAttributeValue(this.format, this.name)) {
                logger.debug("Security attribute added: (" +
                             this.format + ", " + this.name + ")");
            } else {
                logger.warn("Security attribute NOT added: (" +
                            this.format + ", " + this.name + ")");
            }
        }
    }

    /**
     * @deprecated As of version&nbsp;0.5.4, use {@link #getName()},
     *             {@link #getNameQualifier()}, and {@link #getFormat()}
     *             instead.
     */
    public SAMLNameIdentifier getNameID() {
        return this.nameID;
    }

    /**
     * @deprecated As of version&nbsp;0.5.4, use
     *             {@link #SAMLIdentity(String, String, String, String, String)}
     *             instead.
     */
    public void setNameID(SAMLNameIdentifier nameID) {

        if (nameID == null) {
            String msg = "Identity nameID is null";
            throw new IllegalArgumentException(msg);
        }

        if (this.isTrusted()) {
            String msg = "This identity is trusted and " +
                         "therefore its nameID is immutable: " +
                         this.nameID.toString();
            logger.warn(msg);
            return;
        }

        try {
            this.nameID = (SAMLNameIdentifier)nameID.clone();
        } catch (CloneNotSupportedException e) {
            this.nameID = nameID;
        }
        logger.debug("nameID = " + this.nameID);

        this.name = this.nameID.getName();
        this.nameQualifier = this.nameID.getNameQualifier();
        this.format = this.nameID.getFormat();
    }

    /**
     * A convenience method that gets the SAML principal
     * associated with this <code>SAMLIdentity</code> instance.
     * This method is a very thin wrapper around the
     * {@link org.globus.gridshib.security.SAMLSecurityContext#getSAMLPrincipal(SAMLIdentity)}
     * method.
     *
     * @return the (possibly null) SAML principal associated
     *         with this <code>SAMLIdentity</code> instance
     *
     * @since 0.4.3
     */
    public SAMLPrincipal getSAMLPrincipal() {

        logger.debug("Computing SAML principal for identity " +
                     this.format);

        return SAMLSecurityContext.getSAMLPrincipal(this);
    }

    public boolean equals(Object o) {

        if (this == o) return true;
        if (!(o instanceof SAMLIdentity)) return false;

        SAMLIdentity id = (SAMLIdentity)o;

        if (!this.getIssuer().equals(id.getIssuer())) return false;
        if (!this.name.equals(id.getName())) return false;
        String qualifier = this.nameQualifier;
        if (qualifier == null) {
            if (id.getNameQualifier() != null) return false;
        } else {
            if (!qualifier.equals(id.getNameQualifier())) return false;
        }
        if (!this.format.equals(id.getFormat())) return false;

        return true;
    }

    public int hashCode() {
        return this.getIssuer().hashCode() &
               this.name.hashCode() &
               this.nameQualifier.hashCode() &
               this.format.hashCode();
    }

    public String toString() {

        StringBuffer buf = new StringBuffer(
            ((isTrusted()) ? "" : "(untrusted) ") + "SAMLIdentity ");
        buf.append("{\n  id='").append(this.getId());
        buf.append("'\n  issuer='").append(this.getIssuer());
        buf.append("'\n  name='").append(this.name);
        buf.append("'\n  nameQualifier='").append(this.nameQualifier);
        buf.append("'\n  format='").append(this.format);
        buf.append("'\n}");

        return buf.toString();
    }
}
