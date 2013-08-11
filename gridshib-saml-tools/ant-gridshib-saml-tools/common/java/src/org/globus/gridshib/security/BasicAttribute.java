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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.LoadException;
import org.globus.gridshib.common.StringSetFile;
import org.globus.gridshib.config.BootstrapConfigLoader;

/**
 * A SAML attribute abstraction of the simplest kind.
 * <p>
 * Some attributes are <em>identity attributes</em>,
 * that is, attributes whose values may be treated as
 * principal names.  This class maintains the following
 * invariant: <em>There is a one-to-one correspondence
 * between SAML principals and identity attribute values</em>.
 * A getter method to obtain the SAML principals associated
 * with this <code>BasicAttribute</code> instance is provided,
 * but a setter method is not provided since the invariant
 * is maintained internally.
 * <p>
 * This class implements the <code>SecurityAttributes</code>
 * interface by virtue of the superclass
 * <code>DecoratedSecurityItem</code>.  The name and values
 * of the security attribute are the name and values of
 * this <code>BasicAttribute</code> instance, respectively.
 * Note that the security attribute associated with this
 * <code>SAMLIdentity</code> instance is multi-valued.
 *
 * @see org.globus.gridshib.security.DecoratedSecurityItem
 * @see org.globus.gridshib.security.SecurityAttributes
 */
public class BasicAttribute extends DecoratedSecurityItem {

    static Log logger =
        LogFactory.getLog(BasicAttribute.class.getName());

    private static StringSetFile identityAttributes;

    static {
        identityAttributes = BootstrapConfigLoader.getIdentityAttributes();
    }

    private String name;
    private String nameFormat;
    private Set values;

    /**
     * Creates an instance of <code>BasicAttribute</code>.
     * By default, the instance is <strong>not</strong> trusted.
     *
     * @param id the unique identifier of this instance
     * @param issuer the unique identifier of the issuer of this instance
     * @param name the name of this <code>BasicAttribute</code>
     * @param nameFormat the name format of this <code>BasicAttribute</code>
     *
     * @exception java.lang.IllegalArgumentException
     *            if any input parameter is null
     *
     * @since 0.3.0
     */
    public BasicAttribute(String id, String issuer,
                          String name, String nameFormat) {

        super(id, issuer);

        if (name == null) {
            throw new IllegalArgumentException("Null name argument");
        }

        this.name = name;
        this.nameFormat = nameFormat;
        this.values = new HashSet();

        this.setTrusted(false);
    }

    /**
     * A convenience constructor that calls
     * {@link #BasicAttribute(String, String, String, String)}
     * and then sets the given value.
     *
     * @since 0.3.0
     */
    public BasicAttribute(String id, String issuer,
                          String name, String nameFormat,
                          String value) {

        this(id, issuer, name, nameFormat);
        addValue(value);
    }

    public String getName() {
        return this.name;
    }

    public String getNameFormat() {
        return this.nameFormat;
    }

    public String[] getValues() {
        return (String[])(this.values.toArray(new String[0]));
    }

    /**
     * @deprecated As of version&nbsp;0.5.4, do not use this setter
     *             method.  It will be removed in a future version
     *             of GridShib SAML Tools.
     */
    public void setName(String name) {

        if (name == null) {
            String msg = "Attribute name is null";
            throw new IllegalArgumentException(msg);
        }

        if (this.isTrusted()) {
            String msg = "This BasicAttribute is trusted and " +
                         "therefore its name is immutable: " +
                         this.name;
            logger.warn(msg);
            return;
        }

        this.name = name;
        logger.debug("name = " + name);
    }

    /**
     * @deprecated As of version&nbsp;0.5.4, do not use this setter
     *             method.  It will be removed in a future version
     *             of GridShib SAML Tools.
     */
    public void setNameFormat(String nameFormat) {

        if (this.isTrusted()) {
            String msg = "This BasicAttribute is trusted and " +
                         "therefore its nameFormat is immutable: " +
                         this.nameFormat;
            logger.warn(msg);
            return;
        }

        this.nameFormat = nameFormat;
        logger.debug("nameFormat = " + nameFormat);
    }

    /**
     * Add a value to this <code>BasicAttribute</code> instance.
     */
    public void addValue(String value) {

        if (this.isTrusted()) {
            String msg = "This BasicAttribute is trusted and " +
                         "therefore its values are immutable: " +
                         this.values.toString();
            logger.warn(msg);
            return;
        }

        this.values.add(value);
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
            for (Iterator it = this.values.iterator(); it.hasNext();) {
                String value = (String)it.next();
                if (this.addAttributeValue(this.name, value)) {
                    logger.debug("Security attribute added: (" +
                                 this.name + ", " + value + ")");
                } else {
                    logger.warn("Security attribute NOT added: (" +
                                this.name + ", " + value + ")");
                }
            }
        }
    }

    /**
     * @since 0.5.4
     */
    public boolean isIdentityAttribute() throws LoadException {

        if (identityAttributes == null) {
            logger.debug("No identity attributes are configured");
            return false;
        }

        return identityAttributes.contains(this.name);

    }

    /**
     * A convenience method that gets the SAML principals
     * associated with this <code>BasicAttribute</code> instance.
     * This method is a very thin wrapper around the
     * {@link org.globus.gridshib.security.SAMLSecurityContext#getSAMLPrincipals(BasicAttribute)}
     * method.
     *
     * @return a (possibly empty) list of <code>SAMLPrincipal</code>
     *         objects associated with this
     *         <code>BasicAttribute</code> instance
     *
     * @since 0.4.3
     */
    public List getSAMLPrincipals() {

        logger.debug("Computing SAML principals for attribute " +
                     this.name);

        return SAMLSecurityContext.getSAMLPrincipals(this);
    }

    public boolean equals(Object o) {

        if (this == o) return true;
        if (!(o instanceof BasicAttribute)) return false;

        BasicAttribute attribute = (BasicAttribute)o;

        if (!this.getIssuer().equals(attribute.getIssuer())) return false;
        if (!this.name.equals(attribute.getName())) return false;
        if (!this.nameFormat.equals(attribute.getNameFormat())) return false;

        return true;
    }

    public int hashCode() {
        return this.getIssuer().hashCode() & this.name.hashCode();
    }

    public String toString() {

        StringBuffer buf = new StringBuffer(
            ((isTrusted()) ? "" : "(untrusted) ") + "BasicAttribute ");
        buf.append("{\n  id='").append(this.getId());
        buf.append("'\n  issuer='").append(this.getIssuer());
        buf.append("'\n  name='").append(this.name);
        buf.append("'\n  nameFormat='").append(this.nameFormat);

        String[] values = this.getValues();
        for (int i = 0; i < values.length; i++) {
            buf.append("'\n  value #").
                append(i+1).
                append("='").
                append(values[i]);
        }

        buf.append("'\n}");

        return buf.toString();
    }
}
