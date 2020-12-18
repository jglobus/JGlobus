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

/**
 * The base class for all security context components.
 */
public abstract class BaseSecurityItem implements IssuedSecurityItem {

    static Log logger =
        LogFactory.getLog(BaseSecurityItem.class.getName());

    /**
     * The unique identifier of the issuer of
     * this <code>BaseSecurityItem</code>
     */
    private String issuer;

    /**
     * The unique identifier of this <code>BaseSecurityItem</code>
     *
     * @since 0.3.0
     */
    private String id;

    /**
     * Indicates whether or not this <code>BaseSecurityItem</code>
     * is trusted.
     *
     * @since 0.3.0
     */
    private boolean trusted;

    /**
     * @exception java.lang.IllegalArgumentException
     *            if either <code>id</code> or <code>issuer</code>
     *            are null
     *
     * @since 0.5.4
     */
    public BaseSecurityItem(String id, String issuer) {

        if (id == null) {
            throw new IllegalArgumentException("Null id argument");
        }

        if (issuer == null) {
            throw new IllegalArgumentException("Null issuer argument");
        }

        this.id = id;
        this.issuer = issuer;
    }

    /**
     * Get the issuer of this <code>BaseSecurityItem</code>
     *
     * @return the unique identifier of the issuer of
     *         this <code>BaseSecurityItem</code>
     */
    public String getIssuer() {
        return this.issuer;
    }

    /**
     * Get the unique identifier of this <code>BaseSecurityItem</code>
     *
     * @return the unique identifier of this <code>BaseSecurityItem</code>
     *
     * @since 0.3.0
     */
    public String getId() {
        return this.id;
    }

    /**
     * Determines whether or not this <code>BaseSecurityItem</code>
     * is trusted.
     *
     * @return true if and only if this <code>BaseSecurityItem</code>
     *         is trusted
     *
     * @since 0.3.0
     */
    public boolean isTrusted() {
        return this.trusted;
    }

    /**
     * Set the issuer of this <code>BaseSecurityItem</code>
     *
     * @param issuer the unique identifier of the issuer
     *
     * @exception java.lang.IllegalArgumentException
     *            if the argument (<code>issuer</code>) is null
     *
     * @deprecated As of version&nbsp;0.5.4, use
     *             {@link #BaseSecurityItem(String, String)} instead.
     *             This setter method will be removed in a future
     *             version of GridShib SAML Tools.
     */
    public void setIssuer(String issuer) {

        if (issuer == null) {
            String msg = "Issuer is null";
            throw new IllegalArgumentException(msg);
        }

        if (this.trusted) {
            String msg = "This BaseSecurityItem is trusted and " +
                         "therefore its issuer is immutable: " +
                         this.issuer;
            logger.warn(msg);
            return;
        }

        this.issuer = issuer;
        logger.debug("issuer = " + issuer);
    }

    /**
     * Set the unique identifier of this <code>BaseSecurityItem</code>.
     *
     * @param id the unique identifier of this <code>BaseSecurityItem</code>
     *
     * @exception java.lang.IllegalArgumentException
     *            if the argument (<code>id</code>) is null
     *
     * @since 0.3.0
     *
     * @deprecated As of version&nbsp;0.5.4, use
     *             {@link #BaseSecurityItem(String, String)} instead.
     *             This setter method will be removed in a future
     *             version of GridShib SAML Tools.
     */
    public void setId(String id) {

        if (id == null) {
            String msg = "ID is null";
            throw new IllegalArgumentException(msg);
        }

        if (this.trusted) {
            String msg = "This BaseSecurityItem is trusted and " +
                         "therefore its identifier is immutable: " +
                         this.id;
            logger.warn(msg);
            return;
        }

        this.id = id;
        logger.debug("id = " + id);
    }

    /**
     * Set the <code>trusted</code> field of this
     * <code>BaseSecurityItem</code>. If the
     * <code>trusted</code> field already has
     * the value of the <code>trusted</code> argument,
     * a warning message is logged and no action is
     * taken.  If this <code>BaseSecurityItem</code>
     * is already trusted and the <code>trusted</code>
     * argument is false, an error message is logged
     * and an exception is thrown.
     *
     * @param trusted indicates whether or not
     *        this <code>BaseSecurityItem</code> is trusted
     *
     * @exception java.lang.IllegalArgumentException
     *            if the <code>trusted</code> field is true
     *            and the value of the <code>trusted</code>
     *            argument is false.
     *
     * @since 0.3.0
     */
    public void setTrusted(boolean trusted) {

        if (this.trusted == trusted) {
            String msg = "This BaseSecurityItem is already " +
                         (trusted ? "" : "un") + "trusted";
            logger.warn(msg);
            return;
        }

        if (this.trusted && !trusted) {
            String msg = "This BaseSecurityItem is already trusted " +
                         "and can not be reverted to untrusted";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }

        this.trusted = trusted;
        logger.debug("This BaseSecurityItem is " +
                     ((trusted) ? "" : "not ") + "trusted");
    }
}
