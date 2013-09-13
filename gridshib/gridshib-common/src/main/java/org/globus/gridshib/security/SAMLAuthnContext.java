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

import java.net.URI;
import java.net.URISyntaxException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * An abstraction for <em>authentication context</em>, that is,
 * the details surrounding a previous act of authentication.
 */
public class SAMLAuthnContext extends BaseSecurityItem {

    static Log logger =
        LogFactory.getLog(SAMLAuthnContext.class.getName());

    private URI authnMethod;
    private Date authnInstant;
    private String ipAddress;
    private String dnsName;

    /**
     * @exception java.lang.IllegalArgumentException
     *            if any input parameter is null
     *
     * @since 0.3.0
     */
    public SAMLAuthnContext(String id, String issuer,
                            URI authnMethod, Date authnInstant) {

        this(id, issuer, authnMethod, authnInstant, null, null);
    }

    /**
     * @exception java.lang.IllegalArgumentException
     *            if any input parameter (except
     *            <code>ipAddress</code> or <code>dnsName</code>)
     *            is null
     *
     * @since 0.3.0
     */
    public SAMLAuthnContext(String id, String issuer,
                            URI authnMethod, Date authnInstant,
                            String ipAddress, String dnsName) {

        super(id, issuer);

        setAuthnMethod(authnMethod);
        setAuthnInstant(authnInstant);
        setIPAddress(ipAddress);
        setDNSName(dnsName);
        setTrusted(false);
    }

    public URI getAuthnMethod() {
        return this.authnMethod;
    }

    public Date getAuthnInstant() {
        return this.authnInstant;
    }

    /**
     * @since 0.4.3
     */
    public String getFormattedAuthnInstant() {
        SimpleDateFormat formatter =
                new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));

        return formatter.format(this.authnInstant);
    }

    public String getIPAddress() {
        return this.ipAddress;
    }

    public String getDNSName() {
        return this.dnsName;
    }

    /**
     * @deprecated As of version&nbsp;0.5.4, do not use this setter
     *             method.  It will be removed in a future version
     *             of GridShib SAML Tools.
     */
    public void setAuthnMethod(String authnMethodStr) {

        if (authnMethodStr == null) {
            String msg = "Authn method string is null";
            throw new IllegalArgumentException(msg);
        }

        setAuthnMethod(toURI(authnMethodStr));
    }

    /**
     * @deprecated As of version&nbsp;0.5.4, do not use this setter
     *             method.  It will be removed in a future version
     *             of GridShib SAML Tools.
     */
    public void setAuthnMethod(URI authnMethod) {

        if (authnMethod == null) {
            String msg = "Authn method is null";
            throw new IllegalArgumentException(msg);
        }

        if (this.isTrusted()) {
            String msg = "This SAMLAuthnContext is trusted and " +
                         "therefore its authnMethod is immutable: " +
                         this.authnMethod.toString();
            logger.warn(msg);
            return;
        }

        this.authnMethod = authnMethod;
        logger.debug("authnMethod = " + authnMethod.toString());
    }

    /**
     * @deprecated As of version&nbsp;0.5.4, do not use this setter
     *             method.  It will be removed in a future version
     *             of GridShib SAML Tools.
     */
    public void setAuthnInstant(Date authnInstant) {

        if (authnInstant == null) {
            String msg = "Authn instant is null";
            throw new IllegalArgumentException(msg);
        }

        if (this.isTrusted()) {
            String msg = "This SAMLAuthnContext is trusted and " +
                         "therefore its authnInstant is immutable: " +
                         this.getFormattedAuthnInstant();
            logger.warn(msg);
            return;
        }

        this.authnInstant = authnInstant;
        logger.debug("authnInstant = " + authnInstant.toString());
    }

    /**
     * @deprecated As of version&nbsp;0.5.4, do not use this setter
     *             method.  It will be removed in a future version
     *             of GridShib SAML Tools.
     */
    public void setIPAddress(String ipAddress) {

        if (this.isTrusted()) {
            String msg = "This SAMLAuthnContext is trusted and " +
                         "therefore its ipAddress is immutable: " +
                         this.ipAddress;
            logger.warn(msg);
            return;
        }

        this.ipAddress = ipAddress;
        logger.debug("ipAddress = " + ipAddress);
    }

    /**
     * @deprecated As of version&nbsp;0.5.4, do not use this setter
     *             method.  It will be removed in a future version
     *             of GridShib SAML Tools.
     */
    public void setDNSName(String dnsName) {

        if (this.isTrusted()) {
            String msg = "This SAMLAuthnContext is trusted and " +
                         "therefore its dnsName is immutable: " +
                         this.dnsName;
            logger.warn(msg);
            return;
        }

        this.dnsName = dnsName;
        logger.debug("dnsName = " + dnsName);
    }

    public boolean equals(Object o) {

        if (this == o) return true;
        if (!(o instanceof SAMLAuthnContext)) return false;

        SAMLAuthnContext ac = (SAMLAuthnContext)o;

        if (!this.getIssuer().equals(ac.getIssuer())) return false;
        if (!this.authnMethod.equals(ac.getAuthnMethod())) return false;
        if (!this.authnInstant.equals(ac.getAuthnInstant())) return false;

        return true;
    }

    public int hashCode() {
        return this.getIssuer().hashCode() &
               this.authnMethod.hashCode() &
               this.authnInstant.hashCode();
    }

    public String toString() {

        StringBuffer buf = new StringBuffer(
            ((isTrusted()) ? "" : "(untrusted) ") + "SAMLAuthnContext ");
        buf.append("{\n  id='").append(this.getId());
        buf.append("'\n  issuer='").append(this.getIssuer());
        buf.append("'\n  authnMethod='").append(this.authnMethod.toString());
        String authnInstantStr = this.getFormattedAuthnInstant();
        buf.append("'\n  authnInstant='").append(authnInstantStr);
        buf.append("'\n  ipAddress='").append(this.ipAddress);
        buf.append("'\n  dnsName='").append(this.dnsName);
        buf.append("'\n}");

        return buf.toString();
    }

    private static URI toURI(String authnMethodStr) {
        URI authnMethod = null;
        try {
            authnMethod = new URI(authnMethodStr);
        } catch (URISyntaxException e) {
            logger.warn("Unable to parse authnMethod string", e);
        }
        return authnMethod;
    }
}
