/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.globus.opensaml11.md.common.provider;

import java.io.Serializable;

import org.apache.log4j.Logger;
import javax.xml.namespace.QName;
import org.globus.opensaml11.saml.SAMLException;
import org.w3c.dom.Element;

import org.globus.opensaml11.md.common.LocalPrincipal;
import org.globus.opensaml11.md.common.NameIdentifierMappingException;

/**
 * Base class for
 * {@link org.globus.opensaml11.md.common.NameIdentifierMapping}
 * implementations that support Shibboleth Attribute Query Handles.
 *
 * @author Walter Hoehn
 */
public abstract class AQHNameIdentifierMapping extends BaseNameIdentifierMapping {

    private static Logger log = Logger.getLogger(AQHNameIdentifierMapping.class.getName());
    /** Time in seconds for which handles are valid */
    protected long handleTTL = 1800;
    protected static QName[] errorCodes = {SAMLException.REQUESTER,
            new QName(org.globus.opensaml11.md.common.XML.SHIB_NS, "InvalidHandle")};

    public AQHNameIdentifierMapping(Element config) throws NameIdentifierMappingException {

        super(config);

        String rawTTL = ((Element) config).getAttribute("handleTTL");
        try {
            if (rawTTL != null && !rawTTL.equals("")) {
                handleTTL = Long.parseLong(rawTTL);
                if (handleTTL < 30) {
                    log.warn("You have set the Attribute Query Handle \"Time To Live\' to a very low "
                            + "value.  It is recommended that you increase it.");
                }
            }
            log.debug("Attribute Query Handle TTL set to (" + handleTTL + ") seconds.");

        } catch (NumberFormatException nfe) {
            log.error("Value for attribute \"handleTTL\" mus be a long integer.");
            throw new NameIdentifierMappingException("Could not load Name Identifier Mapping with configured data.");
        }
    }

    protected HandleEntry createHandleEntry(LocalPrincipal principal) {

        return new HandleEntry(principal, handleTTL);
    }
}

class HandleEntry implements Serializable {

    static final long serialVersionUID = 1L;
    protected LocalPrincipal principal;
    protected long expirationTime;

    /**
     * Creates a HandleEntry
     *
     * @param principal
     *            the principal represented by this entry.
     * @param TTL
     *            the time, in seconds, for which the handle should be valid.
     */
    protected HandleEntry(LocalPrincipal principal, long TTL) {

        this.principal = principal;
        expirationTime = System.currentTimeMillis() + (TTL * 1000);
    }

    protected boolean isExpired() {

        return (System.currentTimeMillis() >= expirationTime);
    }

    public long getExpirationTime() {

        return expirationTime;
    }

    public void setExpirationTime(long expr) {

        expirationTime = expr;
    }
}