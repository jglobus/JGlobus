/*
 * Copyright 2006-2009 University of Illinois
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

package org.globus.gridshib.config;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.opensaml11.saml.SAMLAttribute;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLNameIdentifier;

/**
 * Configuration properties for the SAML Assertion Issuer Tool.
 *
 * @since 0.4.0
 */
public class SAMLToolsConfig extends BasicConfig {

    private static Log logger =
        LogFactory.getLog(SAMLToolsConfig.class.getName());

    /**
     * @since 0.4.3
     */
    static final String DEFAULT_FORMAT =
        SAMLNameIdentifier.FORMAT_UNSPECIFIED;

    /**
     * @since 0.4.3
     */
    static final String DEFAULT_TEMPLATE =
        "%PRINCIPAL%";

    /**
     * @since 0.4.3
     */
    static final String DEFAULT_PATTERN =
        "yyyy-MM-dd'T'HH:mm:ssZ";

    private static Set attributes;

    public SAMLToolsConfig() {
        super();
        this.attributes = new HashSet();
        this.setFormat(DEFAULT_FORMAT);
        this.setTemplate(DEFAULT_TEMPLATE);
        this.setDateTimePattern(DEFAULT_PATTERN);
    }

    /**
     * @since 0.5.0
     */
    public Set getAttributeSet() {
        return attributes;
    }

    public SAMLAttribute[] getAttributes() {
        SAMLAttribute[] attribs =
            new SAMLAttribute[this.attributes.size()];
        this.attributes.toArray(attribs);
        return attribs;
    }

    public boolean addAttribute(SAMLAttribute attribute)
                         throws SAMLException {

        if (attribute == null) { return false; }

        Iterator attributes = this.attributes.iterator();
        while (attributes.hasNext()) {
            SAMLAttribute oldAttribute = (SAMLAttribute)attributes.next();
            if (attribute.equals(oldAttribute)) {
                // merge attribute values
                Iterator values = oldAttribute.getValues();
                while (values.hasNext()) {
                    attribute.addValue(values.next());
                }
                if (!this.attributes.remove(oldAttribute)) {
                    String msg =
                        "Failed to maintain integrity of attribute set";
                    throw new RuntimeException(msg);
                }
                break;
            }
        }

        return this.attributes.add(attribute);
    }
}
