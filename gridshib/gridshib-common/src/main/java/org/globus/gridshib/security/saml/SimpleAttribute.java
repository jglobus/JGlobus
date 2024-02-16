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

package org.globus.gridshib.security.saml;

import java.util.Arrays;

import javax.xml.namespace.QName;

import org.globus.opensaml11.md.common.Constants;
import org.globus.opensaml11.saml.SAMLAttribute;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.XML;

/**
 * A constrained subclass of <code>SAMLAttribute</code>.
 * An instance of this subclass necessarily has type
 * <code>xsd:string</code> with unspecified
 * (infinite) lifetime.
 */
public class SimpleAttribute extends SAMLAttribute {

    private static final QName QNAME = new QName(XML.XSD_NS, "string");
    private static final String NAMESPACE =
        Constants.SHIB_ATTRIBUTE_NAMESPACE_URI;

    /**
     * @since 0.3.3
     */
    public SimpleAttribute(String name, String value)
                    throws SAMLException {

        this(name, new String[]{value});
    }

    /**
     * @since 0.3.0
     */
    public SimpleAttribute(String name, String[] values)
                    throws SAMLException {

        super(name, NAMESPACE, QNAME, 0, Arrays.asList(values));
    }

    public SimpleAttribute(
        String namespace, String name, String[] values) throws SAMLException {

        super(name, namespace, QNAME, 0, Arrays.asList(values));
    }
}
