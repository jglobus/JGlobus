/*
 * Copyright 2006-2009 University of Illinois
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.globus.opensaml11.saml.nameid;

import org.apache.log4j.Logger;

import org.globus.opensaml11.saml.MalformedException;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLNameIdentifier;
import org.globus.opensaml11.saml.XML;

import org.w3c.dom.Element;

/**
 * An implementation of the SAML unspecified name identifier
 *
 * @see org.globus.opensaml11.saml.SAMLNameIdentifier
 *
 * @author Tom Scavo
 */
public class UnspecifiedNameIdentifier extends SAMLNameIdentifier {

    private static Logger log =
        Logger.getLogger(UnspecifiedNameIdentifier.class.getName());

    /**
     * Creates an unspecified name identifier out of its component parts.
     * (The factory mechanism of the superclass requires that this
     * constructor be overridden.)
     *
     * @param  name                 Name of subject
     * @param  nameQualifier        Federates or qualifies subject name
     * @param  format               URI describing name semantics and format
     * @exception  SAMLException    Raised if a name cannot be constructed
     */
    public UnspecifiedNameIdentifier(String name,
                                     String nameQualifier,
                                     String format)
                              throws SAMLException {
        super(name, nameQualifier, format);
    }

    /**
     * Creates an unspecified name identifier from a DOM tree.
     * (The factory mechanism of the superclass requires that this
     * constructor be overridden.)
     *
     * @param  e                  The root of a DOM tree
     * @exception  SAMLException  Thrown if the object cannot be constructed
     */
    public UnspecifiedNameIdentifier(Element e) throws SAMLException {
        super(e);
    }

    /**
     * Makes sure each of the following characteristics of this
     * object are satisfied:
     * <ul>
     *   <li>The name is not empty</li>
     *   <li>The format is not empty</li>
     *   <li>The format is the standard SAML&nbsp;1.1 unspecified format</li>
     *   <li></li>
     * </ul>
     *
     * @exception SAMLException if any of the above are not satisfied
     *
     * @see org.globus.opensaml11.saml.SAMLNameIdentifier#checkValidity()
     */
    public void checkValidity() throws SAMLException {
        log.debug("UnspecifiedNameIdentifier.checkValidity() called");

        // check name:
        if (XML.isEmpty(this.name)) {
            String msg = "Name identifier must not be empty";
            throw new MalformedException(msg);
        }
        log.debug("name checked: " + this.name);

        // check format (mostly a sanity check):
        if (XML.isEmpty(this.format)) {
            String msg = "Name identifier format must not be empty";
            throw new MalformedException(msg);
        }
        if (!this.format.equals(FORMAT_UNSPECIFIED)) {
            String msg = "Name identifier format must be FORMAT_UNSPECIFIED";
            log.error(msg + ": " + this.format);
            throw new MalformedException(msg);
        }
        log.debug("format checked: " + this.format);

    }

}
