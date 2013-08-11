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

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;

import org.globus.opensaml11.saml.MalformedException;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLNameIdentifier;
import org.globus.opensaml11.saml.XML;

import org.w3c.dom.Element;

/**
 * An implementation of the SAML X509SubjectName name identifier
 *
 * @see org.globus.opensaml11.saml.SAMLNameIdentifier
 *
 * @author Tom Scavo
 */
public class X509SubjectNameNameIdentifier extends SAMLNameIdentifier {

    private static Logger log =
        Logger.getLogger(X509SubjectNameNameIdentifier.class.getName());

    /**
     * Creates an X509SubjectName name identifier out of its component parts.
     * (The factory mechanism of the superclass requires that this
     * constructor be overridden.)
     *
     * @param  name                 Name of subject
     * @param  nameQualifier        Federates or qualifies subject name
     * @param  format               URI describing name semantics and format
     * @exception  SAMLException    Raised if a name cannot be constructed
     */
    public X509SubjectNameNameIdentifier(String name,
                                         String nameQualifier,
                                         String format)
                                  throws SAMLException {
        super(name, nameQualifier, format);
    }

    /**
     * Creates an X509SubjectName name identifier from a DOM tree.
     * (The factory mechanism of the superclass requires that this
     * constructor be overridden.)
     *
     * @param  e                  The root of a DOM tree
     * @exception  SAMLException  Thrown if the object cannot be constructed
     */
    public X509SubjectNameNameIdentifier(Element e) throws SAMLException {
        super(e);
    }

    /**
     * Determines the canonical name of this object by
     * calling #getCanonicalName(String) on this <code>name</code>.
     *
     * @return The canonical name.
     *
     * @exception SAMLException if unable to canonicalize the name
     *
     * @see javax.security.auth.x500.X500Principal
     */
    public String getCanonicalName() throws SAMLException {
        return getCanonicalName(this.name);
    }

    /**
     * Determines the canonical name of this object.
     * (Simultaneously checks the name for validity.)
     * The canonicalized name is obtained by calling
     * javax.security.auth.x500.X500Principal#getName(String).
     *
     * @return The canonical name.
     *
     * @exception SAMLException if unable to canonicalize the name
     *
     * @see javax.security.auth.x500.X500Principal
     */
    public static String getCanonicalName(String name) throws SAMLException {
        String canonicalName;
        try {
            canonicalName = (new X500Principal(name)).getName(X500Principal.CANONICAL);
        } catch (NullPointerException e) {
            String msg = "Name identifier must not be null";
            log.error(msg);
            throw new MalformedException(msg, e);
        } catch (IllegalArgumentException e) {
            String msg = "Name identifier must be a valid distinguished name";
            log.error(msg + ": " + name);
            throw new MalformedException(msg, e);
        }
        return canonicalName;
    }

    /**
     * Makes sure each of the following characteristics of this
     * object are satisfied:
     * <ul>
     *   <li>The name is not empty</li>
     *   <li>The name is a valid X.500 distinguished name</li>
     *   <li>The format is not empty</li>
     *   <li>The format is the standard SAML&nbsp;1.1 X509SubjectName format</li>
     *   <li></li>
     * </ul>
     *
     * @exception SAMLException if any of the above are not satisfied
     *
     * @see org.globus.opensaml11.saml.SAMLNameIdentifier#checkValidity()
     */
    public void checkValidity() throws SAMLException {
        log.debug("X509SubjectNameNameIdentifier.checkValidity() called");

        // check name:
        if (XML.isEmpty(this.name)) {
            String msg = "Name identifier must not be empty";
            throw new MalformedException(msg);
        }
        checkName();
        log.debug("name checked: " + this.name);

        // check format (mostly a sanity check):
        if (XML.isEmpty(this.format)) {
            String msg = "Name identifier format must not be empty";
            throw new MalformedException(msg);
        }
        if (!this.format.equals(FORMAT_X509)) {
            String msg = "Name identifier format must be FORMAT_X509";
            log.error(msg + ": " + this.format);
            throw new MalformedException(msg);
        }
        log.debug("format checked: " + this.format);

    }

    private void checkName() throws SAMLException {
        checkName(this.name);
    }

    private static void checkName(String name) throws SAMLException {
        try {
            new X500Principal(name);
        } catch (NullPointerException e) {
            String msg = "Name identifier must not be null";
            log.error(msg);
            throw new MalformedException(msg, e);
        } catch (IllegalArgumentException e) {
            String msg = "Name identifier must be a valid distinguished name";
            log.error(msg + ": " + name);
            throw new MalformedException(msg, e);
        }
    }

}
