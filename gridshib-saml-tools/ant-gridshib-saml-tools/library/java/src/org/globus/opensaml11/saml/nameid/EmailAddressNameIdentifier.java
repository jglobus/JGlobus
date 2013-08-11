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

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.apache.log4j.Logger;

import org.globus.opensaml11.saml.MalformedException;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLNameIdentifier;
import org.globus.opensaml11.saml.XML;

import org.w3c.dom.Element;

/**
 * An implementation of the SAML emailAddress name identifier
 *
 * @see org.globus.opensaml11.saml.SAMLNameIdentifier
 *
 * @author Tom Scavo
 */
public class EmailAddressNameIdentifier extends SAMLNameIdentifier {

    private static Logger log =
        Logger.getLogger(EmailAddressNameIdentifier.class.getName());

    // building up a regexp for e-mail addresses:
    final private static String ATOM =
        "[a-zA-Z0-9!#$%&'*+\\-/=?\\^_`{|}~]+";
    final private static String DOT_ATOM =
        ATOM + "(?:\\." + ATOM + ")*";
    final private static String LOCAL_PART =
        "(" + DOT_ATOM + ")";
    final private static String DOMAIN =
        "(" + DOT_ATOM + ")";

    /**
     * A regular expression for a (reduced) <code>addr-spec</code>
     * as defined in RFC&nbsp;2822.
     */
    final static String ADDR_SPEC =
        LOCAL_PART + "@" + DOMAIN;

    /**
     * A pattern that recognizes emailAddress name identifiers.
     */
    private static Pattern emailAddress;

    static {
        log.debug("Using regex: " + ADDR_SPEC);
        // compile the regular expression:
        try {
            emailAddress = Pattern.compile(ADDR_SPEC);
        } catch (PatternSyntaxException e) {
            log.error("Invalid regular expression: " + ADDR_SPEC);
            throw e;
        }
    }

    /**
     * Creates an emailAddress name identifier out of its component parts.
     * (The factory mechanism of the superclass requires that this
     * constructor be overridden.)
     *
     * @param  name                 Name of subject
     * @param  nameQualifier        Federates or qualifies subject name
     * @param  format               URI describing name semantics and format
     * @exception  SAMLException    Raised if a name cannot be constructed
     */
    public EmailAddressNameIdentifier(String name, String nameQualifier, String format)
                               throws SAMLException {
        super(name, nameQualifier, format);
    }

    /**
     * Creates an emailAddress name identifier from a DOM tree.
     * (The factory mechanism of the superclass requires that this
     * constructor be overridden.)
     *
     * @param  e                  The root of a DOM tree
     * @exception  SAMLException  Thrown if the object cannot be constructed
     */
    public EmailAddressNameIdentifier(Element e) throws SAMLException {
        super(e);
    }

    /**
     * Get an email address matcher for this object by calling
     * #getMatcher(String) on this <code>name</code>.
     *
     * @return An email address matcher.
     *
     * @see java.util.regex.Matcher
     */
    public Matcher getMatcher() {
        return getMatcher(this.name);
    }

    /**
     * Get an email address matcher for the <code>name</code> provided.
     *
     * @return An email address matcher.
     *
     * @see java.util.regex.Matcher
     */
    public static Matcher getMatcher(String name) {
        return emailAddress.matcher(name);
    }

    /**
     * Makes sure each of the following characteristics of this
     * object are satisfied:
     * <ul>
     *   <li>The name is not empty</li>
     *   <li>The name is a valid email address</li>
     *   <li>The format is not empty</li>
     *   <li>The format is the standard SAML&nbsp;1.1 emailAddress format</li>
     *   <li></li>
     * </ul>
     *
     * @exception SAMLException if any of the above are not satisfied
     *
     * @see org.globus.opensaml11.saml.SAMLNameIdentifier#checkValidity()
     */
    public void checkValidity() throws SAMLException {
        log.debug("EmailAddressNameIdentifier.checkValidity() called");

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
        if (!this.format.equals(FORMAT_EMAIL)) {
            String msg = "Name identifier format must be EMAIL_FORMAT";
            log.error(msg + ": " + this.format);
            throw new MalformedException(msg);
        }
        log.debug("format checked: " + this.format);

    }

    private void checkName() throws SAMLException {
        checkName(this.name);
    }

    private static void checkName(String name) throws SAMLException {
        if (!getMatcher(name).matches()) {
            String msg = "Name identifier must be a valid email address";
            log.error(msg + ": " + name);
            throw new MalformedException(msg);
        }
    }

}
