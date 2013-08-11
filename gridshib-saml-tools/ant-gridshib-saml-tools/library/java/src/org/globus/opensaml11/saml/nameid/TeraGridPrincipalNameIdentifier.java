/*
 * Copyright 2009 University of Illinois
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
 * An implementation of the
 * <a href="http://www.teragridforum.org/mediawiki/index.php?title=SAML_NameIDs_for_TeraGrid#TeraGrid_Principal_Name_Format"><code>TeraGridPrincipalName</code></a>
 * identifier.
 *
 * @see org.globus.opensaml11.saml.SAMLNameIdentifier
 *
 * @author Tom Scavo
 */
public class TeraGridPrincipalNameIdentifier extends SAMLNameIdentifier {

    private static Logger log =
        Logger.getLogger(TeraGridPrincipalNameIdentifier.class.getName());

    /**  TeraGridPrincipalName Format URI */
    final public static String FORMAT_TGPN =
        "http://teragrid.org/names/nameid-format/principalname";

    /**
     * A regular expression for a <code>TeraGridPrincipalName</code>,
     * built from the same base character set as a (reduced)
     * <code>addr-spec</code> as defined in RFC&nbsp;2822.
     */
    final private static String ADDR_SPEC =
        EmailAddressNameIdentifier.ADDR_SPEC;

    /**
     * A pattern that recognizes <code>TeraGridPrincipalName</code>
     * identifiers.
     */
    private static Pattern tgPrincipalName;

    static {
        log.debug("Using regex: " + ADDR_SPEC);
        // compile the regular expression:
        try {
            tgPrincipalName = Pattern.compile(ADDR_SPEC);
        } catch (PatternSyntaxException e) {
            log.error("Invalid regular expression: " + ADDR_SPEC);
            throw e;
        }
    }

    /**
     * Creates a <code>TeraGridPrincipalName</code> identifier out
     * of its component parts.
     * (The factory mechanism of the superclass requires that this
     * constructor be overridden.)
     *
     * @param  name                 Name of subject
     * @param  nameQualifier        Federates or qualifies subject name
     * @param  format               URI describing name semantics and format
     * @exception  SAMLException    Raised if a name cannot be constructed
     */
    public TeraGridPrincipalNameIdentifier(String name,
                                           String nameQualifier,
                                           String format)
                                    throws SAMLException {
        super(name, nameQualifier, format);
    }

    /**
     * Creates a <code>TeraGridPrincipalName</code> identifier from
     * a DOM tree.
     * (The factory mechanism of the superclass requires that this
     * constructor be overridden.)
     *
     * @param  e                  The root of a DOM tree
     * @exception  SAMLException  Thrown if the object cannot be constructed
     */
    public TeraGridPrincipalNameIdentifier(Element e) throws SAMLException {
        super(e);
    }

    /**
     * Get a <code>TeraGridPrincipalName</code> matcher for
     * this object by calling {@link #getMatcher(String)}
     * on this <code>name</code>.
     *
     * @return A <code>TeraGridPrincipalName</code> matcher.
     *
     * @see java.util.regex.Matcher
     */
    public Matcher getMatcher() {
        return getMatcher(this.name);
    }

    /**
     * Get a <code>TeraGridPrincipalName</code> matcher for
     * the provided <code>name</code>.
     *
     * @return A <code>TeraGridPrincipalName</code> matcher.
     *
     * @see java.util.regex.Matcher
     */
    public static Matcher getMatcher(String name) {
        return tgPrincipalName.matcher(name);
    }

    /**
     * Makes sure each of the following characteristics of this
     * object are satisfied:
     * <ul>
     *   <li>The name is not empty</li>
     *   <li>The name is a valid <code>TeraGridPrincipalName</code></li>
     *   <li>The format is not empty</li>
     *   <li>The format is the <code>TeraGridPrincipalName</code> format</li>
     *   <li></li>
     * </ul>
     *
     * @exception SAMLException if any of the above are not satisfied
     *
     * @see org.globus.opensaml11.saml.SAMLNameIdentifier#checkValidity()
     */
    public void checkValidity() throws SAMLException {
        log.debug("TeraGridPrincipalNameIdentifier.checkValidity() called");

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
        if (!this.format.equals(FORMAT_TGPN)) {
            String msg = "Name identifier format must be: " + FORMAT_TGPN;
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
            String msg = "Name identifier must be a valid " +
                         "TeraGridPrincipalName";
            log.error(msg + ": " + name);
            throw new MalformedException(msg);
        }
    }

}
