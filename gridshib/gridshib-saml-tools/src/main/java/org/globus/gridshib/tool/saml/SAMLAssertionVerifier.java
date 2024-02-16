/*
 * Copyright 2008-2009 University of Illinois
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

package org.globus.gridshib.tool.saml;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.TimeZone;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.cli.ApplicationRuntimeException;
import org.globus.gridshib.saml.SAMLToolsCLI;
import org.globus.gridshib.security.util.GSIUtil;

import org.globus.gsi.X509Credential;
import org.globus.gsi.CredentialException;

import org.globus.opensaml11.saml.SAMLAttribute;
import org.globus.opensaml11.saml.SAMLAttributeStatement;
import org.globus.opensaml11.saml.SAMLAuthenticationStatement;
import org.globus.opensaml11.saml.SAMLAuthorizationDecisionStatement;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLNameIdentifier;
import org.globus.opensaml11.saml.SAMLStatement;
import org.globus.opensaml11.saml.SAMLSubject;
import org.globus.opensaml11.saml.SAMLSubjectAssertion;
import org.globus.opensaml11.saml.SubjectStatement;

/**
 * This is the SAML Assertion Verifier. Given a command-line
 * interface (CLI) that implements the <code>SAMLToolsCLI</code>
 * interface and a SAML assertion, the Verifier verifies
 * the correctness of the following assertion content:
 * <ul>
 *   <li>The <code>Issuer</code> XML attribute</li>
 *   <li>The <code>&lt;Subject&gt;</code> element</li>
 *   <li>
 *     <ul>The <code>&lt;NameIdentifier&gt;</code> element</ul>
 *     <ul>The <code>&lt;ConfirmationMethod&gt;</code> element</ul>
 *   </li>
 *   <li>The <code>&lt;AuthenticationStatement&gt;</code> element</li>
 *   <li>
 *     <ul>The <code>AuthenticationMethod</code> XML attribute</ul>
 *     <ul>The <code>AuthenticationInstant</code> XML attribute</ul>
 *     <ul>The <code>&lt;SubjectLocality&gt;</code> element</ul>
 *   </li>
 *   <li>The <code>&lt;AttributeStatement&gt;</code> element</li>
 *   <li>
 *     <ul>The name and value of every attribute corresponding
 *     to an <code>&lt;Attribute&gt;</code> element</ul>
 *   </li>
 * </ul>
 *
 * @see org.globus.gridshib.saml.SAMLToolsCLI
 *
 * @since 0.5.0
 */
public class SAMLAssertionVerifier {

    private static Log logger =
        LogFactory.getLog(SAMLAssertionVerifier.class.getName());

    private static final String UNSPECIFIED =
        SAMLAuthenticationStatement.AuthenticationMethod_Unspecified;

    SAMLToolsCLI cli = null;

    public SAMLAssertionVerifier(SAMLToolsCLI cli) {
        this.cli = cli;
    }

    public void verify(SAMLSubjectAssertion assertion)
                throws ApplicationRuntimeException {

        checkIssuer(assertion);
        checkSubject(assertion);
        checkStatements(assertion);
    }

    /* The use of CommandLine.hasOption(Char) and
     * CommandLine.getOptionValue(Char) throughout the instance
     * methods of this class is errorprone.  Evidently, the
     * corresponding methods that operate on a String argument
     * are broken in CLI 1.1.  Oh well.
     */

    private void checkIssuer(SAMLSubjectAssertion assertion)
                      throws ApplicationRuntimeException {

        CommandLine line = this.cli.getCommandLine();

        String issuer = assertion.getIssuer();

        String entityID = this.cli.getConfig().getEntityID();
        if (entityID == null) {
            X509Credential cred = null;
            if (line.hasOption("c") && line.hasOption("k")) {
                String certPath = line.getOptionValue("c").trim();
                String keyPath = line.getOptionValue("k").trim();
                logger.debug("Command-line options certPath (" + certPath +
                             ") and keyPath (" + keyPath + ") specified");
                try {
                    cred = GSIUtil.getCredential(certPath, keyPath);
                } catch (CredentialException e) {
                    this.cli.setExitCode(this.cli.APPLICATION_ERROR);
                    String msg = "Unable to obtain issuing credential";
                    throw new ApplicationRuntimeException(msg);
                }
            } else if (!line.hasOption("c") && !line.hasOption("k")) {
                logger.debug("Issuing credential configured in config file");
                cred = this.cli.getConfig().getCredential();
            } else {
                this.cli.setExitCode(this.cli.APPLICATION_ERROR);
                String msg = "Both options certPath and keyPath are required";
                throw new ApplicationRuntimeException(msg);
            }
            entityID = GSIUtil.getDefaultSAMLIssuer(cred);
        }

        if (issuer.equals(entityID)) {
            logger.debug("SAML issuer checked: " + issuer);
        } else {
            this.cli.setExitCode(this.cli.APPLICATION_ERROR);
            String msg = "SAML issuer is incorrect: " + issuer;
            throw new ApplicationRuntimeException(msg);
        }
    }

    private void checkSubject(SAMLSubjectAssertion assertion)
                       throws ApplicationRuntimeException {

        CommandLine line = this.cli.getCommandLine();

        SAMLSubject subject = assertion.getSubject();

        // check NameIdentifier:
        String name = line.getOptionValue("u");
        String qualifier = null;
        String format = null;
        if (name == null) {
            try {
                X509Credential cred = this.cli.getConfig().getCredential();
                name = GSIUtil.getIdentity(cred);
            } catch (CredentialException e) {
                this.cli.setExitCode(this.cli.APPLICATION_ERROR);
                String msg = "Unable to obtain NameIdentifier value";
                throw new ApplicationRuntimeException(msg);
            }
            format = SAMLNameIdentifier.FORMAT_X509;
        } else {
            name = this.cli.getConfig().getFormattedName(name);
            qualifier = this.cli.getConfig().getNameQualifier();
            format = this.cli.getConfig().getFormat();
        }
        SAMLNameIdentifier nameid = null;
        try {
            nameid = new SAMLNameIdentifier(name, qualifier, format);
        } catch (SAMLException e) {
            this.cli.setExitCode(this.cli.APPLICATION_ERROR);
            String msg = "Unable to create NameIdentifier";
            throw new ApplicationRuntimeException(msg);
        }
        if (!subject.getNameIdentifier().equals(nameid)) {
            this.cli.setExitCode(this.cli.APPLICATION_ERROR);
            String msg = "NameIdentifier does not match: " +
                         nameid.toString();
            throw new ApplicationRuntimeException(msg);
        }

        // check SubjectConfirmation:
        Iterator methods = subject.getConfirmationMethods();
        if (methods.hasNext()) {
            String method = (String)methods.next();
            if (!method.equals(SAMLSubject.CONF_SENDER_VOUCHES)) {
                this.cli.setExitCode(this.cli.APPLICATION_ERROR);
                String msg = "No support for confirmation method: " + method;
                throw new ApplicationRuntimeException(msg);
            }
            if (!line.hasOption("V")) {
                this.cli.setExitCode(this.cli.APPLICATION_ERROR);
                String msg = "Option --sender-vouches not specified";
                throw new ApplicationRuntimeException(msg);
            }
        } else {
            if (line.hasOption("V")) {
                this.cli.setExitCode(this.cli.APPLICATION_ERROR);
                String msg = "Confirmation methods do not match";
                throw new ApplicationRuntimeException(msg);
            }
        }
    }

    private Set assertedAttributeSet = null;

    private void checkStatements(SAMLSubjectAssertion assertion)
                          throws ApplicationRuntimeException {

        CommandLine line = this.cli.getCommandLine();

        boolean hasAuthnStatement = false;
        boolean hasAttributeStatement = false;

        assertedAttributeSet = new HashSet();

        // process SAML statements:
        Iterator statements = assertion.getStatements();
        while (statements.hasNext()) {
            SAMLStatement statement = (SAMLStatement)statements.next();
            if (statement instanceof SAMLAuthenticationStatement) {
                if (!line.hasOption("a")) {
                    this.cli.setExitCode(this.cli.APPLICATION_ERROR);
                    String msg = "Unexpected AuthnStatement found";
                    throw new ApplicationRuntimeException(msg);
                }
                hasAuthnStatement = true;
                checkAuthnStatement((SAMLAuthenticationStatement)statement);
            } else if (statement instanceof SAMLAttributeStatement) {
                hasAttributeStatement = true;
                checkAttributeStatement((SAMLAttributeStatement)statement);
            } else if (statement instanceof SAMLAuthorizationDecisionStatement) {
                logger.warn("Unsupported statement type");
                logger.info("Skipping statement: " + statement.toString());
            } else if (statement instanceof SubjectStatement) {
                logger.info("Skipping empty SubjectStatement: " +
                            statement.toString());
            } else {
                logger.warn("Unknown statement type");
                logger.info("Skipping statement: " + statement.toString());
            }
        }

        // check if AuthStatement is missing:
        if (line.hasOption("a") && !hasAuthnStatement) {
            this.cli.setExitCode(this.cli.APPLICATION_ERROR);
            String msg = "AuthnStatement missing";
            throw new ApplicationRuntimeException(msg);
        }

        // check if any attributes are missing:
        Object[] o = assertedAttributeSet.toArray(new SAMLAttribute[0]);
        SAMLAttribute[] assertedAttributes = (SAMLAttribute[])o;
        Iterator attributes =
            this.cli.getConfig().getAttributeSet().iterator();
        while (attributes.hasNext()) {
            Object attribute = attributes.next();
            for (int i = 0; i < assertedAttributes.length; i++) {
                SAMLAttribute attr = (SAMLAttribute)attribute;
                if (assertedAttributes[i].equals(attr)) {
                    if (assertedAttributes[i].hasEqualValues(attr)) {
                        logger.debug("Configured attribute checked: " +
                                     attr.toString());
                        continue;
                    } else {
                        this.cli.setExitCode(this.cli.APPLICATION_ERROR);
                        String msg = "Configured attribute has wrong " +
                                     "values: " + attr.toString();
                        throw new ApplicationRuntimeException(msg);
                    }
                }
            }
        }
    }

    private void checkAuthnStatement(SAMLAuthenticationStatement statement)
                              throws ApplicationRuntimeException {

        CommandLine line = this.cli.getCommandLine();

        // check the AuthenticationMethod attribute:
        String authnMethod = statement.getAuthMethod();
        if (authnMethod == null) {
            this.cli.setExitCode(this.cli.APPLICATION_ERROR);
            String msg = "AuthenticationMethod is missing";
            throw new ApplicationRuntimeException(msg);
        } else {
            if (line.hasOption("M")) {
                String value = line.getOptionValue("M");
                if (!authnMethod.equals(value)) {
                    this.cli.setExitCode(this.cli.APPLICATION_ERROR);
                    String msg = "authnMethod is (" + authnMethod +
                                 "), should be (" + value + ")";
                    throw new ApplicationRuntimeException(msg);
                }
            } else {
                if (!authnMethod.equals(UNSPECIFIED)) {
                    this.cli.setExitCode(this.cli.APPLICATION_ERROR);
                    String msg = "authnMethod is (" + authnMethod +
                                 "), should be (" + UNSPECIFIED + ")";
                    throw new ApplicationRuntimeException(msg);
                }
            }
            logger.debug("AuthenticationMethod was checked: " + authnMethod);
        }

        // check the AuthenticationInstant attribute:
        Date authnInstant = statement.getAuthInstant();
        if (authnInstant == null) {
            this.cli.setExitCode(this.cli.APPLICATION_ERROR);
            String msg = "AuthenticationInstant is missing";
            throw new ApplicationRuntimeException(msg);
        } else {
            if (line.hasOption("I")) {
                String pattern = this.cli.getConfig().getDateTimePattern();
                SimpleDateFormat formatter = new SimpleDateFormat(pattern);
                formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
                Date date = null;
                try {
                    date = formatter.parse(line.getOptionValue("I"));
                } catch (ParseException e) {
                    this.cli.setExitCode(this.cli.APPLICATION_ERROR);
                    String msg = "authnInstant can not be parsed: " +
                                 authnInstant.toString();
                    throw new ApplicationRuntimeException(msg, e);
                }
                if (!authnInstant.equals(date)) {
                    this.cli.setExitCode(this.cli.APPLICATION_ERROR);
                    String msg = "authnInstant is (" +
                                 authnInstant.toString() +
                                 "), should be (" + date.toString() + ")";
                    throw new ApplicationRuntimeException(msg);
                }
            } else {
                this.cli.setExitCode(this.cli.APPLICATION_ERROR);
                String msg = "authnInstant is missing";
                throw new ApplicationRuntimeException(msg);
            }
            logger.debug("AuthenticationInstant was checked: " +
                         authnInstant.toString());
        }

        // check the SubjectLocality element:
        String ipAddress = statement.getSubjectIP();
        if (ipAddress == null) {
            if (line.hasOption("i")) {
                this.cli.setExitCode(this.cli.APPLICATION_ERROR);
                String msg = "IP address is missing";
                throw new ApplicationRuntimeException(msg);
            }
            logger.debug("Null IPAddress was checked");
        } else {
            if (line.hasOption("i")) {
                String value = line.getOptionValue("i");
                if (!ipAddress.equals(value)) {
                    this.cli.setExitCode(this.cli.APPLICATION_ERROR);
                    String msg = "address is (" + ipAddress +
                                 "), should be (" + value + ")";
                    throw new ApplicationRuntimeException(msg);
                }
            } else {
                this.cli.setExitCode(this.cli.APPLICATION_ERROR);
                String msg = "address is missing";
                throw new ApplicationRuntimeException(msg);
            }
            logger.debug("IPAddress was checked: " + ipAddress);
        }
    }

    private void checkAttributeStatement(SAMLAttributeStatement statement)
                                  throws ApplicationRuntimeException {

        SAMLAttribute[] configAttributes =
            this.cli.getConfig().getAttributes();
        Iterator attributes = statement.getAttributes();
        while (attributes.hasNext()) {
            Object attribute = attributes.next();
            assertedAttributeSet.add(attribute);
            for (int i = 0; i < configAttributes.length; i++) {
                SAMLAttribute attr = (SAMLAttribute)attribute;
                if (configAttributes[i].equals(attr)) {
                    if (configAttributes[i].hasEqualValues(attr)) {
                        logger.debug("Asserted attribute checked: " +
                                     attr.toString());
                        continue;
                    } else {
                        this.cli.setExitCode(this.cli.APPLICATION_ERROR);
                        String msg = "Asserted attribute has wrong values: " +
                                     attr.toString();
                        throw new ApplicationRuntimeException(msg);
                    }
                }
            }
        }
    }
}
