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

package org.globus.gridshib.security.x509;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.GridShibConfigException;
import org.globus.gridshib.config.SAMLToolsConfig;
import org.globus.gridshib.config.SAMLToolsConfigLoader;
import org.globus.gridshib.security.saml.AttributeSet;
import org.globus.gridshib.security.saml.GlobusSAMLException;
import org.globus.gridshib.security.saml.SelfIssuedAssertion;
import org.globus.gridshib.security.util.GSIUtil;
import org.globus.gridshib.security.x509.SAMLX509Extension;

import org.globus.gsi.X509Credential;
import org.globus.gsi.CredentialException;

import org.globus.opensaml11.saml.SAMLAttribute;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLNameIdentifier;
import org.globus.opensaml11.saml.SAMLResponse;

/**
 * A <code>GlobusSAMLCredential</code> is a proxy credential
 * with a SAML assertion bound to a non-critical certificate
 * extension.
 * <p>
 * Every instance of <code>GlobusSAMLCredential</code> is
 * associated with a configuration object.  This
 * configuration object determines the default values of
 * various instance variables (<code>entityID</code>,
 * <code>format</code>, <code>attributes</code>, etc.).
 * To change the default values, invoke
 * {@link #setDefaultConfigFile(String)}.  The next
 * <code>GlobusSAMLCredential</code> instance will take
 * its default values from the given config file.
 *
 * @since 0.3.0
 */
public class GlobusSAMLCredential {

    protected static Log logger =
        LogFactory.getLog(GlobusSAMLCredential.class.getName());

    /**
     * An indicator of holder-of-key subject confirmation.
     * Used as an argument to
     * {@link #GlobusSAMLCredential(String, int)}.
     */
    public static final int HOLDER_OF_KEY = 0;

    /**
     * An indicator of sender-vouches subject confirmation.
     * Used as an argument to
     * {@link #GlobusSAMLCredential(String, int)}.
     */
    public static final int SENDER_VOUCHES = 1;

    /**
     * A convenience method that gets the default lifetime
     * of a proxy credential associated with the
     * <code>GlobusSAMLCredential</code> class.
     *
     * @return the default X.509 lifetime
     */
    public static int getDefaultX509Lifetime() {
        return GSIUtil.getDefaultLifetime();
    }

    private static File defaultConfigFile = null;

    /**
     * Sets the default config file for this class of
     * <code>GlobusSAMLCredential</code> instances.
     * If a config file has already been loaded before
     * a <code>GlobusSAMLCredential</code> instance is
     * created, the default config file is ignored.
     * Otherwise the default config file is loaded as
     * the <code>GlobusSAMLCredential</code> instance
     * is created.  You can change the default config
     * file at any time, in which case the next instance
     * of <code>GlobusSAMLCredential</code> will be
     * associated with this new config file by default.
     * <p>
     * The default config file is initially null and may be
     * explicitly set to null by calling this method with a
     * null argument.  If the default config file is null,
     * the next instance of <code>GlobusSAMLCredential</code>
     * that is not already associated with a config file
     * will be associated with the default config file
     * specified in the bootstrap properties file.
     *
     * @param configPath a (system dependent) path to a config file
     *
     * @see org.globus.gridshib.config.SAMLToolsConfigLoader
     */
    public static void setDefaultConfigFile(String configPath) {

        if (configPath == null) {
            defaultConfigFile = null;
            return;
        }
        defaultConfigFile = new File(configPath);
    }

    private static X509Credential defaultIssuingCred = null;

    /**
     * Sets the default issuing credential for this class
     * of <code>GlobusSAMLCredential</code> instances.
     * Invoking this method overrides the configured
     * issuing credential.
     * <p>
     * Use
     * {@link #setCredential(X509Credential)} to override
     * this default issuing credential on a per instance
     * basis.
     *
     * @param cred the default issuing credential
     *
     * @see #setDefaultConfigFile(String)
     */
    public static void setDefaultCredential(X509Credential cred) {
        defaultIssuingCred = cred;
    }

    private SAMLToolsConfig config = null;

    // instance variables whose values are provided by the user:
    private String username;
    private int confirmationType;

    // instance variables whose initial values may be configured:
    private String format;
    private String template;
    private String nameQualifier;
    private AttributeSet attributes;
    private X509Credential issuingCred;

    // instance variables whose values are computed by this class:
    private boolean wantAuthnStatement;
    private String authnMethod;
    private Date authnInstant;
    private String ipAddress;
    private File ssoResponseFile;
    private File xmlFile;
    private int x509Lifetime;
    private int samlLifetime;
    private SelfIssuedAssertion assertion;
    private boolean isDirty;

    /**
     * A GlobusCredential containing a self-issued SAML
     * assertion with holder-of-key subject confirmation.
     */
    public GlobusSAMLCredential() throws GlobusSAMLException {
        this.username = null;
        init(HOLDER_OF_KEY);
    }

    /**
     * A <code>GlobusSAMLCredential</code> instance is essentially
     * a <code>GlobusCredential</code> containing a self-issued SAML
     * assertion with the indicated type of subject confirmation.
     *
     * @param username the name of the authenticated user
     * @param confirmationType the subject confirmation type,
     *        either <code>HOLDER_OF_KEY</code> or
     *        <code>SENDER_VOUCHES</code>
     *
     * @exception GlobusSAMLException
     *            if a config file is not loaded and unable
     *            to load the default config file, or if the
     *            confirmation type is not recognized
     */
    public GlobusSAMLCredential(String username, int confirmationType)
                         throws GlobusSAMLException {
        this.username = username;
        init(confirmationType);
    }

    private void init(int confirmationType) throws GlobusSAMLException {

        try {
            loadConfigFile();
            logger.info("Loaded the default config file");
        } catch (GridShibConfigException e) {
            String msg = "Unable to load the default config file";
            logger.error(msg, e);
            throw new GlobusSAMLException(msg, e);
        } catch (CredentialException e) {
            String msg = "Unable to obtain a Globus credential";
            logger.error(msg, e);
            throw new GlobusSAMLException(msg, e);
        }

        switch (confirmationType) {
            case HOLDER_OF_KEY:
                logger.info("set holder-of-key subject confirmation");
                break;
            case SENDER_VOUCHES:
                logger.info("set sender-vouches subject confirmation");
                break;
            default:
                String msg = "Unrecognizable confirmation type: " +
                             confirmationType;
                logger.error(msg);
                throw new GlobusSAMLException(msg);
        }

        this.confirmationType = confirmationType;

        this.issuingCred = config.getCredential();  // may be null
        this.setFormat(config.getFormat(), config.getTemplate());
        this.setNameQualifier(config.getNameQualifier());
        this.setAttributes(config.getAttributes());

        this.wantAuthnStatement = false;
        this.authnMethod = null;
        this.authnInstant = null;
        this.ipAddress = null;
        this.ssoResponseFile = null;
        this.xmlFile = null;
        this.x509Lifetime = 0;
        this.samlLifetime = 0;
        this.assertion = null;
        this.isDirty = true;
    }

    /**
     * Loads the default configuration file.
     *
     * @exception org.globus.gridshib.common.GridShibConfigException
     *            if unable to load the config file or
     *            get the resulting config instance
     * @exception CredentialException
     *            if unable to get the <code>GlobusCredential</code>
     *            indicated in the config file
     */
    private void loadConfigFile() throws GridShibConfigException,
                                         CredentialException {

        // get the config instance:
        config = SAMLToolsConfigLoader.getToolConfig(defaultConfigFile);

        // configure the issuing credential:
        if (defaultIssuingCred != null) {
            config.setCredential(defaultIssuingCred);
        }

        // get the configured issuing credential:
        X509Credential configCred = config.getCredential();
        if (configCred == null) {
            logger.warn("Issuing credential not configured");
        } else {
            logger.info("Configured issuing credential: " +
                        configCred.toString());
        }

        // get the entityID;
        String configEntityID = config.getEntityID();
        if (configEntityID == null) {
            logger.warn("entityID not configured");
        } else {
            logger.info("configured entityID: " + configEntityID);
        }

        logger.info("NameID format: " + config.getFormat());
        logger.info("NameID qualifier: " + config.getNameQualifier());

        // get the configured attributes:
        SAMLAttribute[] configAttributes = config.getAttributes();
        logger.info("Found " + configAttributes.length +
                    " configured attribute" +
                    ((configAttributes.length == 1) ? "" : "s"));
    }

    /**
     * Get the username of this <code>GlobusSAMLCredential</code>
     * instance.  The username may be null in the case of a
     * holder-of-key SAML assertion, in which case a DN is used.
     *
     * @return the username
     */
    public String getUsername() {
        return this.username;
    }

    /**
     * Determines if the X.509-bound SAML token
     * is a holder-of-key SAML assertion.
     *
     * @return true if and only if the token is a
     *         holder-of-key SAML assertion
     */
    public boolean isHolderOfKey() {
        return this.confirmationType == HOLDER_OF_KEY;
    }

    /**
     * Determines if the X.509-bound SAML token
     * is a sender-vouches SAML assertion.
     *
     * @return true if and only if the token is a
     *         sender-vouches SAML assertion
     */
    public  boolean isSenderVouches() {
        return this.confirmationType == SENDER_VOUCHES;
    }

    /**
     * Get the name identifier format of this
     * <code>GlobusSAMLCredential</code> instance.
     * The name identifier format is never null.
     *
     * @return the name identifier format URI
     *
     * @since 0.4.0
     */
    public String getFormat() {
        return this.format;
    }

    /**
     * Get the name identifier format template of this
     * <code>GlobusSAMLCredential</code> instance.
     * The name identifier format template is never null.
     *
     * @return the name identifier format template
     *
     * @since 0.4.0
     */
    public String getTemplate() {
        return this.template;
    }

    /**
     * Sets the <code>Format</code> XML attribute on the
     * SAML <code>&lt;NameIdentifier&gt;</code> element.
     * A formatting template containing a <code>%PRINCIPAL%</code>
     * placeholder must be included with the <code>Format</code>
     * URI.
     *
     * @param format the (non-null) name identifier format URI
     * @param template the (non-null) name identifier format template
     *
     * @since 0.4.0
     */
    public void setFormat(String format, String template) {
        if (format == null || template == null) { return; }
        this.isDirty = true;
        this.format = format;
        this.template = template;
    }

    /**
     * Get the formatted name of this
     * <code>GlobusSAMLCredential</code> instance.
     * The formatted name eventually becomes the actual
     * value of the SAML <code>&lt;NameIdentifier&gt;</code>
     * element and is therefore never null.
     *
     * @return the formatted name
     *
     * @since 0.4.0
     */
    public String getFormattedName() {
        if (this.template == null || this.username == null) {
            return null;
        }
        return this.template.replaceAll("%PRINCIPAL%", this.username);
    }

    /**
     * Get the name qualifier of this <code>GlobusSAMLCredential</code>
     * instance.  The name qualifier may be null.
     *
     * @return the name qualifier
     *
     * @since 0.4.0
     */
    public String getNameQualifier() {
        return this.nameQualifier;
    }

    /**
     * Sets the <code>NameQualifier</code> XML attribute on
     * the SAML <code>&lt;NameIdentifier&gt;</code> element.
     *
     * @param nameQualifier the (non-null) name qualifier
     *
     * @since 0.4.0
     */
    public void setNameQualifier(String nameQualifier) {
        if (nameQualifier == null) { return; }
        this.isDirty = true;
        this.nameQualifier = nameQualifier;
    }

    /**
     * Get the attributes associated with this
     * <code>GlobusSAMLCredential</code> instance.
     *
     * @return the SAML attributes
     */
    public SAMLAttribute[] getAttributes() {
        logger.debug("Found " + this.attributes.size() +
                     " attribute" +
                     ((this.attributes.size() == 1) ? "" : "s"));
        Object[] o = this.attributes.toArray(new SAMLAttribute[0]);
        return (SAMLAttribute[])o;
    }

    /**
     * Add a SAML attribute to this
     * <code>GlobusSAMLCredential</code> instance.
     *
     * @param attribute the (non-null) attribute to be added
     *
     * @return true if and only if the attribute was added
     */
    public boolean addAttribute(SAMLAttribute attribute) {

        if (attribute == null) {
            String msg = "Null argument (attribute)";
            throw new IllegalArgumentException(msg);
        }
        logger.debug("attribute: " + attribute.toString());

        if (this.attributes.add(attribute)) {
            return (this.isDirty = true);
        }
        return false;
    }

    /**
     * Sets the attributes associated with this
     * <code>GlobusSAMLCredential</code> instance to
     * the given attributes.  Initially, the attributes
     * are precisely the configured attributes.  To clear
     * these attributes, call this method with a null
     * argument.  In any event, calling this method
     * clears any attributes associated with this
     * <code>GlobusSAMLCredential</code> instance.
     *
     * @param attributes the attributes to be associated
     *        with this <code>GlobusSAMLCredential</code>
     *        instance
     */
    public void setAttributes(SAMLAttribute[] attributes) {

        this.attributes = new AttributeSet();
        this.isDirty = true;
        if (attributes == null) { return; }
        for (int i = 0; i < attributes.length; i++) {
            this.addAttribute(attributes[i]);
        }
    }

    /**
     * Get the issuing credential of this
     * <code>GlobusSAMLCredential</code> instance.
     * The issuing credential is never null.
     *
     * @return the issuing credential
     *
     * @since 0.4.0
     */
    public X509Credential getCredential() {
        return this.issuingCred;
    }

    /**
     * Sets the issuing credential, that is, the credential
     * that signs the proxy credential issued with either
     * the {@link #issue()} or the {@link #issue(boolean)}
     * method. If the <code>setCredential</code> method is
     * <strong>not</strong> called, the configured issuing
     * credential is used.
     *
     * @param cred the (non-null) issuing credential
     *
     * @since 0.3.3
     */
    public void setCredential(X509Credential cred) {
        if (cred == null) { return; }
        this.isDirty = true;
        this.issuingCred = cred;
    }

    /**
     * Sets the authentication context for the authenticated user.
     * Call this method if and only if the requester did in fact
     * authenticate the user.  If, for example, user identity is
     * federated with an external identity provider (such as a
     * Shibboleth IdP), do <strong>not</strong> call this method.
     * <p>
     * The arguments must satisfy the following requirements:
     * <ul>
     *   <li>The <code>authnMethod</code> MUST be an URI and SHOULD
     *   be an authentication method defined in section&nbsp;7.1 of
     *   <a href="http://www.oasis-open.org/committees/download.php/3406/oasis-sstc-saml-core-1.1.pdf">SAML&nbsp;V1.1 Core</a>.</li>
     *   <li>The <code>authnInstant</code> MUST be in the past.</li>
     *   <li>The <code>ipAddress</code> is RECOMMENDED but MAY be null.</li>
     * </ul>
     *
     * @param authnMethod the (non-null) authentication method
     * @param authnInstant the (non-null) authentication instant
     * @param ipAddress the IP address of the authenticated user
     */
    public void setAuthnContext(
            String authnMethod, Date authnInstant, String ipAddress) {

        if (authnMethod == null) {
            String msg = "Null argument (authnMethod)";
            throw new IllegalArgumentException(msg);
        }
        logger.debug("authnMethod: " + authnMethod);

        if (authnInstant == null) {
            String msg = "Null argument (authnInstant)";
            throw new IllegalArgumentException(msg);
        }
        logger.debug("authnInstant: " + authnInstant.toString());
        if (authnInstant.compareTo(new Date()) >= 0) {
            String msg = "authnInstant not in the past";
            throw new IllegalArgumentException(msg);
        }

        this.authnMethod = authnMethod;
        this.authnInstant = authnInstant;
        this.wantAuthnStatement = true;
        this.isDirty = true;

        if (ipAddress == null) {
            logger.warn("Null argument (ipAddress)");
        } else {
            logger.debug("ipAddress: " + ipAddress);
            this.ipAddress = ipAddress;
        }
    }

    /**
     * Sets the path to a SAML SSO Response element.
     * Presumably, this SSO Response contains an
     * authentication statement whose content represents
     * the authentication context of the X.509-bound
     * SAML token.
     *
     * @param ssoResponseFile a system-independent <code>File</code>
     *        representation of the file containing the SAML
     *        SSO response.
     */
    public void setSSOResponseFile(File ssoResponseFile) {

        this.ssoResponseFile = ssoResponseFile;
        this.isDirty = true;
    }

    /**
     * Sets the path to an XML document.  The content of this
     * document is bound to the <code>Advice</code> element of
     * the X.509-bound SAML token.
     *
     * @param xmlFile a system-independent <code>File</code>
     *        representation of the file containing the XML
     *        document.
     */
    public void setXMLFile(File xmlFile) {

        this.xmlFile = xmlFile;
        this.isDirty = true;
    }

    /**
     * The lifetime of the X.509 proxy certificate.
     *
     * @param x509Lifetime the X.509 lifetime (in secs)
     */
    public void setX509Lifetime(int x509Lifetime) {

        if (x509Lifetime > 0) {
            this.x509Lifetime = x509Lifetime;
            this.isDirty = true;
        }
    }

    /**
     * The lifetime of the SAML token.
     * <p>
     * Note: It is best to <strong>not</strong> set this
     * variable.  Rather let the SAML assertion assume the
     * lifetime of the enclosing certificate, which it
     * does by default.
     *
     * @param samlLifetime the SAML lifetime (in secs)
     */
    public void setSAMLLifetime(int samlLifetime) {

        if (samlLifetime > 0) {
            this.samlLifetime = samlLifetime;
            this.isDirty = true;
        }
    }

    /**
     * This convenience method is equivalent to calling
     * <code>getSAMLToken(false)</code>.
     *
     * @exception GlobusSAMLException if unable to get the SAML token
     *
     * @see #getSAMLToken(boolean)
     */
    public SelfIssuedAssertion getSAMLToken() throws GlobusSAMLException {

        return getSAMLToken(false);
    }

    /**
     * Get a SAML token for this
     * <code>GlobusSAMLCredential</code> instance.
     * The SAML token is cached for efficiency.
     * Repeated calls to this method or other methods
     * requiring a SAML token may return the cached token.
     * <p>
     * If <code>forceNewToken</code> is true, a brand new
     * SAML token is returned.  Otherwise, a cached SAML
     * token may be returned.
     * <p>
     * This method throws an exception if any of the
     * following situations arise:
     * <ul>
     *   <li>if an issuing credential is not available</li>
     *   <li>if method <code>setAuthnContext</code> was
     *   called and a holder-of-key assertion is indicated</li>
     *   <li>if method <code>setSSOResponseFile</code> was
     *   called and a holder-of-key assertion is indicated</li>
     *   <li>if both methods <code>setAuthnContext</code> and
     *   <code>setSSOResponseFile</code> were called</li>
     *   <li>if unable to issue the SAML token (for any reason)</li>
     *   <li>if unable to add a SAML
     *   <code>&lt;AttributeStatement&gt;</code> to the
     *   SAML token (if required)</li>
     *   <li>if unable to add a SAML
     *   <code>&lt;AuthenticationStatement&gt;</code> to the
     *   SAML token (if required)</li>
     *   <li>if unable to determine the subject name (in
     *   the case of holder-of-key assertion)</li>
     * </ul>
     *
     * @param forceNewToken if true, returns a fresh token
     *        regardless of the cache state
     *
     * @return a self-issued assertion, that is, an assertion
     *         whose issuer is the proxy issuer
     *
     * @exception GlobusSAMLException if unable to get the SAML token
     */
    public SelfIssuedAssertion getSAMLToken(boolean forceNewToken)
                                     throws GlobusSAMLException {

        if (this.issuingCred == null) {
            String msg = "An issuing credential is required";
            logger.error(msg);
            throw new GlobusSAMLException(msg);
        }

        if (this.wantAuthnStatement && this.isHolderOfKey()) {
            String msg = "A local authentication context " +
                         "(set by calling the setAuthnContext method) " +
                         "requires sender-vouches subject confirmation";
            logger.error(msg);
            throw new GlobusSAMLException(msg);
        }

        if (this.ssoResponseFile != null && this.isHolderOfKey()) {
            String msg = "A federated authentication context (implied " +
                         "by calling the setSSOResponseFile method) " +
                         "requires sender-vouches subject confirmation";
            logger.error(msg);
            throw new GlobusSAMLException(msg);
        }

        if (this.wantAuthnStatement && this.ssoResponseFile != null) {
            String msg = "A local authentication context " +
                         "(set by calling the setAuthnContext method) " +
                         "is mutually exclusive of " +
                         "a federated authentication context (implied " +
                         "by calling the setSSOResponseFile method)";
            logger.error(msg);
            throw new GlobusSAMLException(msg);
        }

        if (forceNewToken) { this.isDirty = true; }

        if (this.isDirty) {
            logger.debug("Issuing fresh SAML token");
        } else {
            logger.debug("Getting cached SAML token");
            return this.assertion;
        }

        String entityID = config.getEntityID();
        if (entityID == null) {
            entityID = GSIUtil.getDefaultSAMLIssuer(this.issuingCred);
            logger.info("using default entityID: " + entityID);
        } else {
            logger.info("using configured entityID: " + entityID);
        }

        // self-issue a SAML Subject Assertion:
        SelfIssuedAssertion assertion = null;

        if (this.isSenderVouches()) {
            logger.debug("Issuing sender-vouches SAML assertion");
            try {
                Date now = new Date();
                assertion = new SelfIssuedAssertion(
                    now,
                    entityID,
                    this.samlLifetime,
                    this.getFormattedName(),
                    this.nameQualifier,
                    this.format,
                    true);  // sender-vouches required
                assertion.addAuthnStatement(
                    this.authnMethod,
                    this.authnInstant,
                    this.ipAddress);
                int n = this.attributes.size();
                logger.debug("Asserting " + n + " attribute" +
                             ((n == 1) ? "" : "s"));
                assertion.addAttributeStatement(
                    (n == 0) ? null : this.attributes.cloneSet());
            } catch (SAMLException e) {
                String msg = "Unable to create SAML assertion";
                logger.error(msg, e);
                throw new GlobusSAMLException(msg, e);
            } catch (CloneNotSupportedException e) {
                String msg = "Unable to clone the AttributeSet";
                logger.error(msg, e);
                throw new GlobusSAMLException(msg, e);
            }
            // nest SSO assertions (if any):
            if (this.ssoResponseFile != null) {
                String responseStr = this.ssoResponseFile.toString();
                logger.debug("Processing SSO Response: " + responseStr);
                try {
                    URL url = this.ssoResponseFile.toURI().toURL();
                    SAMLResponse response =
                        new SAMLResponse(url.openStream());
                    try {
                        assertion.nestSSOAssertions(response);
                    } catch (SAMLException e) {
                        logger.error("Unable to nest assertions", e);
                        logger.warn("Ignoring SSO Response: " + responseStr);
                    }
                } catch (MalformedURLException e) {
                    logger.error("Error converting File to URL", e);
                    logger.warn("Ignoring SSO Response: " + responseStr);
                } catch (IOException e) {
                    logger.error("Error getting InputStream", e);
                    logger.warn("Ignoring SSO Response: " + responseStr);
                } catch (SAMLException e) {
                    logger.error("Error getting SAMLResponse", e);
                    logger.warn("Ignoring SSO Response: " + responseStr);
                }
            }
        } else {
            logger.debug("Issuing holder-of-key SAML assertion");
            String nameid = null;
            String nameQualifier = null;
            String format = null;
            if (this.username == null) {
                try {
                    nameid = GSIUtil.getIdentity(this.issuingCred);
                } catch (CredentialException e) {
                    String msg = "Unable to user identity";
                    logger.error(msg, e);
                    throw new GlobusSAMLException(msg, e);
                }
                format = SAMLNameIdentifier.FORMAT_X509;
                nameQualifier = null;
            } else {
                nameid = this.getFormattedName();
                format = this.format;
                nameQualifier = this.nameQualifier;
            }
            try {
                Date now = new Date();
                assertion = new SelfIssuedAssertion(
                    now,
                    entityID,
                    this.samlLifetime,
                    nameid,
                    nameQualifier,
                    format);
                int n = this.attributes.size();
                logger.debug("Asserting " + n + " attribute" +
                             ((n == 1) ? "" : "s"));
                assertion.addAttributeStatement(
                    (n == 0) ? null : this.attributes.cloneSet());
            } catch (SAMLException e) {
                String msg = "Unable to create SAML assertion";
                logger.error(msg, e);
                throw new GlobusSAMLException(msg, e);
            } catch (CloneNotSupportedException e) {
                String msg = "Unable to clone the AttributeSet";
                logger.error(msg, e);
                throw new GlobusSAMLException(msg, e);
            }
        }

        // bind arbitrary XML content (if any) to Advice element:
        File infile = this.xmlFile;
        if (infile != null) {
            logger.debug("Processing infile " + infile);
            BufferedInputStream in = null;
            try {
                in = new BufferedInputStream(new FileInputStream(infile));
            } catch (FileNotFoundException e) {
                String msg = "Unable to locate input file";
                logger.error(msg, e);
                throw new GlobusSAMLException(msg, e);
            } catch (SecurityException e) {
                String msg = "Unable to read from file";
                logger.error(msg, e);
                throw new GlobusSAMLException(msg, e);
            }
            ByteArrayOutputStream out = null;
            try {
                out = new ByteArrayOutputStream();
                int c;
                while ((c = in.read()) != -1) {
                    out.write(c);
                }
                if (out.size() > 0) {
                    byte[] bytes = out.toByteArray();
                    try {
                        String s = new String(bytes);
                        assertion.addAdvice(s);
                        logger.debug("String added to advice: " + s);
                    } catch (SAMLException e) {
                        String msg = "Unable to add string to advice";
                        logger.error(msg, e);
                        throw new GlobusSAMLException(msg, e);
                    }
                } else {
                    logger.debug("No XML content for Advice element found");
                }
            } catch (IOException e) {
                String msg = "Unable to read bytes from input stream";
                logger.error(msg, e);
                throw new GlobusSAMLException(msg, e);
            } finally {
                if (in != null) {
                    try { in.close(); } catch (IOException e) { }
                }
                if (out != null) {
                    try { out.close(); } catch (IOException e) { }
                }
            }
        }

        this.isDirty = false;
        return (this.assertion = assertion);
    }

    /**
     * This convenience method is quivalent to calling
     * <code>getSAMLExtension(false)</code>.
     *
     * @see #getSAMLExtension(boolean)
     */
    public SAMLX509Extension getSAMLExtension() throws GlobusSAMLException,
                                                       IOException {

        return getSAMLExtension(false);
    }

    /**
     * Get the SAML X.509 certificate extension for this
     * <code>GlobusSAMLCredential</code> instance.
     * The SAML token bound to the certificate extension
     * is cached for efficiency.
     * Repeated calls to this method or other methods
     * requiring a SAML token may return the cached token.
     * <p>
     * If <code>forceNewToken</code> is true, a brand new
     * SAML token is returned.  Otherwise, a cached SAML
     * token may be returned.
     * <p>
     * This method throws an exception for all the same
     * reasons that {@link #getSAMLToken(boolean)} might
     * throw an exception.  In addition, an exception may
     * be thrown if the SAML token can not be bound to an
     * X.509 certificate extension (for any reason).
     *
     * @param forceNewToken if true, returns a freshly
     *        bound SAML token regardless of the cache state
     *
     * @return a SAML X.509 certificate extension, that is,
     *         a certificate extension containing a
     *         self-issued assertion
     *
     * @exception GlobusSAMLException if unable to get the SAML token
     * @exception IOException if unable to bind the SAML token
     *            to the certificate extension
     */
    public SAMLX509Extension getSAMLExtension(boolean forceNewToken)
                                       throws GlobusSAMLException,
                                              IOException {

        if (forceNewToken) { this.isDirty = true; }

        SelfIssuedAssertion assertion = null;
        try {
            assertion = getSAMLToken();
        } catch (GlobusSAMLException e) {
            logger.error("Unable to issue the SAML token", e);
            throw e;
        }
        assert (assertion != null);

        SAMLX509Extension ext = null;
        try {
            ext = new SAMLX509Extension(assertion);
        } catch (IOException e) {
            logger.error("Unable to create SAML X.509 Extension", e);
            throw e;
        }

        return ext;
    }

    /**
     * This convenience method is quivalent to calling
     * <code>issue(false)</code>.
     *
     * @see #issue(boolean)
     */
    public X509Credential issue() throws GlobusSAMLException,
                                           CredentialException {

        return issue(false);
    }

    /**
     * Issue an X.509 proxy credential with bound SAML token
     * for this <code>GlobusSAMLCredential</code> instance.
     * The bound SAML token is cached for efficiency.
     * Repeated calls to this method or other methods
     * requiring a SAML token may return the cached token.
     * <p>
     * If <code>forceNewToken</code> is true, a brand new
     * SAML token is returned.  Otherwise, a cached SAML
     * token may be returned.
     * <p>
     * This method throws an exception for all the same
     * reasons that {@link #getSAMLToken(boolean)} might
     * throw an exception.  In addition, an exception may
     * be thrown if the SAML token can not be bound to an
     * X.509 certificate extension (for any reason).
     *
     * @param forceNewToken if true, returns a freshly
     *        bound SAML token regardless of the cache state
     *
     * @return an X.509 proxy certificate containing a
     *         self-issued assertion
     *
     * @exception GlobusSAMLException if unable to get the SAML token
     * @exception CredentialException if unable to bind the
     *            SAML token to an X.509 proxy certificate
     */
    public X509Credential issue(boolean forceNewToken)
                           throws GlobusSAMLException,
                                  CredentialException {

        if (forceNewToken) { this.isDirty = true; }

        SelfIssuedAssertion assertion = null;
        try {
            assertion = getSAMLToken();
        } catch (GlobusSAMLException e) {
            logger.error("Unable to issue the SAML token", e);
            throw e;
        }
        assert (assertion != null);

        // bind extension to X.509 proxy certificate:
        X509Credential proxy = null;
        logger.debug("Issue PEM-encoded X.509 proxy credential");
        try {
            int lifetime = this.x509Lifetime;
            if (lifetime == 0) {
                proxy = assertion.bindToX509Proxy(this.issuingCred);
            } else {
                proxy = assertion.bindToX509Proxy(this.issuingCred, lifetime);
            }
        } catch (CredentialException e) {
            logger.error("Unable to bind SAML assertion to proxy cert", e);
            throw e;
        }

        return proxy;
    }
}
