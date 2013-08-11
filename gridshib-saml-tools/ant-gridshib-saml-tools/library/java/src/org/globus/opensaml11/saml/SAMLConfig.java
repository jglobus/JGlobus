/*
 *  Copyright 2001-2005 Internet2
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

package org.globus.opensaml11.saml;

import java.io.IOException;
import java.io.InputStream;
import java.util.Hashtable;
import java.util.Properties;

import javax.xml.namespace.QName;
import javax.xml.parsers.FactoryConfigurationError;

import org.apache.log4j.Logger;

import org.globus.opensaml11.saml.nameid.TeraGridPrincipalNameIdentifier;

import org.w3c.dom.Element;

/**
 *  OpenSAML configuration bundle.  Implemented as a singleton.
 *
 * @author     Walter Hoehn
 */
public class SAMLConfig {

    private static SAMLConfig instance;
    private Logger log = Logger.getLogger(SAMLConfig.class.getName());

    /*
     * Support for the following name identifier format is lacking:
     *   SAML:1.1:nameid-format:WindowsDomainQualifiedName
     */
    static {

        // register unspecified format handler:
        SAMLNameIdentifier.regFactory(
            SAMLNameIdentifier.FORMAT_UNSPECIFIED,
            "org.globus.opensaml11.saml.nameid.UnspecifiedNameIdentifier");

        // register emailAddress format handler:
        SAMLNameIdentifier.regFactory(
            SAMLNameIdentifier.FORMAT_EMAIL,
            "org.globus.opensaml11.saml.nameid.EmailAddressNameIdentifier");

        // register X509SubjectName format handler:
        SAMLNameIdentifier.regFactory(
            SAMLNameIdentifier.FORMAT_X509,
            "org.globus.opensaml11.saml.nameid.X509SubjectNameNameIdentifier");

        // register TeraGridPrincipalName format handler:
        SAMLNameIdentifier.regFactory(
            TeraGridPrincipalNameIdentifier.FORMAT_TGPN,
            "org.globus.opensaml11.saml.nameid.TeraGridPrincipalNameIdentifier");
    }

    private static final String DEFAULT_PROPS =
        "/conf/globus-saml.properties";

    protected Properties properties;
    private SAMLIdentifier IDProvider = null;
    private Hashtable bindingMap = new Hashtable();

    protected SAMLConfig() {

        verifyUsableXmlParser();

        properties = new Properties();
        try {
            //loadProperties(this.getClass().getResourceAsStream("/conf/opensaml.properties"));
            loadProperties(SAMLConfig.class.getResourceAsStream(DEFAULT_PROPS));
            log.info("Loaded default library properties: " + DEFAULT_PROPS);
        } catch (IOException e) {
            String msg = "Unable to load default library properties: ";
            msg += DEFAULT_PROPS;
            log.warn(msg);
        }

        org.apache.xml.security.Init.init();

        SAMLCondition.conditionTypeMap.put(
            new QName(XML.SAML_NS, "AudienceRestrictionCondition"),
            "org.globus.opensaml11.saml.SAMLAudienceRestrictionCondition");
        SAMLCondition.conditionTypeMap.put(
            new QName(XML.SAML_NS, "AudienceRestrictionConditionType"),
            "org.globus.opensaml11.saml.SAMLAudienceRestrictionCondition");
        SAMLCondition.conditionTypeMap.put(
            new QName(XML.SAML_NS, "DoNotCacheCondition"),
            "org.globus.opensaml11.saml.SAMLDoNotCacheCondition");
        SAMLCondition.conditionTypeMap.put(
            new QName(XML.SAML_NS, "DoNotCacheConditionType"),
            "org.globus.opensaml11.saml.SAMLDoNotCacheCondition");

        SAMLQuery.queryTypeMap.put(
            new QName(XML.SAMLP_NS, "AttributeQuery"),
            "org.globus.opensaml11.saml.SAMLAttributeQuery");
        SAMLQuery.queryTypeMap.put(
            new QName(XML.SAMLP_NS, "AttributeQueryType"),
            "org.globus.opensaml11.saml.SAMLAttributeQuery");
        SAMLQuery.queryTypeMap.put(
            new QName(XML.SAMLP_NS, "AuthenticationQuery"),
            "org.globus.opensaml11.saml.SAMLAuthenticationQuery");
        SAMLQuery.queryTypeMap.put(
            new QName(XML.SAMLP_NS, "AuthenticationQueryType"),
            "org.globus.opensaml11.saml.SAMLAuthenticationQuery");
        SAMLQuery.queryTypeMap.put(
            new QName(XML.SAMLP_NS, "AuthorizationDecisionQuery"),
            "org.globus.opensaml11.saml.SAMLAuthorizationDecisionQuery");
        SAMLQuery.queryTypeMap.put(
            new QName(XML.SAMLP_NS, "AuthorizationDecisionQueryType"),
            "org.globus.opensaml11.saml.SAMLAuthorizationDecisionQuery");

        SAMLStatement.statementTypeMap.put(
            new QName(XML.SAML_NS, "AttributeStatement"),
            "org.globus.opensaml11.saml.SAMLAttributeStatement");
        SAMLStatement.statementTypeMap.put(
            new QName(XML.SAML_NS, "AttributeStatementType"),
            "org.globus.opensaml11.saml.SAMLAttributeStatement");
        SAMLStatement.statementTypeMap.put(
            new QName(XML.SAML_NS, "AuthenticationStatement"),
            "org.globus.opensaml11.saml.SAMLAuthenticationStatement");
        SAMLStatement.statementTypeMap.put(
            new QName(XML.SAML_NS, "AuthenticationStatementType"),
            "org.globus.opensaml11.saml.SAMLAuthenticationStatement");
        SAMLStatement.statementTypeMap.put(
            new QName(XML.SAML_NS, "AuthorizationDecisionStatement"),
            "org.globus.opensaml11.saml.SAMLAuthorizationDecisionStatement");
        SAMLStatement.statementTypeMap.put(
            new QName(XML.SAML_NS, "AuthorizationDecisionStatementType"),
            "org.globus.opensaml11.saml.SAMLAuthorizationDecisionStatement");

        // a concrete implementation of saml:SubjectStatementAbstractType:
        SAMLStatement.statementTypeMap.put(
            new QName(XML.SAMLSAP_NS, "SubjectStatementType"),
            "org.globus.opensaml11.saml.SubjectStatement");

        // Register default binding implementations...
        setDefaultBindingProvider(SAMLBinding.SOAP, getProperty("org.globus.opensaml11.saml.provider.soapbinding"));
    }

    /**
     * Returns the active OpenSAML configuration.
     * @return SAMLConfig
     */
    public synchronized static SAMLConfig instance() {

        if (instance == null) {
            instance = new SAMLConfig();
            return instance;
        }
        return instance;
    }

    /**
     * Returns the default provider of the SAMLIdentifier interface
     * @return  the default provider
     */
    public synchronized SAMLIdentifier getDefaultIDProvider() {
        if (IDProvider == null)
            IDProvider = SAMLIdentifierFactory.getInstance();
        return IDProvider;
    }

    public synchronized String getDefaultBindingProvider(String binding) {
        return (String)bindingMap.get(binding);
    }

    public synchronized void setDefaultBindingProvider(String binding, String provider) {
        bindingMap.put(binding,provider);
    }

    /**
     * Enables a set of configuration properties.
     * @param properties the configuration properties to be enabled
     */
    public void setProperties(Properties properties) {
        this.properties.putAll(properties);
    }

    /**
     * Enables a set of configuration properties.
     * @param inStream an <code>InputStream</code> from which
     * a java properties file can be obtained.
     */
    public void loadProperties(InputStream inStream) throws IOException {
        Properties newProperties = new Properties();
        newProperties.load(inStream);
        setProperties(newProperties);
    }

    /**
     *  Sets a library configuration property<p>
     *
     * @param  key      A property name
     * @param  value    The value to set
     */
    public void setProperty(String key, String value) {
        properties.setProperty(key, value);
    }

    /**
     *  Gets a library configuration property
     *
     * @param  key      A property name
     * @return          The property's value, or null if the property isn't set
     */
    public String getProperty(String key) {
        return properties.getProperty(key);
    }

    /**
     *  Gets a binary library configuration property in boolean form
     *
     * @param  key      A property name
     * @return          The property's boolean value, or false if the property isn't set
     */
    public boolean getBooleanProperty(String key) {
        return new Boolean(properties.getProperty(key)).booleanValue();
    }

    /**
     *  Sets a binary library configuration property in boolean form
     *
     * @param  key      A property name
     * @param  value    A boolean property value
     */
    public void setBooleanProperty(String key, Boolean value) {
        setProperty(key, value.toString());
    }

    /**
     *  Gets a binary library configuration property in boolean form
     *
     * @param  key      A property name
     * @return          The property's integer value
     */
    public int getIntProperty(String key) {
        return new Integer(properties.getProperty(key)).intValue();
    }

    /**
     *  Sets an integer library configuration property
     *
     * @param  key      A property name
     * @param  value    An integer property value
     */
    public void setIntProperty(String key, int value) {
        setProperty(key, new Integer(value).toString());
    }

    private void verifyUsableXmlParser() {
        try {
            Class.forName("javax.xml.validation.SchemaFactory");
            Element.class.getDeclaredMethod("setIdAttributeNS", new Class[]{String.class, String.class,
                    Boolean.TYPE});
        } catch (NoSuchMethodException e) {
            throw new FactoryConfigurationError("OpenSAML requires an xml parser that supports DOM3 calls. "
                    + "Sun JAXP 1.3 has been included with this release and is strongly recommended. "
                    + "If you are using Java 1.4, make sure that you have enabled the Endorsed "
                    + "Standards Override Mechanism for this parser "
                    + "(see http://java.sun.com/j2se/1.4.2/docs/guide/standards/ for details).");
        } catch (ClassNotFoundException e) {
            throw new FactoryConfigurationError("OpenSAML requires an xml parser that supports JAXP 1.3. "
                    + "Sun JAXP 1.3 has been included with this release and is strongly recommended. "
                    + "If you are using Java 1.4, make sure that you have enabled the Endorsed "
                    + "Standards Override Mechanism for this parser "
                    + "(see http://java.sun.com/j2se/1.4.2/docs/guide/standards/ for details).");
        }
    }
}
