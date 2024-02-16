/*
 * Copyright 1999-2009 University of Chicago
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

/* http://sourceforge.net/projects/jargs/ */
import jargs.gnu.CmdLineParser;

import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

//import org.apache.log4j.ConsoleAppender;
//import org.apache.log4j.FileAppender;
//import org.apache.log4j.Level;
//import org.apache.log4j.Logger;
//import org.apache.log4j.PatternLayout;

import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttributeStatement;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
//import org.opensaml.SAMLStatement;
import org.opensaml.SAMLSubject;
//import org.opensaml.SAMLSubjectAssertion;
import org.opensaml.SAMLSubjectStatement;

import edu.internet2.middleware.shibboleth.aa.AAAttribute;
import edu.internet2.middleware.shibboleth.aa.AAAttributeSet;
//import edu.internet2.middleware.shibboleth.aa.AAAttributeSet.ShibAttributeIterator;
import edu.internet2.middleware.shibboleth.aa.arp.ArpEngine;
import edu.internet2.middleware.shibboleth.aa.arp.ArpException;
import edu.internet2.middleware.shibboleth.aa.arp.ArpProcessingException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver;
import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolverException;
import edu.internet2.middleware.shibboleth.common.Credentials;
import edu.internet2.middleware.shibboleth.common.LocalPrincipal;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMapping;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.NameMapper;
import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.common.ServiceProviderMapper;
import edu.internet2.middleware.shibboleth.common.ServiceProviderMapperException;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.idp.IdPConfig;
import edu.internet2.middleware.shibboleth.idp.IdPConfigLoader;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
//import edu.internet2.middleware.shibboleth.xml.Parser;

/**
 * Issue one or more assertions for this principal.
 * One of these assertions will contain an AttributeStatement.
 * Depending on the command-line arguments, one of these
 * assertions may contain an AuthenticationStatement.
 * <p>
 * Based on ResolverTest.java by Walter Hoehn and Noah Levitt
 *
 * @author Tom Scavo
 */
public class ShibSAMLIssuerTool extends GridShibTool {

    //private static Logger log =
    //    Logger.getLogger(ShibSAMLIssuerTool.class.getName());
    //private static Logger log = null;

    /*
    static {
        try {
            configureToolLog();
            log = Logger.getLogger("gridshib-tool");
        } catch (ShibbolethConfigurationException e) {
            // TBA
        }
    }
    */

    // command-line options:
    private static boolean debug = false;
    private static boolean quiet = false;
    private static String principalName = null;
    private static String configURL = null;
    private static String relyingPartyID = null;
    //private static String resource = null;
    private static boolean authnWanted = false;
    private static String authnMethod = null;
    private static Date authnInstant = null;
    private static String ssoResponseURL = null;
    private static boolean x509Wanted = false;

    private static URL resourceUrl = null;  // not used
    private static LocalPrincipal principal = null;
    private static String idpXml = null;

    private static Document idpConfig = null;
    private static IdPConfig configuration = null;
    private static String issuerID = null;
    private static NameMapper nameMapper = null;
    private static RelyingParty relyingParty = null;

    private static AttributeResolver resolver = null;
    private static ArpEngine arpEngine = null;

    private static SubjectBasedAssertionSet assertions = null; // temporary

    /**
     * Run this command-line application.
     *
     * @param args
     *            command-line arguments
     */
    public static void main(String[] args) {

        parseCommandLine(args);
        initializeConfig();
        initializeResolver();
        AAAttributeSet attributeSet = createAttributeSet();
        resolveAttributes(attributeSet);
        issueAssertions(attributeSet);

        // TODO: Support for --x509
        if (x509Wanted) {
            log.warn("Option --x509 not yet implemented");
            log.warn("Ignoring option --x509");
            x509Wanted = false;
        }

        if (x509Wanted) {
            // TODO: Implement bindAssertions()
            //bindAssertions();
            // TODO: Implement outputCertificate()
            //outputCertificate();
        } else {
            outputAssertions(System.out);
        }
        System.exit(0);

    }

    /**
     * Process the command-line arguments.
     *
     * @param args
     *            command-line arguments
     */
    private static void parseCommandLine(String[] args) {

        // TODO: Use Jakarta Commons CLI library
        CmdLineParser parser = new CmdLineParser();

        CmdLineParser.Option helpOption =
            parser.addBooleanOption('h', "help");
        CmdLineParser.Option userOption =
            parser.addStringOption('\u0000', "user");
        CmdLineParser.Option relyingPartyOption =
            parser.addStringOption('\u0000', "relyingParty");
        CmdLineParser.Option configOption =
            parser.addStringOption('\u0000', "config");
        //CmdLineParser.Option resourceOption =
        //    parser.addStringOption('\u0000', "resource");
        CmdLineParser.Option authnOption =
            parser.addBooleanOption('\u0000', "authn");
        CmdLineParser.Option authnMethodOption =
            parser.addStringOption('\u0000', "authnMethod");
        CmdLineParser.Option authnInstantOption =
            parser.addStringOption('\u0000', "authnInstant");
        CmdLineParser.Option ssoResponseOption =
            parser.addStringOption('\u0000', "ssoResponse");
        CmdLineParser.Option x509Option =
            parser.addBooleanOption('\u0000', "x509");
        CmdLineParser.Option debugOption =
            parser.addBooleanOption('d', "debug");
        CmdLineParser.Option quietOption =
            parser.addBooleanOption('\u0000', "quiet");

        try {
            parser.parse(args);
        } catch (CmdLineParser.OptionException e) {
            System.err.println("Command-line parser failed: " + e.getMessage());
            if (!quiet) {printUsage(System.out);}
            System.exit(1);
        }

        Boolean helpEnabled = (Boolean) parser.getOptionValue(helpOption);
        if (helpEnabled != null && helpEnabled.booleanValue()) {
            printUsage(System.out);
            System.exit(0);
        }

        Boolean debugEnabled = ((Boolean) parser.getOptionValue(debugOption));
        if (debugEnabled != null) {
            debug = debugEnabled.booleanValue();
        }
        try {
            configureLogging(debug);
            //log = Logger.getLogger("gridshib-tool");
        } catch (ShibbolethConfigurationException e) {
            System.err.println("Log initialization failed");
            System.exit(1);
        }


        principalName = (String) parser.getOptionValue(userOption);
        relyingPartyID = (String) parser.getOptionValue(relyingPartyOption);
        configURL = (String) parser.getOptionValue(configOption);
        //resource = (String) parser.getOptionValue(resourceOption);

        Boolean authnEnabled = ((Boolean) parser.getOptionValue(authnOption));
        if (authnEnabled != null) {
            authnWanted = authnEnabled.booleanValue();
        }
        authnMethod = (String) parser.getOptionValue(authnMethodOption);
        // TODO: Implement authnInstant
        // authnInstant = (Date) parser.getOptionValue(authnInstantOption);

        ssoResponseURL = (String) parser.getOptionValue(ssoResponseOption);
        Boolean x509Enabled = ((Boolean) parser.getOptionValue(x509Option));
        if (x509Enabled != null) {
            x509Wanted = x509Enabled.booleanValue();
        }
        Boolean quietEnabled = ((Boolean) parser.getOptionValue(quietOption));
        if (quietEnabled != null) {
            quiet = quietEnabled.booleanValue();
        }

        checkArgs();

        principal = new LocalPrincipal(principalName);
        idpXml = configURL + "etc/idp.xml";

    }

    /**
     * Configure logging for this application.
     *
     * @param debugEnabled
     *            debugging indicator
     */
    /*
    private static void configureLogging(boolean debugEnabled) {

        String location = logLocation;
        if (location == null) {}

        FileAppender rootAppender = null;
        try {
            String logPath = new ShibResource(location, GridShibTool.class).getFile().getCanonicalPath();
            rootAppender = createRollingFileAppender(toolLogLayoutPattern,
                                                     logPath,
                                                     logAppenderDatePattern);
            rootAppender.setName("gridshib-tool");
        } catch (Exception e) {
            throw new ShibbolethConfigurationException("location " + location
                    + ": error creating DailyRollingFileAppender: " + e);
        }

        //ConsoleAppender rootAppender = new ConsoleAppender();
        //rootAppender.setWriter(new PrintWriter(System.out));
        //rootAppender.setName("stdout");
        Logger.getRootLogger().addAppender(rootAppender);

        if (debugEnabled) {
            Logger.getRootLogger().setLevel(Level.DEBUG);
            rootAppender.setLayout(new PatternLayout("%-5p %-41X{serviceId} %d{ISO8601} (%c:%L) - %m%n"));
        } else {
            Logger.getRootLogger().setLevel(Level.INFO);
            Logger.getLogger("edu.internet2.middleware.shibboleth.aa.attrresolv").setLevel(Level.WARN);
            rootAppender.setLayout(new PatternLayout(PatternLayout.TTCC_CONVERSION_PATTERN));
        }
        Logger.getLogger("org.apache.xml.security").setLevel(Level.OFF);
    }
    */

    /**
     * Validate command-line arguments.
     */
    private static void checkArgs() {

        // check principal name:
        if (principalName == null) {
            log.error("Missing required option --user");
            if (!quiet) {printUsage(System.out);}
            System.exit(1);
        }
        log.debug("Using option --user=" + principalName);

        // check relying party ID:
        if (relyingPartyID == null) {
            log.error("Missing required option --relyingParty");
            if (!quiet) {printUsage(System.out);}
            System.exit(1);
        }
        try {
            new URI(relyingPartyID);
        } catch (URISyntaxException e) {
            String msg = "Option --relyingParty is invalid URI: ";
            log.error(msg + e.getMessage());
            System.exit(1);
        }
        log.debug("Using option --relyingParty=" + relyingPartyID);

        // check config URL:
        if (configURL == null) {
            log.error("Missing required option --config");
            if (!quiet) {printUsage(System.out);}
            System.exit(1);
        }
        try {
            new URL(configURL);
        } catch (MalformedURLException e) {
            String msg = "Option --config is invalid URL: ";
            log.error(msg + e.getMessage());
            System.exit(1);
        }
        configURL += (configURL.endsWith("/")) ? "" : "/";
        log.debug("Using option --config=" + configURL);

        /*
        // check resource URL:
        try {
            if (resource != null) {
                resourceUrl = new URL(resource);
            }
        } catch (MalformedURLException e) {
            String msg = "Specified resource URL is invalid: ";
            log.error(msg + e.getMessage());
            System.exit(1);
        }
        */

        // check argument dependencies:
        if (!authnWanted && (authnMethod != null || authnInstant != null)) {
            log.error("Option --authn required.");
            if (!quiet) {printUsage(System.out);}
            System.exit(1);
        }

        // check AuthenticationMethod:
        if (authnMethod != null) {
            try {
                new URI(authnMethod);
            } catch (URISyntaxException e) {
                String msg = "Option --authnMethod is invalid URI: ";
                log.error(msg + e.getMessage());
                System.exit(1);
            }
            log.debug("Using option --authnMethod=" + authnMethod);
        }

        // check AuthenticationInstant:
        if (authnInstant != null) {
            // TODO: check authnInstant to be valid Date
            log.warn("Option --authnInstant not yet implemented");
            log.warn("Ignoring option --authnInstant=" + authnInstant);
        }


        // check SSO Response:
        if (ssoResponseURL != null) {
            try {
                new URL(ssoResponseURL);
            } catch (MalformedURLException e) {
                String msg = "Option --ssoResponse is invalid URL: ";
                log.error(msg + e.getMessage());
                System.exit(1);
            }
            // TODO: does ssoResponseURL point to valid SAML Response?
            // TODO: Process ssoResponseURL
            log.warn("Option --ssoResponse not yet implemented");
            log.warn("Ignoring option --ssoResponse=" + ssoResponseURL);
        }

        // TODO: Support for input SAMLResponse (stdin)

    }

    /**
     * Print usage screen.
     *
     * @param out
     *            an output sink
     */
    private static void printUsage(PrintStream out) {
        String usage = "Usage: gridshib-saml-tool ";
        out.println(usage + "[-h|--help]");
        usage += "[-d|--debug] ";
        usage += "[--quiet] ";
        usage += "--user=Name --relyingParty=URI --config=URL ";
        //usage += "[--resource=URL] ";
        usage += "[--authn [--authnMethod=URI] [--authnInstant=Date]] ";
        usage += "[--ssoResponse=URL] ";
        usage += "[--x509] ";
        out.println(usage);
        out.println();
        out.println("Options:");
        out.println("  -d, --debug          Run in debug mode");
        out.println("  --quiet              Run in quiet mode");
        out.println("  --user               Local principal name (username)");
        out.println("  --relyingParty       Unique identifier of relying party (SP)");
        out.println("  --config             IdP home directory (as file: URL)");
        //out.println("  --resource           Filter attributes based on resource URL");
        out.println("  --authn              Issue AuthenticationStatement");
        out.println("  --authnMethod        AuthenticationMethod URI (requires --authn).");
        out.println("  --authnInstant       AuthenticationInstant (requires --authn).");
        out.println("  --ssoResponse        File containing SAMLResponse (as file: URL)");
        out.println("  --x509               Bind assertion(s) to X.509 proxy certificate");
    }

    /**
     * Initialize the configuration (based on config files).
     */
    private static void initializeConfig() {

        try {
            idpConfig = IdPConfigLoader.getIdPConfig(idpXml);
            configuration = new IdPConfig(idpConfig.getDocumentElement());
        } catch (ShibbolethConfigurationException e) {
            String msg = "Error loading IdP configuration file (" + idpXml + "): ";
            log.error(msg + e.getMessage());
            System.exit(1);
        }

        // get IdP entityID directly from config file:
        issuerID = configuration.getProviderId();

        // Load name mappings
        nameMapper = new NameMapper();
        NodeList itemElements =
            idpConfig.getDocumentElement().getElementsByTagNameNS(NameIdentifierMapping.mappingNamespace, "NameMapping");

        for (int i = 0; i < itemElements.getLength(); i++) {
            try {
                nameMapper.addNameMapping((Element) itemElements.item(i));
            } catch (NameIdentifierMappingException e) {
                String msg = "Name identifier mapping could not be loaded: ";
                log.error(msg + e.getMessage());
                System.exit(1);
            }
        }

        // Load signing credentials
        itemElements = idpConfig.getDocumentElement().getElementsByTagNameNS(Credentials.credentialsNamespace, "Credentials");
        if (itemElements.getLength() < 1) {
            log.error("No credentials specified.");
            System.exit(1);
        }
        if (itemElements.getLength() > 1) {
            log.error("Multiple Credentials elements found, using first.");
            System.exit(1);
        }
        Credentials credentials = new Credentials((Element) itemElements.item(0));

        // Load relying party config
        ServiceProviderMapper spMapper = null;
        try {
            spMapper = new ServiceProviderMapper(idpConfig.getDocumentElement(), configuration, credentials, nameMapper);
        } catch (ServiceProviderMapperException e) {
            String msg = "Could not load Identity Provider configuration: ";
            log.error(msg + e.getMessage());
            System.exit(1);
        }

        if (spMapper == null) {
            log.error("Null ServiceProviderMapper");
            System.exit(1);
        }
        relyingParty = spMapper.getRelyingParty(relyingPartyID);

    }

    /**
     * Initialize the attribute resolver.
     */
    private static void initializeResolver() {

        try {
            resolver = new AttributeResolver((edu.internet2.middleware.shibboleth.idp.IdPConfig)configuration);

            NodeList itemElements = idpConfig.getDocumentElement().getElementsByTagNameNS(
                    IdPConfig.configNameSpace, "ReleasePolicyEngine");

            if (itemElements.getLength() > 1) {
                String msg = "Multiple ReleasePolicyEngine elements found, using first.";
                log.warn(msg);
            }

            if (itemElements.getLength() < 1) {
                arpEngine = new ArpEngine();
            } else {
                arpEngine = new ArpEngine((Element) itemElements.item(0));
            }
        } catch (AttributeResolverException e) {
            String msg = "Error initializing the Attribute Resolver: ";
            log.error(msg + e.getMessage());
            System.exit(1);
        } catch (ArpException e) {
            String msg = "Error initializing the ARP Engine: ";
            log.error(msg + e.getMessage());
            System.exit(1);
        }

    }

    /**
     * Create a set of attributes for this principal.
     *
     * @return a set of attributes
     */
    private static AAAttributeSet createAttributeSet() {

        String[] attributes = resolver.listRegisteredAttributeDefinitionPlugIns();
        AAAttributeSet attributeSet = new AAAttributeSet();

        for (int i = 0; i < attributes.length; i++) {
            try {
                attributeSet.add(new AAAttribute(attributes[i]));
            } catch (org.opensaml.SAMLException e) {
                String msg = "Error creating AAAttribute (" + attributes[i] + "): ";
                log.error(msg + e.getMessage());
                System.exit(1);
            }
        }

        return attributeSet;
    }

    /**
     * Resolve attributes subject to policy.
     *
     * @param attributeSet
     *            a set of attributes for this principal
     */
    private static void resolveAttributes(AAAttributeSet attributeSet) {

        resolver.resolveAttributes(principal, relyingPartyID, issuerID, attributeSet);

        try {
            if (arpEngine != null) {
                arpEngine.filterAttributes(attributeSet, principal, relyingPartyID, resourceUrl);
            }
        } catch (ArpProcessingException e) {
            String msg = "Error applying Attribute Release Policy: ";
            log.error(msg + e.getMessage());
            System.exit(1);
        }
    }

    /**
     * Construct an AttributeStatement and (optionally) an
     * AuthenticationStatement.  Wrap these statements in an
     * assertion (or separate assertions if so desired).
     *
     * @param attributeSet
     *            a set of attributes for this principal
     */
    private static void issueAssertions(AAAttributeSet attributeSet) {

        // TODO: Call checkValidity() everywhere

        assertions =
            new SubjectBasedAssertionSet(nameMapper, principal, relyingParty);
        assertions.setIssuer(issuerID);

        // issue attribute statement:
        SAMLAttributeStatement attrStatement = new SAMLAttributeStatement();
        Collection attributes = Arrays.asList(attributeSet.getAttributes());
        try {
            attrStatement.setAttributes(attributes);
        } catch (SAMLException e) {
            String msg = "Unable to create AttributeStatement: ";
            log.error(msg + e.getMessage());
            System.exit(1);
        }
        try {
            assertions.add(attrStatement);
        } catch (Exception e) {
            String msg = "Unable to add AttributeStatement: ";
            log.error(msg + e.getMessage());
            System.exit(1);
        }
        if (authnWanted) {
            // issue authentication statement:
            SAMLAuthenticationStatement authnStatement =
                new SAMLAuthenticationStatement();
            if (authnMethod == null) {
                authnMethod = relyingParty.getDefaultAuthMethod().toString();
            }
            authnStatement.setAuthMethod(authnMethod);
            if (authnInstant == null) {
                authnInstant = new Date(System.currentTimeMillis());
            }
            authnStatement.setAuthInstant(authnInstant);
            try {
                assertions.add(authnStatement);
            } catch (Exception e) {
                String msg = "Unable to add AuthenticationStatement: ";
                log.error(msg + e.getMessage());
                System.exit(1);
            }
        }

    }

    /**
     * TBA
     *
     * @param out
     *            an output sink
     */
    private static void outputAssertions(PrintStream out) {

        // each assertion is null-terminated:
        Iterator iterator = assertions.iterator();
        while (iterator.hasNext()) {
            out.print(((SAMLAssertion)iterator.next()).toString());
            out.print('\u0000');
        }
        /*
        for (int i = 0; i < assertions.size(); i++) {
            out.print(((SAMLAssertion)assertions.get(i)).toString());
            out.print('\u0000');
        }
        */

    }

}

/**
 * A set of subject-based assertions
 */
class SubjectBasedAssertionSet extends HashSet {

    /* TODO:
     * - add a logger
     * - implement wantsOneAssertion
     * - remove dependencies on NameMapper, LocalPrincipal, RelyingParty (tuff)
     * - change name to SAMLSubjectAssertionSet
     * - implement class SAMLSubjectAssertion
     * - cache subject
     * - implement exception class
     * - implement: public void add(SAMLAssertion);
     */

    private NameMapper nameMapper;
    private LocalPrincipal principal;
    private RelyingParty relyingParty;
    private String issuer;

    public SubjectBasedAssertionSet(NameMapper mapper,
                                    LocalPrincipal principal,
                                    RelyingParty relyingParty) {
        this.nameMapper = mapper;
        this.principal = principal;
        this.relyingParty = relyingParty;
        this.issuer = null;
    }

    public void add(SAMLSubjectStatement newStatement) throws Exception {

        // TODO: check subject-less statement

        // check exceptional case:
        if (relyingParty.singleAssertion() && super.size() > 1) {
            throw new Exception("Multiple assertions in set");
        }

        // compute subject (cloned or new):
        SAMLSubject subject = null;
        if (super.size() > 0) {
            SAMLSubjectStatement statement = null;
            SAMLAssertion assertion = null;
            Iterator iterator = super.iterator();
            while (iterator.hasNext()) {
                assertion = (SAMLAssertion) iterator.next();
                if (assertion.getStatements().hasNext()) {
                    statement = (SAMLSubjectStatement) assertion.getStatements().next();
                    break;
                }
            }
            if (statement == null) {
                throw new Exception("Assertions have no statements");
            }
            try {
                subject = (SAMLSubject) statement.getSubject().clone();
            } catch (CloneNotSupportedException e) {
                String msg = "Unable to clone Subject: ";
                if (relyingParty.passThruErrors()) {
                    // TBD
                } else {
                    // TBD
                }
                throw new Exception(msg + e.getMessage());
            }
        } else {
            SAMLNameIdentifier nameid = null;
            try {
                nameid = getNameIdentifier(nameMapper, principal, relyingParty, null);
            } catch (NameIdentifierMappingException e) {
                String msg = "Unable to map principal to SAMLNameIdentifier: ";
                throw new Exception(msg + e.getMessage());
            }
            try {
                subject = new SAMLSubject(nameid, null, null, null);
            } catch (SAMLException e) {
                String msg = "Unable to create AttributeStatement/Subject: ";
                throw new Exception(msg + e.getMessage());
            }
        }

        // add subject to statement:
        newStatement.setSubject(subject);

        /* Is the following block of code threadsafe?
         * Should this sequence be atomic?
         */

        // compute assertion (new or existing):
        SAMLAssertion assertion = null;
        if (relyingParty.singleAssertion() && super.size() > 0) {
            assertion = (SAMLAssertion)super.iterator().next();
        } else {
            assertion = new SAMLAssertion();
            assertion.setIssuer(issuer);
        }

        // add statement to assertion:
        try {
            assertion.addStatement(newStatement);
        } catch (SAMLException e) {
            String msg = "Unable to add statement: ";
            throw new Exception(msg + e.getMessage());
        }

        // add assertion to this collection:
        super.add(assertion);

    }

    public NameMapper getNameMapper() {
        return this.nameMapper;
    }

    public LocalPrincipal getLocalPrincipal() {
        return this.principal;
    }

    public RelyingParty getRelyingParty() {
        return this.relyingParty;
    }

    public String getIssuer() {
        return this.issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    /**
     * Get a SAML NameIdentifier for the given principal.
     *
     * @param mapper
     *            name mapping facility
     * @param principal
     *            the principal represented by the name identifier
     * @param relyingParty
     *            the party that will consume the name identifier
     * @param descriptor
     *            metadata descriptor for the party that will consume the name identifier
     *
     * @return the SAML NameIdentifier
     *
     * @throws NameIdentifierMappingException
     *            if a name identifier can not be created
     */
    private SAMLNameIdentifier getNameIdentifier(
        NameMapper mapper,
        LocalPrincipal principal,
        RelyingParty relyingParty,
        EntityDescriptor descriptor) throws NameIdentifierMappingException {

        String[] availableMappings = relyingParty.getNameMapperIds();

        /*  TODO: Incorporate metadata
        // If we have preferred Name Identifier formats from the metadata, see if the we can find one that is configured
        // for this relying party
        SPSSODescriptor role;
        if (descriptor != null
                && (role = descriptor.getSPSSODescriptor(org.opensaml.XML.SAML11_PROTOCOL_ENUM)) != null) {
            Iterator spPreferredFormats = role.getNameIDFormats();
            while (spPreferredFormats.hasNext()) {

                String preferredFormat = (String) spPreferredFormats.next();
                for (int i = 0; availableMappings != null && i < availableMappings.length; i++) {
                    NameIdentifierMapping mapping = mapper.getNameIdentifierMappingById(availableMappings[i]);
                    if (mapping != null && preferredFormat.equals(mapping.getNameIdentifierFormat().toString())) {
                        log.debug("Found a supported name identifier format that "
                                + "matches the metadata for the relying party: ("
                                + mapping.getNameIdentifierFormat().toString() + ").");
                        return mapping.getNameIdentifier(principal, relyingParty, relyingParty.getIdentityProvider());
                    }
                }
            }
        }
        */

        // If we didn't find any matches, then just use the default for the relying party
        String defaultNameMapping = null;
        if (availableMappings != null && availableMappings.length > 0) {
            defaultNameMapping = availableMappings[0];
        }
        SAMLNameIdentifier nameid =
            mapper.getNameIdentifier(defaultNameMapping, principal, relyingParty, relyingParty.getIdentityProvider());
        //log.info("Using the default name identifier format for this relying party: (" + nameid.getFormat());
        return nameid;
    }

}
