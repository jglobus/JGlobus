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

package org.globus.gridshib.security;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.mapper.GridShibEntityMapper;
import org.globus.gridshib.common.mapper.TrivialEntityMap;
import org.globus.gridshib.config.BootstrapConfigLoader;
import org.globus.gridshib.saml.SAMLToolsTestCase;
import org.globus.gridshib.security.SAMLSecurityContext;
import org.globus.gridshib.security.SecurityContext;
import org.globus.gridshib.security.SecurityContextFactory;
import org.globus.gridshib.security.SecurityContextLogger;
import org.globus.gridshib.security.saml.SelfIssuedAssertion;
import org.globus.gridshib.security.saml.SimpleAttribute;
import org.globus.gridshib.security.util.CertUtil;
import org.globus.gridshib.security.util.GSIUtil;
import org.globus.gridshib.security.util.SAMLUtil;
import org.globus.gridshib.security.x509.SAMLX509Extension;

import org.globus.gsi.X509Credential;
import org.globus.gsi.CredentialException;

import org.globus.opensaml11.md.common.Constants;
import org.globus.opensaml11.saml.SAMLAuthenticationStatement;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLSubjectAssertion;

/**
 * A test application that illustrates the use of the
 * standalone GridShib Security Framework. For best results,
 * use a GridShib CA-issued EEC (which contains an embedded
 * SAML assertion).
 *
 * @since 0.3.0
 */
public class GridShibSecurityTest extends SAMLToolsTestCase {

    private static final Class CLASS = GridShibSecurityTest.class;
    private static final String CLASSNAME = CLASS.getName();

    private static Log logger = LogFactory.getLog(CLASSNAME);

    // the issuing credential (EEC or proxy):
    private static X509Credential credential = null;

    // the issued proxy credential:
    private static X509Credential proxy = null;

    // a mapping from SAML entities to X.509 entities:
    private static TrivialEntityMap entityMap = new TrivialEntityMap();

    private static String[] args = new String[]{};

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CLASS);
        GridShibSecurityTest.args = args;
    }

    public GridShibSecurityTest(String name) {
        super(name);
    }

    /**
     * @see SAMLToolsTestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();
    }

    /**
     * @see SAMLToolsTestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Loads the issuing credential and then calls the production,
     * initialization, and consumption methods in turn.
     */
    public void testGridShibSecurity() throws Exception {

        // check the number of command-line arguments:
        int n = args.length;
        if (n > 2) {
            System.err.println("Too many command-line arguments: " + n);
            System.exit(1);
        }

        /* If there are command-line arguments, use them to
         * find the issuing credential.  If there is one argument,
         * assume it's a path to a credential.  If there are two
         * arguments, assume the first is the path to the cert
         * and the second is the path to the key.
         */
        if (n > 0) {
            String certPath = args[0];
            String keyPath = (n > 1) ? args[1] : args[0];
            logger.debug("cert path: " + certPath);
            logger.debug("key path: " + keyPath);

            File certFile = new File(certPath);
            File keyFile = new File(keyPath);
            assert (certFile != null && keyFile != null);
            try {
                credential = GSIUtil.getCredential(certFile, keyFile);
            } catch (CredentialException e) {
                String msg = "Unable to obtain issuing credential";
                logger.error(msg, e);
                fail(msg);
            }
        } else {
            /* First try to get a standard GSI credential from the
             * usual place.  If that fails, fall back on the test
             * credential loaded from the bootstrap properties.
             */
            try {
                credential = GSIUtil.getCredential();
            } catch (CredentialException e1) {
                String msg = "Unable to obtain default GSI credential";
                logger.debug(msg, e1);
                credential = BootstrapConfigLoader.getCredentialDefault();
            }
        }

        logger.debug("Issuing credential (chain length " +
                     credential.getCertificateChain().length + "):\n" +
                     credential.toString());

        produceX509BoundSAML();
        initializeEntityMapping();
        consumeX509BoundSAML();
    }

    /**
     * Issues a proxy certificate with a bound SAML assertion.
     */
    private static void produceX509BoundSAML() {

        // SAML IssueInstant:
        Date now = new Date();
        // SAML issuer:
        String entityID = "https://gridshib.example.org/idp";
        // assertion lifetime:
        int lifetime = 0;
        // SAML name identifier:
        String nameid = "tscavo";
        // SAML name qualifier:
        String nameQualifier = null;
        // SAML name identifier format
        String format = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

        SelfIssuedAssertion assertion = null;
        try {
            assertion = new SelfIssuedAssertion(
                now,
                entityID,
                lifetime,
                nameid,
                nameQualifier,
                format,
                true);  // sender-vouches required
        } catch (SAMLException e) {
            String msg = "Unable to create SAML assertion";
            logger.error(msg, e);
            fail(msg);
        }

        // SAML authentication method:
        String authnMethod =
            SAMLAuthenticationStatement.AuthenticationMethod_Password;
        // SAML authentication instant:
        Date authnInstant = new Date();
        // IP address of the authenticated user:
        String subjectIP = null;

        try {
            assertion.addAuthnStatement(authnMethod, authnInstant, subjectIP);
        } catch (SAMLException e) {
            String msg = "Unable to add authn statement";
            logger.error(msg, e);
            fail(msg);
        }

        List attributeList = new ArrayList();
        String name; String[] values;
        String namespace = Constants.SHIB_ATTRIBUTE_NAMESPACE_URI;
        try {
            // FriendlyName="countryName":
            name = "urn:oid:2.5.4.6";
            values = new String[]{"US"};
            attributeList.add(new SimpleAttribute(namespace,
                                                  name,
                                                  values));
            // FriendlyName="isMemberOf":
            name = "urn:oid:1.3.6.1.4.1.5923.1.5.1.1";
            values = new String[]{"http://www.nanohub.org",
                                  "http://www.us-vo.org/"};
            attributeList.add(new SimpleAttribute(namespace,
                                                  name,
                                                  values));
        } catch (SAMLException e) {
            String msg = "Unable to create attributes";
            logger.error(msg, e);
            fail(msg);
        }

        try {
            assertion.addAttributeStatement(attributeList);
        } catch (SAMLException e) {
            String msg = "Unable to add attribute statement";
            logger.error(msg, e);
            fail(msg);
        }

        logger.debug("Binding SAML assertion to proxy: " +
                     assertion.toString());

        // proxy lifetime (in secs):
        int proxylifetime = 0;

        try {
            if (proxylifetime == 0) {
                proxy = assertion.bindToX509Proxy(credential);
            } else {
                proxy = assertion.bindToX509Proxy(credential, proxylifetime);
            }
        } catch (CredentialException e) {
            String msg = "Unable to bind SAML assertion to proxy cert";
            logger.error(msg, e);
            fail(msg);
        }

        logger.debug("Issued credential (chain length " +
                     proxy.getCertificateChain().length + "):\n" +
                     proxy.toString());
    }

    /**
     * Initializes an entity mapping, that is, a mapping of SAML
     * issuers to X.509 issuers.  For each bound SAML assertion,
     * add a map from the issuer of the SAML assertion to the
     * issuer of the containing certificate (which may be an
     * EEC or a proxy certificate).
     *
     * Note: In practice, a consumer depends on a static entity
     * map configured into the runtime environment.  In GridShib
     * for GT, for example, entity mappings are stored in the
     * file system and loaded when the runtime initializes.
     */
    private static void initializeEntityMapping() {

        /* Determine the proxy issuer, which is the EEC subject,
         * by definition.
         */
        X509Certificate[] certs = proxy.getCertificateChain();
        X509Certificate eec = null;
        try {
            logger.debug("Getting end entity cert...");
            eec = CertUtil.getEEC(certs);
        } catch (CertificateException e) {
            String msg = "Unable to determine if certificate is an " +
                         "impersonation proxy";
            logger.error(msg, e);
            fail(msg);
        }
        if (eec == null) {
            String msg = "Unable to find end entity certificate";
            logger.error(msg);
            fail(msg);
        }
        logger.debug("End entity cert: " + eec.toString());
        X500Principal eecSubject = eec.getSubjectX500Principal();
        String eecSubjectDN = eecSubject.getName(X500Principal.RFC2253);
        logger.debug("EEC subject: " + eecSubjectDN);

        /* Traverse the certificate chain and add an entity
         * map for each bound SAML assertion.
         */
        for (int i = 0; i < certs.length; i++) {
            logger.debug("Processing certificate " + i + ": " +
                         certs[i].toString());

            String entityID = null;
            SAMLSubjectAssertion assertion = null;
            try {
                assertion = SAMLX509Extension.getSAMLAssertion(certs[i]);
            } catch (IOException e) {
                String msg = "Unable to decode certificate extension";
                logger.error(msg, e);
                fail(msg);
            } catch (SAMLException e) {
                String msg = "Unable to convert extension to SAMLAssertion";
                logger.error(msg, e);
                fail(msg);
            }
            if (assertion == null) {
                logger.debug("Certificate " + i +
                             " does not contain a SAML assertion");
            } else {
                logger.debug("Bound SAML assertion: " + assertion.toString());
                entityID = assertion.getIssuer();
            }

            try {
                if (!CertUtil.isImpersonationProxy(certs[i])) {
                    if (assertion != null) {
                        assert (entityID != null);
                        // map the SAML issuer to the certificate issuer:
                        X500Principal certIssuer =
                            certs[i].getIssuerX500Principal();
                        String dn = certIssuer.getName(X500Principal.RFC2253);
                        logger.debug("Mapping SAML issuer to " +
                                     "certificate issuer: " + dn);
                        entityMap.addMapping(entityID, dn);
                    }
                    logger.debug("All certificates processed");
                    break;
                } else {
                    if (assertion != null) {
                        assert (entityID != null);
                        // map the SAML issuer to the proxy issuer:
                        logger.debug("Mapping SAML issuer to " +
                                     "proxy issuer: " + eecSubjectDN);
                        entityMap.addMapping(entityID, eecSubjectDN);
                    }
                    continue;
                }
            } catch (CertificateException e) {
                String msg = "Unable to determine if certificate is an " +
                             "impersonation proxy";
                logger.error(msg, e);
                fail(msg);
            }
        }

        GridShibEntityMapper.register(entityMap);
    }

    /**
     * Creates a security context from the SAML assertions bound
     * to the certificate chain.
     */
    private static void consumeX509BoundSAML() {

        ExtSecurityContext.init();
        Subject subject = new Subject();
        SecurityContext secCtx = SecurityContextFactory.getInstance(subject);
        assertTrue("Security context is null", secCtx != null);
        assertTrue("Security context is not an instance of " +
                   "ExtSecurityContext",
                   secCtx instanceof ExtSecurityContext);

        ExtSecurityContext extSecCtx = (ExtSecurityContext)secCtx;
        extSecCtx.addCertificateChain(proxy.getCertificateChain());
        extSecCtx.addIssuingCredential(credential);

        try {
            SAMLUtil.consumeSAMLAssertions(subject);
        } catch (IOException e) {
            String msg = "Unable to decode extension";
            logger.error(msg, e);
            fail(msg);
        } catch (SAMLException e) {
            String msg = "Unable to convert extension to SAMLAssertion";
            logger.error(msg, e);
            fail(msg);
        } catch (CertificateException e) {
            String msg = "Unable to determine if certificate is an " +
                         "impersonation proxy";
            logger.error(msg, e);
            fail(msg);
        }

        extSecCtx.log(CLASSNAME + "#consumeX509BoundSAML");
        logger.debug(extSecCtx.toString(true));  // verbose
    }
}
