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

package org.teragrid.ncsa.gridshib.security.util;

import javax.security.auth.Subject;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.saml.SAMLToolsTestCase;
import org.globus.gridshib.security.SAMLIdentity;
import org.globus.gridshib.security.SecurityContext;
import org.globus.gridshib.security.SecurityContextFactory;

import org.teragrid.ncsa.gridshib.security.GatewaySecurityContext;

/**
 * @since 0.5.1
 */
public class SAMLUtilTest extends SAMLToolsTestCase {

    private static final Class CLASS = SAMLUtilTest.class;
    private static final String CLASSNAME = CLASS.getName();

    private static Log logger = LogFactory.getLog(CLASSNAME);

    private Subject subject = null;
    private GatewaySecurityContext gwSecCtx = null;

    private static String[] args = new String[]{};

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CLASS);
        SAMLUtilTest.args = args;
    }

    public SAMLUtilTest(String name) {
        super(name);
    }

    /**
     * @see TestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();

        GatewaySecurityContext.init();
        subject = new Subject();
        SecurityContext secCtx = SecurityContextFactory.getInstance(subject);
        assertTrue("Security context is null", secCtx != null);
        assertTrue("Security context is not an instance of " +
                   "GatewaySecurityContext",
                   secCtx instanceof GatewaySecurityContext);

        gwSecCtx = (GatewaySecurityContext)secCtx;
    }

    /**
     * @see TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    public void testGetGatewayIdentity() throws Exception {

        logger.debug("Testing getGatewayIdentity method...");

        SAMLIdentity[] identities;
        int n;
        String id;

        // test no SAMLIdentities:
        identities = gwSecCtx.getSAMLIdentities();
        assertTrue("SAMLIdentities is null", identities != null);
        n = identities.length;
        assertTrue("Wrong number of SAMLIdentities: " + n, n == 0);
        id = SAMLUtil.getGatewayIdentity(subject);
        assertTrue("Gateway identity is not null", id == null);

        // test an untrusted SAMLIdentity:
        if (!gwSecCtx.addUntrustedSAMLIdentity()) {
            fail("Unable to add untrusted SAMLIdentity");
        }
        identities = gwSecCtx.getSAMLIdentities();
        assertTrue("SAMLIdentities is null", identities != null);
        n = identities.length;
        assertTrue("Wrong number of SAMLIdentities: " + n, n == 1);
        id = SAMLUtil.getGatewayIdentity(subject);
        assertTrue("Gateway identity is not null", id == null);

        // test an irrelevant (non-gateway) SAMLIdentity:
        if (!gwSecCtx.addNonGatewaySAMLIdentity()) {
            fail("Unable to add non-gateway SAMLIdentity");
        }
        identities = gwSecCtx.getSAMLIdentities();
        assertTrue("SAMLIdentities is null", identities != null);
        n = identities.length;
        assertTrue("Wrong number of SAMLIdentities: " + n, n == 2);
        id = SAMLUtil.getGatewayIdentity(subject);
        assertTrue("Gateway identity is not null", id == null);

        // test a bona fide gateway SAMLIdentity:
        if (!gwSecCtx.addGatewaySAMLIdentity()) {
            fail("Unable to add gateway SAMLIdentity");
        }
        identities = gwSecCtx.getSAMLIdentities();
        assertTrue("SAMLIdentities is null", identities != null);
        n = identities.length;
        assertTrue("Wrong number of SAMLIdentities: " + n, n == 3);
        id = SAMLUtil.getGatewayIdentity(subject);
        assertTrue("Gateway identity is null", id != null);
    }
}
