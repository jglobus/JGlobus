/*
 * Copyright 1999-2010 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS,WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */
package org.globus.gsi.gssapi.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;

import java.security.cert.X509Certificate;
import java.util.Date;
import javax.security.auth.x500.X500Principal;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSCredential;

import org.gridforum.jgss.ExtendedGSSManager;
import org.gridforum.jgss.ExtendedGSSCredential;

import org.globus.gsi.gssapi.GlobusGSSCredentialImpl;
import org.globus.gsi.gssapi.GlobusGSSManagerImpl;
import org.globus.gsi.gssapi.GlobusGSSException;
import org.globus.gsi.gssapi.GSSConstants;

import junit.framework.TestCase;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.globus.gsi.X509Credential;

public class GlobusGSSCredentialTest extends TestCase {

    private static final X500Principal SELF_SIGNED_DN =
                new X500Principal("DC=self-signed,DC=example,DC=org");

    private ExtendedGSSManager manager;
    private Log logger = LogFactory.getLog(GlobusGSSCredentialTest.class);
    private X509V3CertificateGenerator certificateGenerator;
    private KeyPairGenerator kpg;

    @Override
    protected void setUp() throws Exception {
	manager = new GlobusGSSManagerImpl();
        kpg = KeyPairGenerator.getInstance("RSA");
        certificateGenerator = new X509V3CertificateGenerator();
        certificateGenerator.setIssuerDN(SELF_SIGNED_DN);
        certificateGenerator.setSubjectDN(SELF_SIGNED_DN);
        certificateGenerator.setNotBefore(new Date());
        certificateGenerator.setNotAfter(new Date(System.currentTimeMillis()+1000*60));
        certificateGenerator.setSerialNumber(BigInteger.ONE);
        certificateGenerator.setSignatureAlgorithm("SHA1WithRSA");
    }

    public void testImportBadFile() throws Exception {
	String handle = "PROXY = /a/b/c";

	try {
	    manager.createCredential(handle.getBytes(),
				     ExtendedGSSCredential.IMPEXP_MECH_SPECIFIC,
				     GSSCredential.DEFAULT_LIFETIME,
				     null,
				     GSSCredential.ACCEPT_ONLY);
	    fail("Exception not thrown as expected.");
	} catch (GSSException e) {
	    // TODO: check for specific major/minor code
	}

    }

    public void testImportBadOption() throws Exception {
	String handle = "PROXY = /a/b/c";

	try {
	    manager.createCredential(handle.getBytes(),
				     3,
				     GSSCredential.DEFAULT_LIFETIME,
				     null,
				     GSSCredential.ACCEPT_ONLY);
	    fail("Exception not thrown as expected.");
	} catch (GSSException e) {
	    if (e.getMajor() != GSSException.FAILURE &&
		e.getMinor() != GlobusGSSException.BAD_ARGUMENT) {
		e.printStackTrace();
		fail("Unexpected exception");
	    }
	}

    }

    public void testImportExportOpaque() throws Exception {

	GlobusGSSCredentialImpl cred =
	    (GlobusGSSCredentialImpl)manager.createCredential(GSSCredential.ACCEPT_ONLY);
	assertTrue(cred != null);

	byte [] data = cred.export(ExtendedGSSCredential.IMPEXP_OPAQUE);
	assertTrue(data != null);

	logger.debug(new String(data));

	GlobusGSSCredentialImpl cred2 =
	    (GlobusGSSCredentialImpl)manager.createCredential(data,
							      ExtendedGSSCredential.IMPEXP_OPAQUE,
							      GSSCredential.DEFAULT_LIFETIME,
							      null,
							      GSSCredential.ACCEPT_ONLY);
	assertTrue(cred2 != null);
	assertEquals(cred.getPrivateKey(), cred2.getPrivateKey());
    }

    public void testImportExportMechSpecific() throws Exception {

	GlobusGSSCredentialImpl cred =
	    (GlobusGSSCredentialImpl)manager.createCredential(GSSCredential.ACCEPT_ONLY);
	assertTrue(cred != null);

	byte [] data = cred.export(ExtendedGSSCredential.IMPEXP_MECH_SPECIFIC);
	assertTrue(data != null);

	String handle = new String(data);
	logger.debug(handle);

	GlobusGSSCredentialImpl cred2 =
	    (GlobusGSSCredentialImpl)manager.createCredential(data,
							      ExtendedGSSCredential.IMPEXP_MECH_SPECIFIC,
							      GSSCredential.DEFAULT_LIFETIME,
							      null,
							      GSSCredential.ACCEPT_ONLY);
	assertTrue(cred2 != null);

	assertEquals(cred.getPrivateKey(), cred2.getPrivateKey());

	handle = handle.substring(handle.indexOf('=')+1);
	assertTrue((new File(handle)).delete());
    }

    public void testInquireByOid() throws Exception {

	ExtendedGSSCredential cred =
	    (ExtendedGSSCredential)manager.createCredential(GSSCredential.ACCEPT_ONLY);

	Object tmp = null;
	X509Certificate[] chain = null;

	tmp = cred.inquireByOid(GSSConstants.X509_CERT_CHAIN);
	assertTrue(tmp != null);
	assertTrue(tmp instanceof X509Certificate[]);
	chain = (X509Certificate[])tmp;
	assertTrue(chain.length > 0);
    }

    public void testSerialisation() throws Exception {
        GSSCredential cred = manager.createCredential(GSSCredential.ACCEPT_ONLY);
        GSSCredential copy = serialiseAndDeserialise(cred);
        assertThat(copy, equalTo(cred));
    }

    public void testEqualsForNull() throws GSSException {
        GSSCredential credential =
                manager.createCredential(GSSCredential.ACCEPT_ONLY);
        assertThat(credential, not(equalTo(null)));
    }

    public void testEqualsReflexive() throws GSSException {
        GSSCredential credential =
                manager.createCredential(GSSCredential.ACCEPT_ONLY);
        assertThat(credential, equalTo(credential));
    }

    public void testEqualsForSameCredential() throws GSSException {
        GSSCredential cred1 = manager.createCredential(GSSCredential.ACCEPT_ONLY);
        GSSCredential cred2 = manager.createCredential(GSSCredential.ACCEPT_ONLY);
        assertThat(cred1, equalTo(cred2));
        assertThat(cred2, equalTo(cred1));
    }

    public void testEqualsForDifferentUsage() throws GSSException {
        GSSCredential cred1 = manager.createCredential(GSSCredential.ACCEPT_ONLY);
        GSSCredential cred2 = manager.createCredential(GSSCredential.DEFAULT_LIFETIME);
        assertThat(cred1, not(equalTo(cred2)));
        assertThat(cred2, not(equalTo(cred1)));
    }

    public void testEqualsForEqualX509Credential() throws Exception {
        X509Credential x509 = buildSelfSigned();

        GSSCredential cred1 =
                buildCredential(x509, GSSCredential.DEFAULT_LIFETIME);

        GSSCredential cred2 =
                buildCredential(x509, GSSCredential.DEFAULT_LIFETIME);

        assertThat(cred1, equalTo(cred2));
        assertThat(cred2, equalTo(cred1));
    }

    public void testEqualsForDifferentX509Credentials() throws Exception {
        GSSCredential cred1 =
                buildSelfSigned(GSSCredential.DEFAULT_LIFETIME);
        GSSCredential cred2 =
                buildSelfSigned(GSSCredential.DEFAULT_LIFETIME);

        assertThat(cred1, not(equalTo(cred2)));
        assertThat(cred2, not(equalTo(cred1)));
    }

    private GSSCredential buildSelfSigned(int usage) throws GeneralSecurityException, GSSException {
        return buildCredential(buildSelfSigned(), usage);
    }

    private GSSCredential buildCredential(X509Credential credential, int usage) throws GSSException {
        X509Credential.setDefaultCredential(credential);
        return manager.createCredential(usage);
    }

    private X509Credential buildSelfSigned() throws GeneralSecurityException {
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey privateKey = kp.getPrivate();
        certificateGenerator.setPublicKey(kp.getPublic());
        X509Certificate certificate = certificateGenerator.generate(privateKey);
        X509Certificate[] certChain = new X509Certificate[]{certificate};
        return new X509Credential(privateKey, certChain);
    }

    private GlobusGSSCredentialImpl serialiseAndDeserialise(GSSCredential credential) throws IOException, ClassNotFoundException {
        if(!(credential instanceof GlobusGSSCredentialImpl)) {
            throw new RuntimeException("credential not a GlobusGSSCredentialImpl");
        }
        ByteArrayOutputStream storage = new ByteArrayOutputStream();
        new ObjectOutputStream(storage).writeObject(credential);
        byte[] data = storage.toByteArray();

        ObjectInputStream in =
                new ObjectInputStream(new ByteArrayInputStream(data));
        return (GlobusGSSCredentialImpl) in.readObject();
    }
}
