/*
* Copyright 1999-2010 University of Chicago
*
* Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
* compliance with the License. You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software distributed under the License is
* distributed on an "AS IS" BASIS,WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
* express or implied.
*
* See the License for the specific language governing permissions and limitations under the License.
*/
package org.globus.gsi.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.apache.commons.io.FileUtils;
import org.globus.gsi.testutils.DirSetupUtil;
import org.globus.gsi.testutils.FileSetupUtil;
import org.globus.gsi.util.CertificateLoadUtil;

import org.globus.gsi.stores.PEMKeyStore;
//import org.globus.gsi.stores.PEMKeyStoreParameters;

import org.globus.gsi.X509Credential;

import org.globus.gsi.provider.GlobusProvider;
import org.globus.gsi.provider.KeyStoreParametersFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.KeyStore.LoadStoreParameter;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Vector;

import org.globus.util.GlobusResource;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
* FILL ME
*
* @author ranantha@mcs.anl.gov
*/
public class TestPEMFileBasedKeyStore {

    DirSetupUtil trustedDirectory;
    DirSetupUtil defaultTrustedDirectory;
    Vector<X509Certificate> testTrustedCertificates = new Vector<X509Certificate>();
    FileSetupUtil proxyFile1;
    FileSetupUtil proxyFile2;
    FileSetupUtil certFile;
    FileSetupUtil keyFile;
    FileSetupUtil keyEncFile;

    Map<FileSetupUtil, X509Certificate> trustedCertificates = new HashMap<FileSetupUtil, X509Certificate>();
    Map<FileSetupUtil, X509Credential> proxyCertificates = new HashMap<FileSetupUtil, X509Credential>();

    @Before
    public void setUp() throws Exception {

        ClassLoader loader = TestPEMFileBasedKeyStore.class.getClassLoader();

        String[] trustedCertFilenames = new String[]{"testTrustStore/1c3f2ca8.0", "testTrustStore/b38b4d8c.0"};
        this.trustedDirectory = new DirSetupUtil(trustedCertFilenames);
        this.trustedDirectory.createTempDirectory();
        this.trustedDirectory.copy();
        for (String trustedCertFilename : trustedCertFilenames) {
            InputStream in = null;
            try {
                in = loader.getResourceAsStream(trustedCertFilename);
                if (in == null) {
                    throw new Exception("Unable to load: " + trustedCertFilename);
                }
                this.trustedCertificates.put(this.trustedDirectory.getFileSetupUtil(trustedCertFilename),
                        CertificateLoadUtil.loadCertificate(in));
            } finally {
                if (in != null) {
                    in.close();
                }
            }
        }

        String[] defaultTrustedCert = new String[]{"testTrustStore/d1b603c3.0"};
        this.defaultTrustedDirectory = new DirSetupUtil(defaultTrustedCert);
        this.defaultTrustedDirectory.createTempDirectory();
        this.defaultTrustedDirectory.copy();
        for (String aDefaultTrustedCert : defaultTrustedCert) {
            InputStream in = null;
            try {
                in = loader.getResourceAsStream(aDefaultTrustedCert);
                if (in == null) {
                    throw new Exception("Unable to load: " + aDefaultTrustedCert);
                }
                this.trustedCertificates.put(
                        this.defaultTrustedDirectory.getFileSetupUtil(aDefaultTrustedCert),
                        CertificateLoadUtil.loadCertificate(in));
            } finally {
                if (in != null) {
                    in.close();
                }
            }
        }


// String proxyFilename1 = "validatorTest/gsi2fullproxy.pem";
        String proxyFilename1 = "validatorTest/gsi3independentFromLimitedProxy.pem";
        this.proxyFile1 = new FileSetupUtil(proxyFilename1);
        this.proxyFile1.copyFileToTemp();
        this.proxyCertificates.put(this.proxyFile1,
                new X509Credential(loader.getResourceAsStream(proxyFilename1), loader.getResourceAsStream(proxyFilename1)));

        String proxyFilename2 = "validatorTest/gsi3FromPathOneProxy.pem";
        this.proxyFile2 = new FileSetupUtil(proxyFilename2);
        this.proxyFile2.copyFileToTemp();
        this.proxyCertificates.put(this.proxyFile2,
                new X509Credential(loader.getResourceAsStream(proxyFilename2),
                        loader.getResourceAsStream(proxyFilename2)));

        String certFilename = "validatorTest/testeec2.pem";
        this.certFile = new FileSetupUtil(certFilename);
        this.certFile.copyFileToTemp();
        String keyFilename = "validatorTest/testeec2-private.pem";
        this.keyFile = new FileSetupUtil(keyFilename);
        this.keyFile.copyFileToTemp();
        String keyEncFilename = "validatorTest/testeec2-private-enc.pem";
        this.keyEncFile = new FileSetupUtil(keyEncFilename);
        this.keyEncFile.copyFileToTemp();


        Security.addProvider(new GlobusProvider());
    }

    @Test
    public void testCreationDate() throws Exception {
        KeyStore store = KeyStore.getInstance("PEMFilebasedKeyStore", "Globus");

        // Parameters in properties file
        Properties properties = new Properties();
        properties.setProperty(PEMKeyStore.DEFAULT_DIRECTORY_KEY,
        		"file:"+ this.defaultTrustedDirectory.getTempDirectoryName());
        properties.setProperty(PEMKeyStore.DIRECTORY_LIST_KEY,
               "file:" + this.trustedDirectory.getTempDirectoryName() + "/*.0");

        InputStream ins = null;
        try {
            ins = getProperties(properties);
            store.load(ins, null);
        } finally {
            if (ins != null) {
                ins.close();
            }
        }
        Enumeration<String> aliases = store.aliases();
        if (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            assertNotNull(store.getCreationDate(alias));
        }
        assertNull(store.getCreationDate("FakeAlias"));

    }

    @Test
    public void testTrustedCerts() throws Exception {

        PEMKeyStore store = new PEMKeyStore();

        // Parameters in properties file
        Properties properties = new Properties();
        properties.setProperty(PEMKeyStore.DEFAULT_DIRECTORY_KEY,
        		"file:" + this.defaultTrustedDirectory.getTempDirectoryName());
        properties.setProperty(PEMKeyStore.DIRECTORY_LIST_KEY,
        		 "file:" + this.trustedDirectory.getTempDirectoryName() + "/*.0");

        InputStream ins = null;
        try {
            ins = getProperties(properties);
            store.engineLoad(ins, null);
        } finally {
            if (ins != null) {
                ins.close();
            }
        }
        testLoadedStore(store);
        Iterator<FileSetupUtil> iterator = this.trustedCertificates.keySet().iterator();
        FileSetupUtil util = iterator.next();
        testDelete(store, util.getTempFilename(), util);
    }

    @Test
    public void testParameterLoad() throws Exception {
        PEMKeyStore keystore = loadFromParameters();
        testLoadedStore(keystore);
    }

    private PEMKeyStore loadFromParameters() throws Exception {
        LoadStoreParameter params = KeyStoreParametersFactory.createTrustStoreParameters(
        		"file:" + this.trustedDirectory.getTempDirectoryName(),
                "file:" + this.defaultTrustedDirectory.getTempDirectoryName()
        );
        PEMKeyStore keystore = new PEMKeyStore();
        keystore.engineLoad(params);
        return keystore;
    }

    private void testLoadedStore(PEMKeyStore store) throws KeyStoreException {
        Enumeration aliases = store.engineAliases();
        assertTrue(aliases.hasMoreElements());

        // alias to certificate test to be added.
        Iterator<FileSetupUtil> iterator = this.trustedCertificates.keySet().iterator();
        String alias;
        FileSetupUtil util;
        while (iterator.hasNext()) {
            util = iterator.next();
            alias = util.getTempFile().toURI().toASCIIString();
            assertTrue(store.engineIsCertificateEntry(alias));
            Certificate certificate = store.engineGetCertificate(alias);
            assertNotNull(certificate);
            assertEquals(certificate, this.trustedCertificates.get(util));
            String storeAlias = store.engineGetCertificateAlias(certificate);
            assertEquals(alias, storeAlias);
        }
        assertFalse(store.engineIsCertificateEntry("FakeCert"));
    }

    private void testDelete(PEMKeyStore store, String alias, FileSetupUtil util) throws Exception {
        // test delete
        store.engineDeleteEntry(alias);

        assertNull(store.engineGetCertificate(alias));
        assertNotNull(util);
        File tempFile = util.getTempFile();
        assertNotNull(tempFile);
    }

    @Test
    public void testProxyCerts() throws Exception {

        PEMKeyStore store = new PEMKeyStore();
        // Parameters in properties file
        Properties properties = new Properties();
        properties.setProperty(PEMKeyStore.PROXY_FILENAME,
                "file:"+ this.proxyFile1.getAbsoluteFilename());

        InputStream ins = null;
        try {
            ins = getProperties(properties);
            store.engineLoad(ins, null);
        } finally {
            if (ins != null) {
                ins.close();
            }
        }

        Enumeration aliases = store.engineAliases();
        assert (aliases.hasMoreElements());
        // proxy file 1
        String proxyId1 = new GlobusResource(this.proxyFile1.getTempFile().getAbsolutePath()).getFile().toString();//getURL().toExternalForm();
        Key key = store.engineGetKey("file:"+ this.proxyFile1.getAbsoluteFilename(), null);

        assertTrue(store.engineIsKeyEntry("file:"+ this.proxyFile1.getAbsoluteFilename()));
        assertNotNull(key != null);
        assertTrue(key instanceof PrivateKey);
        Certificate[] certificates = store.engineGetCertificateChain(this.proxyFile1.getURL().toExternalForm());
        assertNotNull(certificates != null);
        assertTrue(certificates instanceof X509Certificate[]);
        key = null;

        // assert (this.proxyCertificates.get(this.proxyFile1.getAbsoluteFilename()).equals(certificates[0]));

        properties.setProperty(PEMKeyStore.PROXY_FILENAME,
                "file:" + this.proxyFile2.getAbsoluteFilename());
        ins = null;
        try {
            ins = getProperties(properties);
            store.engineLoad(ins, null);
        } finally {
            if (ins != null) {
                ins.close();
            }
        }
        // proxy file 2
        String proxyId2 = new GlobusResource(this.proxyFile2.getTempFile().getAbsolutePath()).getURL().toExternalForm();
        key = store.engineGetKey("file:" + this.proxyFile2.getAbsoluteFilename(), null);
        assertTrue(store.engineIsKeyEntry("file:" + this.proxyFile2.getAbsoluteFilename()));
        assertNotNull(key);
        assertTrue(key instanceof PrivateKey);

        certificates = store.engineGetCertificateChain(proxyId1);
        assertNotNull(certificates != null);
        assertTrue(certificates instanceof X509Certificate[]);

// assert (this.proxyCertificates.get(this.proxyFile2.getTempFilename()).equals(certificates[0]));


        // test delete
        store.engineDeleteEntry(proxyId1);

        certificates = store.engineGetCertificateChain(proxyId1);
        assertEquals(0, certificates.length);
        assertFalse((new File("file:"+ this.proxyFile1.getAbsoluteFilename())).exists());
        assertFalse(store.engineIsKeyEntry(proxyId1));

    }

    @Test
    public void testUserCerts() throws Exception {
        PEMKeyStore store = new PEMKeyStore();
        // Parameters in properties file
        Properties properties = new Properties();
        properties.setProperty(PEMKeyStore.CERTIFICATE_FILENAME, new GlobusResource(
                this.certFile.getTempFile().getAbsolutePath()).getURL().toExternalForm());
        properties.setProperty(PEMKeyStore.KEY_FILENAME, new GlobusResource(this.keyFile.getTempFile().getAbsolutePath())
                .getURL().toExternalForm());
        InputStream ins = null;
        try {
            ins = getProperties(properties);
            store.engineLoad(ins, null);
        } finally {
            if (ins != null) {
                ins.close();
            }
        }
        Enumeration aliases = store.engineAliases();
        assertTrue(aliases.hasMoreElements());
        String alias = (String) aliases.nextElement();
        Key key = store.engineGetKey(alias, null);
        assertNotNull(key);
        assertTrue(key instanceof PrivateKey);

        Certificate[] chain = store.engineGetCertificateChain(alias);
        assertNotNull(chain);

        Certificate certificate = store.engineGetCertificate(alias);
        assertNull(certificate);

        X509Credential x509Credential = new X509Credential(new FileInputStream(this.certFile.getAbsoluteFilename()),
                new FileInputStream(this.keyFile.getAbsoluteFilename()));

        assertEquals(key, x509Credential.getPrivateKey());
        Certificate[] x509CredentialChain = x509Credential.getCertificateChain();
        assertEquals(chain.length, x509CredentialChain.length);
        for (int i = 0; i < chain.length; i++) {
            assert (chain[i].equals(x509CredentialChain[i]));
        }

        store = new PEMKeyStore();
        properties.setProperty(PEMKeyStore.CERTIFICATE_FILENAME,
                new GlobusResource(this.certFile.getTempFile().getAbsolutePath()).getURL().toExternalForm());
        properties.setProperty(PEMKeyStore.KEY_FILENAME,
                new GlobusResource(this.keyEncFile.getTempFile().getAbsolutePath()).getURL().toExternalForm());
        try {
            ins = getProperties(properties);
            store.engineLoad(ins, null);
        } finally {
            if (ins != null) {
                ins.close();
            }
        }
        aliases = store.engineAliases();
        assert (aliases.hasMoreElements());
        alias = (String) aliases.nextElement();

        try {
            store.engineGetKey(alias, null);
            fail();
        } catch (UnrecoverableKeyException e) {
            //this had better fail
        }
        key = store.engineGetKey(alias, "test".toCharArray());
        assertNotNull(key);
        assertTrue(key instanceof PrivateKey);
        chain = store.engineGetCertificateChain(alias);
        assertNotNull(chain);
    }

    private InputStream getProperties(Properties properties) throws Exception {

        ByteArrayOutputStream stream = null;
        ByteArrayInputStream ins = null;

        try {
            stream = new ByteArrayOutputStream();
            properties.store(stream, "Test Properties");

            // load all the CA files
            ins = new ByteArrayInputStream(stream.toByteArray());

        } finally {
            if (stream != null) {
                stream.close();
            }
        }
        return ins;
    }
    public static boolean deleteDir(File dir) {
		if (dir.isDirectory()) {
			String[] dirContent = dir.list();
			for (int i=0; i<dirContent.length; i++){
				boolean success = deleteDir(new File(dir, dirContent[i]));
				if (!success) {
					return false;
				}
			}
		} // The directory is now empty so delete it
		return dir.delete();
	}
    @After
    public void tearDown() throws Exception {

        deleteDir(new File(trustedDirectory.getTempDirectoryName()));
        this.proxyFile1.deleteFile();
        this.proxyFile2.deleteFile();
        this.certFile.deleteFile();
        this.keyFile.deleteFile();
        this.keyEncFile.deleteFile();
    }
}