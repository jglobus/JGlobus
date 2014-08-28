package org.globus.gsi.provider.simple;

import org.globus.gsi.provider.simple.SimpleMemoryKeyStore;
import org.globus.gsi.provider.simple.SimpleMemoryKeyStoreLoadStoreParameter;

import org.junit.Before;

import java.util.Enumeration;

import org.globus.util.GlobusPathMatchingResourcePatternResolver;

import java.security.cert.CertificateFactory;
import org.junit.AfterClass;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;
import org.junit.BeforeClass;
import java.security.cert.X509Certificate;
import org.junit.Test;

import static org.junit.Assert.*;

public class SimpleMemoryKeyStoreTest {

    private static X509Certificate cert;
    private SimpleMemoryKeyStore store;

    @BeforeClass
    public static void loadBouncyCastleProvider() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) factory.generateCertificate(
            new GlobusPathMatchingResourcePatternResolver().getResource("classpath:/validatorTest/testca.pem").getInputStream());
    }

    @Before
    public void setUp() throws Exception {
        SimpleMemoryKeyStoreLoadStoreParameter params = new SimpleMemoryKeyStoreLoadStoreParameter();
        this.store = new SimpleMemoryKeyStore();
        this.store.engineLoad(params);
    }

    @Test
    public void testEngineSize() throws Exception {
        assertEquals(0, store.engineSize());
        store.engineSetCertificateEntry(cert.getSubjectDN().getName(), cert);
        assertEquals(1, store.engineSize());
    }

    @Test
    public void testEngineAliases() throws Exception {
        assertFalse(store.engineAliases().hasMoreElements());
        store.engineSetCertificateEntry(cert.getSubjectDN().getName(), cert);
        Enumeration e = store.engineAliases();
        assertEquals(cert.getSubjectDN().getName(), e.nextElement());
        assertFalse(e.hasMoreElements());
    }

    @Test
    public void testEngineContainsAliasString() throws Exception {
        assertFalse(store.engineContainsAlias(cert.getSubjectDN().getName()));
        store.engineSetCertificateEntry(cert.getSubjectDN().getName(), cert);
        store.engineSetCertificateEntry("test", cert);
        assertTrue(store.engineContainsAlias(cert.getSubjectDN().getName()));
        assertTrue(store.engineContainsAlias("test"));
    }

    @Test
    public void testEngineDeleteEntryString() throws Exception {
        assertEquals(0, store.engineSize());
        store.engineSetCertificateEntry(cert.getSubjectDN().getName(), cert);
        assertEquals(1, store.engineSize());
        store.engineDeleteEntry(cert.getSubjectDN().getName());
        assertEquals(0, store.engineSize());
    }

    @Test
    public void testEngineGetCertificateString() throws Exception {
        assertNull(store.engineGetCertificate(cert.getSubjectDN().getName()));
        store.engineSetCertificateEntry(cert.getSubjectDN().getName(), cert);
        assertEquals(cert, store.engineGetCertificate(cert.getSubjectDN().getName()));
    }

    @Test
    public void testEngineIsCertificateEntryString() throws Exception {
        assertFalse(store.engineIsCertificateEntry(cert.getSubjectDN().getName()));
        store.engineSetCertificateEntry(cert.getSubjectDN().getName(), cert);
        assertTrue(store.engineIsCertificateEntry(cert.getSubjectDN().getName()));
    }

    @Test
    public void testEngineIsKeyEntryString() throws Exception {
        assertFalse(null, store.engineIsCertificateEntry(cert.getSubjectDN().getName()));
        store.engineSetCertificateEntry(cert.getSubjectDN().getName(), cert);
        assertFalse(store.engineIsKeyEntry(cert.getSubjectDN().getName()));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testEngineStoreOutputStreamCharArray() throws Exception {
        store.engineStore(null);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testEngineSetKeyEntryStringByteArrayCertificateArray() throws Exception {
        store.engineSetKeyEntry(null,null,null);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testEngineSetKeyEntryStringKeyCharArrayCertificateArray() throws Exception {
        store.engineSetKeyEntry(null, null, null);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testEngineLoadInputStreamCharArray() throws Exception {
        store.engineLoad(null,new char[3]);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testEngineGetCertificateAliasCertificate() throws Exception {
        store.engineGetCertificateAlias(cert);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testEngineGetCertificateChainString() throws Exception {
        store.engineGetCertificateChain("test");
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testEngineGetCreationDateString() throws Exception {
        store.engineGetCreationDate("test");
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testEngineGetKeyStringCharArray() throws Exception {
        store.engineGetKey("test", new char[] {'t'});
    }

}
