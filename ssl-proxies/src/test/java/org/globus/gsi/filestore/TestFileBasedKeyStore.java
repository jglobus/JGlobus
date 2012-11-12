package org.globus.gsi.filestore;

import java.security.KeyStore;

import org.globus.gsi.provider.GlobusProvider;
import org.junit.Test;

public class TestFileBasedKeyStore {
	@Test
    public void testLoadEmptyStore() throws Exception {
		KeyStore keyStore = KeyStore.getInstance(GlobusProvider.KEYSTORE_TYPE);
		boolean worked = false;
		try{
			keyStore.load(null, null);
			worked = true;
		}catch(Exception e){
			//Error...
		}
		assert (worked == true);
	}
}
