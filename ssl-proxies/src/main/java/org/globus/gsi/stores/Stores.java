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

package org.globus.gsi.stores;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertStore;
import java.util.HashMap;

import org.globus.common.CoGProperties;
import org.globus.gsi.provider.GlobusProvider;
import org.globus.gsi.provider.KeyStoreParametersFactory;

/**
 * @author Jerome Revillard
 *
 */
public class Stores {
	private static String defaultCAFilesPattern = "*.0";
	private static String defaultCRLFilesPattern = "*.r*";
	private static String defaultSigningPolicyFilesPattern = "*.signing_policy";
	
	private static final HashMap<String, KeyStore> TRUST_STORES = new HashMap<String, KeyStore>();
	private static final HashMap<String, CertStore> CRL_STORES = new HashMap<String, CertStore>();
	private static final HashMap<String, CertStore> CA_CERT_STORES = new HashMap<String, CertStore>();
	private static final HashMap<String, ResourceSigningPolicyStore> SIGNING_POLICY_STORES = new HashMap<String, ResourceSigningPolicyStore>();
	
	
	public static KeyStore getDefaultTrustStore() throws  GeneralSecurityException, IOException {
		String pattern = "file:" + CoGProperties.getDefault().getCaCertLocations() + "/" + defaultCAFilesPattern;
	    return getTrustStore(pattern);
    }
	
	public static KeyStore getTrustStore(String casLocationPattern) throws  GeneralSecurityException, IOException {
		synchronized (TRUST_STORES) {
			KeyStore keyStore = TRUST_STORES.get(casLocationPattern);
			if(keyStore != null){
				return keyStore;
			}
	        keyStore = KeyStore.getInstance(GlobusProvider.KEYSTORE_TYPE, GlobusProvider.PROVIDER_NAME);
	        keyStore.load(KeyStoreParametersFactory.createTrustStoreParameters(casLocationPattern));
	        
	        TRUST_STORES.put(casLocationPattern, keyStore);
	        return keyStore;
		}
    }
    
    public static CertStore getDefaultCACertStore() throws GeneralSecurityException, NoSuchAlgorithmException {
    	String pattern = "file:" + CoGProperties.getDefault().getCaCertLocations() + "/" + defaultCAFilesPattern;
    	return getCACertStore(pattern);
    }
    
    
	public static CertStore getCACertStore(String casLocationPattern) throws GeneralSecurityException, NoSuchAlgorithmException {
    	synchronized (CA_CERT_STORES) {
	    	CertStore caStore = CA_CERT_STORES.get(casLocationPattern);
			if(caStore != null){
				return caStore;
			}
			caStore = CertStore.getInstance(GlobusProvider.CERTSTORE_TYPE, new ResourceCertStoreParameters(casLocationPattern, null));
	        
	        CA_CERT_STORES.put(casLocationPattern, caStore);
	        
	        return caStore;
    	}
    }
    
    public static CertStore getDefaultCRLStore() throws GeneralSecurityException, NoSuchAlgorithmException {
    	String pattern = "file:" + CoGProperties.getDefault().getCaCertLocations() + "/" + defaultCRLFilesPattern;
    	return getCRLStore(pattern);
    }
    
    public static CertStore getCRLStore(String crlsLocationPattern) throws GeneralSecurityException, NoSuchAlgorithmException {
    	synchronized (CRL_STORES) {
	    	CertStore crlStore = CRL_STORES.get(crlsLocationPattern);
			if(crlStore != null){
				return crlStore;
			}
	        crlStore = CertStore.getInstance(GlobusProvider.CERTSTORE_TYPE, new ResourceCertStoreParameters(null, crlsLocationPattern));
	        
	        CRL_STORES.put(crlsLocationPattern, crlStore);
	        
	        return crlStore;
    	}
    }
    
    public static ResourceSigningPolicyStore getDefaultSigningPolicyStore() throws GeneralSecurityException {
    	String pattern = "file:" + CoGProperties.getDefault().getCaCertLocations() + "/" + defaultSigningPolicyFilesPattern;
    	return getSigningPolicyStore(pattern);
    }
    
    public static ResourceSigningPolicyStore getSigningPolicyStore(String signingPolicyLocationPattern) throws GeneralSecurityException {
    	synchronized (SIGNING_POLICY_STORES) {
    		ResourceSigningPolicyStore signingPolicyStore = SIGNING_POLICY_STORES.get(signingPolicyLocationPattern);
			if(signingPolicyStore != null){
				return signingPolicyStore;
			}
	        signingPolicyStore = new ResourceSigningPolicyStore(new ResourceSigningPolicyStoreParameters(signingPolicyLocationPattern));
	        
	        SIGNING_POLICY_STORES.put(signingPolicyLocationPattern, signingPolicyStore) ;
	        
	        return signingPolicyStore;
    	}
    }
    
	public static String getDefaultCAFilesPattern() {
		return defaultCAFilesPattern;
	}

	public static void setDefaultCAFilesPattern(String defaultCAFilesPattern) {
		if(defaultCAFilesPattern == null || Stores.defaultCAFilesPattern.equals(defaultCAFilesPattern)){
			return;
		}
		synchronized (TRUST_STORES) {
			synchronized (CA_CERT_STORES) {
				Stores.defaultCAFilesPattern = defaultCAFilesPattern;
				//Clear if we change the default pattern to prevent potential memory issue;
				TRUST_STORES.clear();
				CA_CERT_STORES.clear();
			}
		}
	}

	public static String getDefaultCRLFilesPattern() {
		return defaultCRLFilesPattern;
	}

	public static void setDefaultCRLFilesPattern(String defaultCRLFilesPattern) {
		if(defaultCRLFilesPattern == null || Stores.defaultCRLFilesPattern.equals(defaultCRLFilesPattern)){
			return;
		}
		synchronized (CRL_STORES) {
			Stores.defaultCRLFilesPattern = defaultCRLFilesPattern;
			//Clear if we change the default pattern to prevent potential memory issue;
			CRL_STORES.clear();
		}
	}

	public static String getDefaultSigningPolicyFilesPattern() {
		return defaultSigningPolicyFilesPattern;
	}

	public static void setDefaultSigningPolicyFilesPattern(String defaultSigningPolicyFilesPattern) {
		if(defaultSigningPolicyFilesPattern == null || Stores.defaultSigningPolicyFilesPattern.equals(defaultSigningPolicyFilesPattern)){
			return;
		}
		synchronized (SIGNING_POLICY_STORES) {
			Stores.defaultSigningPolicyFilesPattern = defaultSigningPolicyFilesPattern;
			//Clear if we change the default pattern to prevent potential memory issue;
			SIGNING_POLICY_STORES.clear();
		}
	}

}
