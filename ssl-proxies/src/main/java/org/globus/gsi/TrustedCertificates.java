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
package org.globus.gsi;

import org.globus.gsi.util.CertificateUtil;
import org.globus.gsi.util.KeyStoreUtil;

import org.globus.gsi.stores.ResourceSigningPolicyStore;
import org.globus.gsi.stores.ResourceSigningPolicyStoreParameters;

import org.globus.gsi.provider.GlobusProvider;
import org.globus.gsi.provider.KeyStoreParametersFactory;

import javax.security.auth.x500.X500Principal;
import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;
import java.security.KeyStore;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.HashMap;
import java.util.HashSet;
import java.util.StringTokenizer;
import java.util.Collection;
import java.util.Iterator;
import java.io.File;
import java.io.FilenameFilter;
import org.globus.common.CoGProperties;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import java.io.Serializable;
import java.io.IOException;

// COMMENT: What is the replacement for this?
// COMMENT: We lost the refresh functionality: Currently an entirely new store is loaded upon load()
/**
 * Class that reads in and maintains trusted certificates and signing
 * policy associated with the CAs.
 * @deprecated
 */
public class TrustedCertificates implements Serializable {
    
    private static Log logger =
        LogFactory.getLog(TrustedCertificates.class.getName());

    static {
        new ProviderLoader();
    }
    
    public static final CertFilter certFileFilter = new CertFilter();
    private static TrustedCertificates trustedCertificates = null;

    // DN is in the format in certificates
    private Map certSubjectDNMap;

    // DN is in Globus format here, without any reversal.
    private Map policyDNMap;

    // Vector of X.509 Certificate objects
    private Vector certList;

    private final Set<X500Principal> invalidPolicies = new HashSet<X500Principal>();

    private boolean changed;

    /**
     * Default signing policy suffix. The files are expected to be
     * <caHash>.signing_policy in the same directory as the trusted 
     * certificates.
     */
    public static String SIGNING_POLICY_FILE_SUFFIX = ".signing_policy";
    private static KeyStore ms_trustStore = null;
//    private static CertStore ms_crlStore = null;
    private static ResourceSigningPolicyStore ms_sigPolStore = null;
    

    
    protected TrustedCertificates() {}
    
    public TrustedCertificates(X509Certificate [] certs) {
        this(certs, null);
    }

    public TrustedCertificates(X509Certificate [] certs,
                               SigningPolicy[] policies) {

        // JGLOBUS-91 
        this.certSubjectDNMap = new HashMap();
        for (int i=0;i<certs.length;i++) {
            if (certs[i] != null) {
                String dn = certs[i].getSubjectDN().toString();
                this.certSubjectDNMap.put(dn,certs[i]);
            }
        }
        
        if (policies != null) {
            this.policyDNMap = new HashMap();        
            for (int i=0; i<policies.length; i++) {
                if (policies[i] != null) {
                    this.policyDNMap.put(CertificateUtil.toGlobusID(policies[i].getCASubjectDN()), policies[i]);
                }
            }
        }
    }

    // COMMENT: BCB: removed getX509CertList() which used PureTLS. Needed by GlobusGSSContextImpl
    // so moved some things over to there

    public X509Certificate[] getCertificates() {
        if (this.certSubjectDNMap == null) {
            return null;
        }
        Collection certs = this.certSubjectDNMap.values();
        return (X509Certificate[]) certs.toArray(new X509Certificate[certs.size()]);
    }
    
    public X509Certificate getCertificate(String subject) {
        if (this.certSubjectDNMap == null) {
            return null;
        }
        return (X509Certificate)this.certSubjectDNMap.get(subject);
    }

    /**
     * Returns all signing policies 
     */
    public SigningPolicy[] getSigningPolicies() {
        if (this.policyDNMap == null) {
            return null;
        }
        Collection values = this.policyDNMap.values();
        return (SigningPolicy[]) this.policyDNMap.values().toArray(new SigningPolicy[values.size()]);
    }

    /**
     * Returns signing policy associated with the given CA subject.
     * 
     * @param subject
     *        CA's subject DN for which signing policy is
     *        required. The DN should be in Globus format (with slashes) and
     *        not reversed. See CertificateUtil.toGlobusID();
     * @return 
     *        Signing policy object associated with the CA's DN. Null
     *        if no policy was configured. SigningPolicy object might not
     *        have any applicable policy if none was configured or none was
     *        found in the policy file configured.
     */
    public SigningPolicy getSigningPolicy(String subject) {
        
        if (this.policyDNMap == null) {
            return null;
        }
        return (SigningPolicy) this.policyDNMap.get(subject);
    }

    /** 
     * Loads X509 certificates and signing policy files from specified 
     * locations. The locations can be either files or
     * directories. The directories will be automatically traversed
     * and all files in the form of <i>hashcode.number</i> and will be
     * loaded automatically as trusted certificates. An attempt will
     * be made to load signing policy for the CA associated with
     * that hashcode from <hashcode>.signing_policy. If policy file is
     * not found, no error will be thrown, only path validation code
     * enforces the signing policy requirement.
     *
     * @param locations a list of certificate files/directories to load 
     *                  the certificates from. The locations are comma 
     *                  separated.
     *
     * @return <code>java.security.cert.X509Certificate</code> an array 
     *         of loaded certificates
     */    
    public static X509Certificate[] loadCertificates(String locations) {
        TrustedCertificates tc = TrustedCertificates.load(locations);
        return (tc == null) ? null : tc.getCertificates();
    }

    public static TrustedCertificates load(String locations) {
        TrustedCertificates tc = new TrustedCertificates();
        tc.reload(locations);
        return tc;
    }

    public static FilenameFilter getCertFilter() {
        return certFileFilter;
    }
    
    public static class CertFilter implements FilenameFilter {
        public boolean accept(File dir, String file) {
            int length = file.length();
            if (length > 2 && 
                file.charAt(length-2) == '.' &&
                file.charAt(length-1) >= '0' && 
                file.charAt(length-1) <= '9') return true;
            return false;
        }
    }

    private static KeyStore getTrustStore(String caCertsLocation) throws  GeneralSecurityException, IOException
    {
        if(TrustedCertificates.ms_trustStore != null)
            return TrustedCertificates.ms_trustStore;
        
        String caCertsPattern = caCertsLocation + "/*.0";
        KeyStore keyStore = KeyStore.getInstance(GlobusProvider.KEYSTORE_TYPE, GlobusProvider.PROVIDER_NAME);
        keyStore.load(KeyStoreParametersFactory.createTrustStoreParameters(caCertsPattern));
        
        TrustedCertificates.ms_trustStore = keyStore;
        
        return keyStore;
    }
    
//    private static CertStore getCRLStore(String caCertsLocation) throws GeneralSecurityException, NoSuchAlgorithmException
//    {
//        if(TrustedCertificates.ms_crlStore != null)
//            return TrustedCertificates.ms_crlStore;
//        
//        String crlPattern = caCertsLocation + "/*.r*";
//        CertStore crlStore = CertStore.getInstance(GlobusProvider.CERTSTORE_TYPE, new ResourceCertStoreParameters(null,crlPattern));
//        
//        TrustedCertificates.ms_crlStore = crlStore ;
//        
//        return crlStore;
//    }
    
    private static ResourceSigningPolicyStore getSigPolStore(String caCertsLocation) throws GeneralSecurityException
    {
        if(TrustedCertificates.ms_sigPolStore != null)
            return TrustedCertificates.ms_sigPolStore;
        
        String sigPolPattern = caCertsLocation + "/*.signing_policy";
        ResourceSigningPolicyStore sigPolStore = new ResourceSigningPolicyStore(new ResourceSigningPolicyStoreParameters(sigPolPattern));
        
        TrustedCertificates.ms_sigPolStore = sigPolStore;
        
        return sigPolStore;
    }
    public void refresh() {
        reload(null);
    }

    public synchronized void reload(String locations) {
        if (locations == null) {
            return;
        }

        this.changed = false;

        StringTokenizer tokens = new StringTokenizer(locations, ",");
        File caDir            = null;

        Map newCertSubjectDNMap = new HashMap();
        Map newSigningDNMap = new HashMap();

        while(tokens.hasMoreTokens()) {
            caDir = new File(tokens.nextToken().toString().trim());

            if (!caDir.canRead()) {
                logger.debug("Cannot read: " + caDir.getAbsolutePath());
                continue;
            }

            String caCertLocation = "file:" + caDir.getAbsolutePath();
//            String sigPolPattern = caCertLocation + "/*.signing_policy";
//            if (!caDir.isDirectory()) {
//                sigPolPattern = getPolicyFileName(caCertLocation);
//            }

            KeyStore trustStore = null;
            try {
                trustStore = TrustedCertificates.getTrustStore(caCertLocation);
                
                Collection<? extends Certificate> caCerts = KeyStoreUtil.getTrustedCertificates(trustStore, new X509CertSelector());
                Iterator iter = caCerts.iterator();
                while (iter.hasNext()) {
                    X509Certificate cert = (X509Certificate) iter.next();
                    newCertSubjectDNMap.put(cert.getSubjectDN().toString(), cert);
                }
            } catch (Exception e) {
                logger.warn("Failed to create trust store",e);
            }
                
            try {
                ResourceSigningPolicyStore sigPolStore = TrustedCertificates.getSigPolStore(caCertLocation);
                Collection<? extends Certificate> caCerts = KeyStoreUtil.getTrustedCertificates(trustStore, new X509CertSelector());
                Iterator iter = caCerts.iterator();
                while (iter.hasNext()) {
                    X509Certificate cert = (X509Certificate) iter.next();
                    X500Principal principal = cert.getSubjectX500Principal();
                    SigningPolicy policy;
                    try {
                        policy = sigPolStore.getSigningPolicy(principal);
                    } catch (Exception e) {
                        if (!invalidPolicies.contains(principal)) {
                            logger.warn("Invalid signing policy for CA certificate; skipping",e);
                            invalidPolicies.add(principal);
                        }
                        continue;
                    }
                    if (policy != null) {
                        newSigningDNMap.put(CertificateUtil.toGlobusID(policy.getCASubjectDN()), policy);
                    } else {
                        logger.warn("no signing policy for ca cert " + cert.getSubjectDN());
                    }
                }
            } catch (Exception e) {
                logger.warn("Failed to create signing policy store",e);
            }
        }
        
        this.changed = true;
        this.certSubjectDNMap = newCertSubjectDNMap;
        this.policyDNMap = newSigningDNMap;

    if (this.changed) {
        this.certList = null;
    }
    }

    /**
     * Signing policy name is created as <hashcode>.signing_policy.
     */
    private String getPolicyFileName(String caFileName) {
        return caFileName.substring(0, caFileName.lastIndexOf(".")) + SIGNING_POLICY_FILE_SUFFIX ;
    }

    /**
     * Indicates if the last reload caused new certificates to be loaded or
     * existing certificates to be reloaded or any certificates removed
     */
    public boolean isChanged() {
        return this.changed;
    }

    /**
     * Obtains the default set of trusted certificates and signing policy
     *
     * @return TrustedCertificates object.
     */
    public static synchronized TrustedCertificates 
        getDefaultTrustedCertificates() {

        return getDefault();
    }

    /**
     * Sets the default set of trusted certificates to use.
     *
     * @param trusted the new set of trusted certificates to use.
     */    
    public static void 
        setDefaultTrustedCertificates(TrustedCertificates trusted) {

        trustedCertificates = trusted;
    }
    
    /**
     * Obtains the default set of trusted certificates and signing policy
     *
     * @return TrustedCertificates object. 
     */
    public static synchronized TrustedCertificates getDefault() {
        if (trustedCertificates == null) {
            trustedCertificates = new DefaultTrustedCertificates();
        }
        trustedCertificates.refresh();
        return trustedCertificates;
    }
    
    private static class DefaultTrustedCertificates 
        extends TrustedCertificates {
        
        public void refresh() {
            reload(CoGProperties.getDefault().getCaCertLocations());
        }
    }

    public String toString() {
        String returnStr = "";
        if (this.certSubjectDNMap == null) {
            returnStr =  "Certificate list is empty.";
        } else {
            returnStr = this.certSubjectDNMap.toString();
        }
        
        if (this.policyDNMap == null) {
            returnStr = returnStr + "Signing policy list is empty.";
        } else {
            returnStr = returnStr + this.policyDNMap.toString();
        }
        return returnStr;
    }
}

