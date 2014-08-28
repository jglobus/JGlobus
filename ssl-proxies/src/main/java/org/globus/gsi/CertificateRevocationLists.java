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

import org.globus.gsi.stores.ResourceCertStoreParameters;
import org.globus.gsi.stores.Stores;

import org.globus.gsi.provider.GlobusProvider;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509CRLSelector;
import java.security.cert.CertStore;
import java.security.cert.X509CRL;
import java.util.Map;
import java.util.Collection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.ListIterator;
import java.util.StringTokenizer;
import java.io.File;
import org.globus.common.CoGProperties;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

// COMMENT: what should be used instead? Probably a cert-store. but that doesn't have a refresh or such
// COMMENT: We lost the functionality that stuff is only loaded when it didnt' exist or changed

/**
 * @deprecated
 */
public class CertificateRevocationLists {

    static {
        new ProviderLoader();
    }

    private static Log logger =
        LogFactory.getLog(CertificateRevocationLists.class.getName());

    // the list of ca cert locations needed for getDefaultCRL call
    private static String prevCaCertLocations = null;
    // the default crl locations list derived from prevCaCertLocations
    private static String defaultCrlLocations = null;
    private static CertificateRevocationLists defaultCrl  = null;

    private volatile Map<String, X509CRL> crlIssuerDNMap;

    private CertificateRevocationLists() {}

    public X509CRL[] getCrls() {
        if (this.crlIssuerDNMap == null) {
            return null;
        }
        Collection crls = this.crlIssuerDNMap.values();
        return (X509CRL[]) crls.toArray(new X509CRL[crls.size()]);
    }

    public Collection<X509CRL> getCRLs(X509CRLSelector selector) {
        Collection<X500Principal> issuers = selector.getIssuers();
        int size = issuers.size();
        Collection<X509CRL> retval = new ArrayList<X509CRL>(size);
        // Yup, this stinks.  There's loss when we convert from principal to
        // string.  Hence, depending on weird encoding effects, we may miss
        // some CRLs.
        Map<String, X509CRL> crlMap = this.crlIssuerDNMap;
        if (crlMap == null) return retval;
        for (X500Principal principal : issuers) {
            String dn = principal.getName();
            X509CRL crl = crlMap.get(dn);
            if (crl != null) {
                retval.add(crl);
            }
        }
        return retval;
    }

    public X509CRL getCrl(String issuerName) {
        if (this.crlIssuerDNMap == null) {
            return null;
        }
        return (X509CRL)this.crlIssuerDNMap.get(issuerName);
    }

    public void refresh() {
        reload(null);
    }

    public synchronized void reload(String locations) {

        if (locations == null) {
            return;
        }

        StringTokenizer tokens = new StringTokenizer(locations, ",");
        Map<String, X509CRL> newCrlIssuerDNMap = new HashMap<String, X509CRL>();

        while(tokens.hasMoreTokens()) {

            try {
              String location = tokens.nextToken().toString().trim();
              CertStore tmp = Stores.getCRLStore("file:" + location + "/*.r*");
              Collection<X509CRL> coll = (Collection<X509CRL>) tmp.getCRLs(new X509CRLSelector());
              for (X509CRL crl : coll) {
                newCrlIssuerDNMap.put(crl.getIssuerX500Principal().getName(), crl);
              }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        this.crlIssuerDNMap = newCrlIssuerDNMap;
    }


    public static CertificateRevocationLists
        getCertificateRevocationLists(String locations) {
        CertificateRevocationLists crl = new CertificateRevocationLists();
        crl.reload(locations);
        return crl;
    }

    public static synchronized
        CertificateRevocationLists getDefaultCertificateRevocationLists() {
        return getDefault();
    }

    public static void
        setDefaultCertificateRevocationList(CertificateRevocationLists crl) {
        defaultCrl = crl;
    }

    public static synchronized CertificateRevocationLists getDefault() {
        if (defaultCrl == null) {
            defaultCrl = new DefaultCertificateRevocationLists();
        }
        defaultCrl.refresh();
        return defaultCrl;
    }

    public String toString() {
        if (this.crlIssuerDNMap == null) {
            return  "crl list is empty";
        } else {
            return this.crlIssuerDNMap.toString();
        }
    }

    private static class DefaultCertificateRevocationLists
        extends CertificateRevocationLists {

         private final long lifetime;
         private long lastRefresh;

         public DefaultCertificateRevocationLists() {
             lifetime = CoGProperties.getDefault().getCertCacheLifetime();
         }

        public void refresh() {
             long now = System.currentTimeMillis();
             if (lastRefresh + lifetime <= now) {
                 reload(getDefaultCRLLocations());
                 lastRefresh = now;
             }
        }

        private static synchronized String getDefaultCRLLocations() {
            String caCertLocations =
                CoGProperties.getDefault().getCaCertLocations();

            if (prevCaCertLocations == null ||
                !prevCaCertLocations.equals(caCertLocations)) {

                if (caCertLocations == null) {
                    logger.debug("No CA cert locations specified");
                    prevCaCertLocations = null;
                    defaultCrlLocations = null;
                } else {
                    StringTokenizer tokens = new StringTokenizer(caCertLocations, ",");
                    File crlFile = null;
                    LinkedList crlDirs = new LinkedList();
                    while(tokens.hasMoreTokens()) {
                        String crlFileName =
                            tokens.nextToken().toString().trim();
                        crlFile = new File(crlFileName);
                        if (crlFile.isDirectory()) {
                            // all all directories
                        } else if (crlFile.isFile()) {
                            // add parent directory
                            crlFileName = crlFile.getParent();
                        } else {
                            // skip other types
                            continue;
                        }

                        // don't add directories twice
                        if (crlFileName != null &&
                            !crlDirs.contains(crlFileName)) {
                            crlDirs.add(crlFileName);
                        }
                    }

                    ListIterator iterator = crlDirs.listIterator(0);
                    String locations = null;
                    while (iterator.hasNext()) {
                        if (locations == null) {
                            locations = (String)iterator.next();
                        } else {
                            locations = locations + ","
                                + (String)iterator.next();
                        }
                    }

                    // set defaults
                    prevCaCertLocations = caCertLocations;
                    defaultCrlLocations = locations;
                }
            }
            return defaultCrlLocations;
        }
    }

}
