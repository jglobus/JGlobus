/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
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

package org.globus.gridshib.client.saml.query;

import org.globus.opensaml11.md.metadata.AttributeAuthorityDescriptor;
import org.globus.opensaml11.md.metadata.EntityDescriptor;
import org.globus.opensaml11.md.metadata.KeyDescriptor;
import org.globus.opensaml11.md.metadata.provider.XMLMetadata;
import org.globus.opensaml11.md.xml.Parser;
import org.globus.gsi.util.CertificateLoadUtil;
import org.globus.gsi.OpenSSLKey;
import org.globus.gsi.bc.BouncyCastleOpenSSLKey;
import org.globus.util.Util;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;

public class CertUtils {

    /**
     * For the given providerId, return all X509 certificates found
     * under the AttributeAuthorityDescriptor element.  Therefore, this
     * is geared for queries about IdPs, really.
     * @param mdpath
     * @param providerId
     * @return certificates to trust for SSL connection to AA
     */
    public static X509Certificate[] findAAcerts(String mdpath,
                                                String providerId)
                    throws Exception {

        // Parse file and verify root element.
        Document doc = Parser.loadDom(
                new URL(new URL("file:"), mdpath), true);
        if (doc == null) {
            throw new Exception("Unable to load file: " + mdpath);
        }
        Element el = doc.getDocumentElement();
        XMLMetadata md = new XMLMetadata(el);
        if (md == null) {
            throw new Exception("Unable to parse metadata");
        }

        // lookup IdP descriptor:
        EntityDescriptor idp = md.lookup(providerId, false);
        if (idp == null) {
            throw new Exception("ProviderId not found in metadata: " + providerId);
        }

        // get AA descriptor:
        AttributeAuthorityDescriptor auth =
                idp.getAttributeAuthorityDescriptor(
                        "urn:oasis:names:tc:SAML:1.1:protocol");
        if (auth == null) {
            throw new Exception("AttributeAuthorityDescriptor not found");
        }

        // accumulate KeyDescriptors:
        ArrayList certs = new ArrayList();
        Iterator iter = auth.getKeyDescriptors();
        while (iter.hasNext()) {
            KeyDescriptor desc = (KeyDescriptor)iter.next();

            // not sure if this is making certain assumptions
            // about the metadata, check later, this may
            // throw NPE for certain metadata documents:
            certs.add(desc.getKeyInfo().getX509Certificate());
        }

        return (X509Certificate[])certs.toArray(new X509Certificate[0]);
    }

    public static void createCertStore(String certFile,
                                      String alias,
                                      String keyStoreFile,
                                      String password,
                                      boolean debug) throws Exception {
        X509Certificate [] certs = new X509Certificate[1];

        try {
            certs[0] = CertificateLoadUtil.loadCertificate(certFile);
        } catch(Exception e) {
            System.err.println("Failed to load certificate: " + e.getMessage());
            throw e;
        }

        FileOutputStream out = null;

        try {
            KeyStore ks = KeyStore.getInstance("JKS", "SUN");
            ks.load(null, null);
            ks.setCertificateEntry(alias,certs[0]);
            out = new FileOutputStream(keyStoreFile);
            ks.store(out, password.toCharArray());
        } catch(Exception e) {
            System.err.println("Failed to create Java key store: "
                    + e.getMessage());
            throw e;
        } finally {
            if (out != null) {
            try { out.close(); } catch(IOException ee) {}
            }
        }
        if (debug) {
            System.err.println("Added '" + alias + "' to " +
                    keyStoreFile + ": " +
                    certs[0].getSubjectX500Principal());
        }
    }

    public static void createCertStore(X509Certificate[] certs,
                                       String alias[],
                                       String keyStoreFile,
                                       String password,
                                       boolean debug) throws Exception {

        if (certs == null) {
            throw new Exception("certs is null");
        }

        if (certs.length == 0) {
            throw new Exception("no certs to add");
        }

        if (certs.length != alias.length) {
            throw new Exception("each cert does not have a " +
                    "corresponding alias");
        }

        FileOutputStream out = null;

        try {
            KeyStore ks = KeyStore.getInstance("JKS", "SUN");
            ks.load(null, null);
            for (int i = 0; i < certs.length; i++) {
                ks.setCertificateEntry(alias[i],certs[i]);
                if (debug) {
                    System.err.println("Added '" + alias[i] + "' to " +
                            keyStoreFile + ": " +
                            certs[i].getSubjectX500Principal());
                }
            }
            out = new FileOutputStream(keyStoreFile);
            ks.store(out, password.toCharArray());
        } catch(Exception e) {
            System.err.println("Failed to create Java key store: "
                    + e.getMessage());
            throw e;
        } finally {
            if (out != null) {
            try { out.close(); } catch(IOException ee) {}
            }
        }
        if (debug) {
            System.err.println("Java keystore file (" + keyStoreFile +
                       ") successfully created.");
        }
    }

    public static void addToCertStore(X509Certificate certificate,
                                      String alias,
                                      String keyStoreFile,
                                      String password,
                                      boolean debug) {

        FileOutputStream out = null;

        try {
            KeyStore ks = KeyStore.getInstance("JKS", "SUN");
            ks.load(new FileInputStream(keyStoreFile), password.toCharArray());
            ks.setCertificateEntry(alias, certificate);
            out = new FileOutputStream(keyStoreFile);
            ks.store(out, password.toCharArray());
        } catch(Exception e) {
            System.err.println("Failed to create Java key store: " + e.getMessage());
        } finally {
            if (out != null) {
            try { out.close(); } catch(IOException ee) {}
            }
        }

        if (debug) {
            System.err.println("Added '" + alias + "' to " + keyStoreFile +
                    ": " + certificate.getSubjectX500Principal());
            System.err.println("Java keystore file (" + keyStoreFile +
                       ") successfully created.");
        }
    }

    /**
     * Creates keystore from PEM file, will prompt the user for a password
     * if the key is encrypted.
     *
     * Copied from org.globus.tools.KeyStoreConvert, which does
     * not make the method public (also, removed int return scheme).
     *
     *
     * See cogkit.org
     * http://www.cogkit.org/viewcvs/viewcvs.cgi/src/jglobus/src/org/globus/tools/KeyStoreConvert.java?rev=HEAD&content-type=text/vnd.viewcvs-markup
     *
     * @param certFile
     * @param keyFile
     * @param alias
     * @param password
     * @param keyStoreFile
     * @param debug
     */
    public static void createKeyStore(String certFile,
                      String keyFile,
                      String alias,
                      String password,
                      String keyStoreFile,
                      boolean debug) throws Exception {

        X509Certificate [] certs = new X509Certificate[1];
        PrivateKey key;

        try {
            certs[0] = CertificateLoadUtil.loadCertificate(certFile);
        } catch(Exception e) {
            System.err.println("Failed to load certificate: " + e.getMessage());
            throw e;
        }

        try {
            OpenSSLKey sslkey = new BouncyCastleOpenSSLKey(keyFile);

            if (sslkey.isEncrypted()) {
            String pwd = Util.getPrivateInput("Enter pass phrase: ");

            if (pwd == null) {
                // user canceled
                throw new Exception("user cancelled");
            }

            sslkey.decrypt(pwd);
            }

            key = sslkey.getPrivateKey();

        } catch(IOException e) {
            System.err.println("Failed to load key: " + e.getMessage());
            throw e;
        } catch(GeneralSecurityException e) {
            System.err.println("Error: Wrong pass phrase");
            if (debug) {
            e.printStackTrace();
            }
            throw e;
        }

        if (debug) {
            System.err.println("Creating Java keystore...");
        }
        FileOutputStream out = null;

        try {
            KeyStore ks = KeyStore.getInstance("JKS", "SUN");
            ks.load(null, null);
            // this takes a while for some reason
            ks.setKeyEntry(alias, key, password.toCharArray(), certs);
            out = new FileOutputStream(keyStoreFile);
            ks.store(out, password.toCharArray());
        } catch(Exception e) {
            System.err.println("Failed to create Java key store: " + e.getMessage());
            throw e;
        } finally {
            if (out != null) {
            try { out.close(); } catch(IOException ee) {}
            }
        }

        if (debug) {
            System.err.println("Java keystore file (" + keyStoreFile +
                       ") successfully created.");
        }
    }
}
