/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 University of Southern California.
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

package org.globus.opensaml11.md.example1;

import org.globus.opensaml11.md.metadata.provider.XMLMetadata;
import org.globus.opensaml11.md.metadata.EntityDescriptor;
import org.globus.opensaml11.md.metadata.EntitiesDescriptor;
import org.globus.opensaml11.md.metadata.AttributeAuthorityDescriptor;
import org.globus.opensaml11.md.metadata.KeyDescriptor;
import org.globus.opensaml11.md.xml.Parser;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.apache.xml.security.keys.KeyInfo;

import java.net.URL;
import java.util.Iterator;
import java.security.cert.X509Certificate;

/**
 * Similar metadata load used in the gridshib-gt package @
 * org.globus.wsrf.impl.security.authorization.samlpiputils.MetadataUtil
 *
 * @author     Tim Freeman
 */
public class MetadataReader {


    public static void main(String[] args) throws Exception {

        if (args.length != 1) {
            String err = "Path to metadata required as only argument";
            System.err.println(err);
            throw new Exception(err);
        }

        XMLMetadata md = loadMetadata(args[0]);

        EntityDescriptor ed = md.getRootEntity();
        EntitiesDescriptor eds = md.getRootEntities();


        if ((ed == null) && (eds == null)) {
            throw new Exception("no EntityDescriptor(s) in metadata");
        }

        if (eds != null) {
            System.err.println("Does not currently " +
                                        "support EntitiesDescriptor");
        } else {
            System.out.println("found lone EntityDescriptor in metadata");

            AttributeAuthorityDescriptor aad =
                                ed.getAttributeAuthorityDescriptor(
                                       "urn:oasis:names:tc:SAML:1.1:protocol");

            if (aad == null) {
                // this is all this example looks for
                throw new Exception("AttributeAuthorityDescriptor " +
                                        "not present in EntityDescriptor");
            }

            String IdPproviderId = ed.getId();

            String AAurl = aad.getAttributeServiceManager().
                                           getDefaultEndpoint().getLocation();

            System.out.println("Found IdPproviderId = '" + IdPproviderId);
            System.out.println("Found AAUrl = '" + AAurl + "'");

            Iterator iter = aad.getKeyDescriptors();
            while (iter.hasNext()) {
                KeyDescriptor kd = (KeyDescriptor) iter.next();
                KeyInfo ki = kd.getKeyInfo();
                X509Certificate x509 = ki.getX509Certificate();
                System.out.println("Found cert with DN ='"
                        + x509.getSubjectDN().getName() + "'");
            }
        }
    }

    /**
     *
     * @param mdpath
     * @return XMLMetadata cannot be null
     * @throws Exception
     */
    public static XMLMetadata loadMetadata(String mdpath)
                                                throws Exception {

        URL url;
        try {
            url = new URL(mdpath);
        } catch (Exception e) {
            url = new URL(new URL("file:"), mdpath);
        }

        Parser.init();
        Document doc = Parser.loadDom(url, true);

        if (doc == null) {
            String err =
                    "Metadata error: unable to read in file: " + mdpath;
            System.err.println(err);
            throw new Exception(err);
        }

        Element el = doc.getDocumentElement();
        XMLMetadata md = new XMLMetadata(el);

        return md; // this cannot be null (see XMLMetadata)
    }
}
