/*
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package org.globus.gsi.stores;

import junit.framework.Assert;
import junit.framework.TestCase;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.globus.gsi.SigningPolicy;

import java.io.File;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * User: AmilaJ (amilaj@apache.org)
 * Date: 6/11/13
 * Time: 10:26 AM
 */

public class ResourceSigningPolicyStoreTest extends TestCase {

    private String caCertsLocation;

    private Log logger = LogFactory.getLog(getClass());

    public void setUp() throws Exception {
        String projectDirectory = System.getProperty("projectDirectory");

        if (projectDirectory == null) {
            projectDirectory = "src/test/resources/org/globus/gsi/stores/";

            File f = new File(projectDirectory);

            if (!f.isDirectory()) {
                projectDirectory = "ssl-proxies/src/test/resources/org/globus/gsi/stores/";
            }
        } else {
            projectDirectory = projectDirectory + "/src/test/resources/org/globus/gsi/stores/";
        }

        File projectDir = new File(projectDirectory);

        caCertsLocation = projectDir.getAbsolutePath();

        logger.info("CA cert location is set to " + caCertsLocation);

    }

    public void testGetSigningPolicyWithOutDNPrincipal() throws Exception {

        String sigPolPattern = caCertsLocation + "/*.signing_policy";
        ResourceSigningPolicyStore sigPolStore
                = new ResourceSigningPolicyStore(new ResourceSigningPolicyStoreParameters(sigPolPattern));

        String certPath1 = caCertsLocation + "/ffc3d59b.0";

        X509Certificate crt1 = readCertificate(certPath1);
        Assert.assertNotNull("Unable to read certificate in " + certPath1 ,crt1);

        // According to https://github.com/jglobus/JGlobus/issues/102 the second attempt is failing.
        // Therefore we query twice.
        SigningPolicy signingPolicy = sigPolStore.getSigningPolicy(crt1.getSubjectX500Principal());

        Assert.assertNotNull(signingPolicy);

        signingPolicy = sigPolStore.getSigningPolicy(crt1.getSubjectX500Principal());

        Assert.assertNotNull(signingPolicy);

    }

    public void testGetSigningPolicyWithDNPrincipal() throws Exception {

        String sigPolPattern = caCertsLocation + "/*.signing_policy";
        ResourceSigningPolicyStore sigPolStore
                = new ResourceSigningPolicyStore(new ResourceSigningPolicyStoreParameters(sigPolPattern));

        String certPath1 = caCertsLocation + "/e5cc84c2.0";

        X509Certificate crt1 = readCertificate(certPath1);
        Assert.assertNotNull("Unable to read certificate in " + certPath1 ,crt1);

        SigningPolicy signingPolicy = sigPolStore.getSigningPolicy(crt1.getSubjectX500Principal());

        Assert.assertNotNull(signingPolicy);

        // According to https://github.com/jglobus/JGlobus/issues/102 the second attempt is failing.
        // Therefore we query twice.
        signingPolicy = sigPolStore.getSigningPolicy(crt1.getSubjectX500Principal());

        Assert.assertNotNull(signingPolicy);

    }



    private X509Certificate readCertificate(String certPath) {
        try {
            FileInputStream fr = new FileInputStream(certPath);
            CertificateFactory cf =
                    CertificateFactory.getInstance("X509");
            X509Certificate crt = (X509Certificate)
                    cf.generateCertificate(fr);
            logger.info("Read certificate:");
            logger.info("\tCertificate for: " +
                    crt.getSubjectDN());
            logger.info("\tCertificate issued by: " +
                    crt.getIssuerDN());
            logger.info("\tCertificate is valid from " +
                    crt.getNotBefore() + " to " + crt.getNotAfter());
            logger.info("\tCertificate SN# " +
                    crt.getSerialNumber());
            logger.info("\tGenerated with " +
                    crt.getSigAlgName());

            return crt;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}
