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
package org.globus.gsi.provider;

import org.globus.gsi.trustmanager.PKITrustManager;

import org.globus.gsi.X509ProxyCertPathParameters;
import org.globus.gsi.X509ProxyCertPathValidatorResult;

import java.security.KeyStore;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.junit.Before;
import org.junit.Test;

/**
 * FILL ME
 * <p>
 * // JGLOBUS-103  separate this from proxy path validator test class.
 *
 * @author ranantha@mcs.anl.gov
 */
public class TestTrustManager extends TestProxyPathValidator {

    @Before
    public void setup() throws Exception {

        super.setup();
    }

    @Test
    public void validationTest() throws Exception {

        KeyStore keyStore = getKeyStore(new X509Certificate[]{goodCertsArr[0]});
        TestCertParameters parameters = new TestCertParameters(null, this.crls);

        CertStore certStore =
                CertStore.getInstance("MockCertStore", parameters);
        TestPolicyStore policyStore =
                new TestPolicyStore(null);
        X509ProxyCertPathParameters validatorParam =
                new X509ProxyCertPathParameters(keyStore, certStore, policyStore,
                        false,
                        null);
        PKITrustManager manager =
                new PKITrustManager(
                        new MockProxyCertPathValidator(false, false, false, false),
                        validatorParam);
        X509Certificate[] certChain =
                new X509Certificate[]{goodCertsArr[5], goodCertsArr[1],
                        goodCertsArr[0]};
        manager.checkClientTrusted(certChain, "RSA");
        manager.checkServerTrusted(certChain, "RSA");
        CertPathValidatorResult result = manager.getValidationResult();
        assert (result != null);
        assert (result instanceof X509ProxyCertPathValidatorResult);
        assert (!((X509ProxyCertPathValidatorResult) result).isLimited());

        X509Certificate[] acceptedIssuers = manager.getAcceptedIssuers();
        assert (acceptedIssuers != null);
        assert (acceptedIssuers.length == 1);

        assert (acceptedIssuers[0].equals(goodCertsArr[0]));


        // Fail because of reject limited proxy
        validatorParam = new X509ProxyCertPathParameters(keyStore, certStore, policyStore, true, null);
        manager = new PKITrustManager(new MockProxyCertPathValidator(false, false, false, false), validatorParam);
        certChain = new X509Certificate[]{goodCertsArr[3], goodCertsArr[1], goodCertsArr[0]};
        boolean exception = false;
        try {
            manager.checkClientTrusted(certChain, "RSA");
        } catch (CertificateException e) {
            Throwable cause = e.getCause();
            if (cause instanceof CertPathValidatorException) {
                if (cause.getMessage().indexOf("Limited") != -1) {
                    exception = true;
                }
            }
        }
        assert (exception);

        exception = false;
        try {
            manager.checkServerTrusted(certChain, "RSA");
        } catch (CertificateException e) {
            Throwable cause = e.getCause();
            if (cause instanceof CertPathValidatorException) {
                if (cause.getMessage().indexOf("Limited") != -1) {
                    exception = true;
                }
            }
        }
        assert (exception);
    }

}
