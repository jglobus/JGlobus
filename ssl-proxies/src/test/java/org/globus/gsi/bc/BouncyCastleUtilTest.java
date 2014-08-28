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
package org.globus.gsi.bc;

import org.globus.gsi.util.CertificateLoadUtil;

import java.io.InputStream;
import org.globus.gsi.proxy.ProxyPathValidatorTest;
import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import org.globus.gsi.GSIConstants;
import org.globus.gsi.TrustedCertificates;
import org.globus.gsi.bc.BouncyCastleUtil;
import junit.framework.TestCase;

public class BouncyCastleUtilTest extends TestCase {

    static String [] badCerts = ProxyPathValidatorTest.badCerts;

    private X509Certificate getCertificate(int i) throws Exception {
        ClassLoader loader = ProxyPathValidatorTest.class.getClassLoader();
        String name = ProxyPathValidatorTest.BASE + ProxyPathValidatorTest.certs[i][1];
        InputStream in = loader.getResourceAsStream(name);
        if (in == null) {
            throw new Exception("Unable to load: " + name);
        }
        return CertificateLoadUtil.loadCertificate(in);
        }

    public void testGetCertificateType() throws Exception {
	for (int i=0;i<ProxyPathValidatorTest.certs.length;i++) {
	    X509Certificate cert = getCertificate(i);
	    String type = ProxyPathValidatorTest.certs[i][0];
	    assertEquals(type, BouncyCastleUtil.getCertificateType(cert).name());
	}
    }

    public void testGetCertificateType2() throws Exception {
	for (int i=0;i<badCerts.length;i++) {
	    X509Certificate cert = CertificateLoadUtil.loadCertificate(new ByteArrayInputStream(badCerts[i].getBytes()));
	    try {
		BouncyCastleUtil.getCertificateType(cert);
		fail("proxy verification did not fail as expected");
	    } catch (CertificateException e) {
		// ignore
	    }
	}
     }

    public void testGetCertificateType3() throws Exception {
	X509Certificate cert = getCertificate(1);
	assertEquals(GSIConstants.CertificateType.EEC, BouncyCastleUtil.getCertificateType(cert));

	TrustedCertificates trustedCerts =
	    new TrustedCertificates(new X509Certificate[] {cert});
	assertEquals(GSIConstants.CertificateType.CA, BouncyCastleUtil.getCertificateType(cert, trustedCerts));
    }

    public void testGetGsi2IdentityCertificate() throws Exception {
	X509Certificate [] goodCertsArr = ProxyPathValidatorTest.initCerts();

	X509Certificate [] chain = null;

	// EEC, CA
	chain = new X509Certificate[] {goodCertsArr[1], goodCertsArr[0]};
	assertEquals(goodCertsArr[1], BouncyCastleUtil.getIdentityCertificate(chain));

	// proxy, EEC, CA
	chain = new X509Certificate[] {goodCertsArr[2], goodCertsArr[1], goodCertsArr[0]};
	assertEquals(goodCertsArr[1], BouncyCastleUtil.getIdentityCertificate(chain));

	// limited proxy, EEC, CA
	chain = new X509Certificate[] {goodCertsArr[3], goodCertsArr[1], goodCertsArr[0]};
	assertEquals(goodCertsArr[1], BouncyCastleUtil.getIdentityCertificate(chain));

	// double limited proxy, limited proxy, EEC, CA
	chain = new X509Certificate[] {goodCertsArr[4], goodCertsArr[3],
				       goodCertsArr[1], goodCertsArr[0]};
	assertEquals(goodCertsArr[1], BouncyCastleUtil.getIdentityCertificate(chain));
    }

    public void testValidateGsi3PathGood() throws Exception {
	X509Certificate [] goodCertsArr = ProxyPathValidatorTest.initCerts();

	X509Certificate [] chain = null;

	// GSI 3 PC impersonation, EEC, CA
	chain = new X509Certificate[] {goodCertsArr[5], goodCertsArr[1], goodCertsArr[0]};
	assertEquals(goodCertsArr[1], BouncyCastleUtil.getIdentityCertificate(chain));

	// GSI 3 PC independent, EEC, CA
	chain = new X509Certificate[] {goodCertsArr[6], goodCertsArr[1], goodCertsArr[0]};
	assertEquals(goodCertsArr[6], BouncyCastleUtil.getIdentityCertificate(chain));

	// GSI 3 PC imperson limited, EEC, CA
	chain = new X509Certificate[] {goodCertsArr[7], goodCertsArr[1], goodCertsArr[0]};
	assertEquals(goodCertsArr[1], BouncyCastleUtil.getIdentityCertificate(chain));

	// GSI 3 PC restricted, EEC, CA
	chain = new X509Certificate[] {goodCertsArr[8], goodCertsArr[1], goodCertsArr[0]};
	assertEquals(goodCertsArr[8], BouncyCastleUtil.getIdentityCertificate(chain));

	// GSI 3 PC impersonation, GSI 3 PC limited impersonation, EEC, CA
	chain = new X509Certificate[] {goodCertsArr[9], goodCertsArr[7],
				       goodCertsArr[1], goodCertsArr[0]};
	assertEquals(goodCertsArr[1], BouncyCastleUtil.getIdentityCertificate(chain));

	// GSI 3 PC impersonation, GSI 3 PC impersonation, EEC, CA
	chain = new X509Certificate[] {goodCertsArr[9], goodCertsArr[5],
				       goodCertsArr[1], goodCertsArr[0]};
	assertEquals(goodCertsArr[1], BouncyCastleUtil.getIdentityCertificate(chain));

	// GSI 3 PC indepedent, GSI 3 PC independent, EEC, CA
	chain = new X509Certificate[] {goodCertsArr[10], goodCertsArr[6],
				       goodCertsArr[1], goodCertsArr[0]};
	assertEquals(goodCertsArr[10], BouncyCastleUtil.getIdentityCertificate(chain));

	// GSI 3 PC impersonation, GSI 3 PC independent, EEC, CA
	chain = new X509Certificate[] {goodCertsArr[9], goodCertsArr[6],
				       goodCertsArr[1], goodCertsArr[0]};
	assertEquals(goodCertsArr[6], BouncyCastleUtil.getIdentityCertificate(chain));
    }
}

