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
package org.globus.gsi.proxy.ext;

import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;

import org.globus.gsi.proxy.ext.ProxyPolicy;
import org.globus.gsi.proxy.ext.ProxyCertInfo;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1OutputStream;

import junit.framework.TestCase;

public class ProxyCertInfoTest extends TestCase {

    String testPolicy = "blahblah";
    ASN1ObjectIdentifier testOid = new ASN1ObjectIdentifier("1.2.3.4.5");

    public void testCreateProxyCertInfo() throws Exception {

	ProxyPolicy policy = new ProxyPolicy(testOid, testPolicy);

	ProxyCertInfo info = new ProxyCertInfo(3,
					       policy);

	assertEquals(3, info.getPathLenConstraint());

	assertEquals(testPolicy, info.getProxyPolicy().getPolicyAsString());
	assertEquals(testOid, info.getProxyPolicy().getPolicyLanguage());

    }

    public void testParseProxyCertInfo() throws Exception {

	ProxyPolicy policy = new ProxyPolicy(testOid, testPolicy);

	ProxyCertInfo info = new ProxyCertInfo(3,
					       policy);


	ByteArrayOutputStream bOut = new ByteArrayOutputStream();
	ASN1OutputStream dOut = ASN1OutputStream.create(bOut);
	dOut.writeObject(info);

	ByteArrayInputStream bIn =
	    new ByteArrayInputStream(bOut.toByteArray());
	ASN1InputStream dIn = new ASN1InputStream(bIn);
	ASN1Primitive obj = dIn.readObject();

	assertTrue(obj instanceof ASN1Sequence);

	ProxyCertInfo testInfo = new ProxyCertInfo((ASN1Sequence)obj);

	assertEquals(3, testInfo.getPathLenConstraint());

	assertEquals(testPolicy, testInfo.getProxyPolicy().getPolicyAsString());
	assertEquals(testOid, testInfo.getProxyPolicy().getPolicyLanguage());
    }

    public void testConstraintsCheck() throws Exception {

	ProxyPolicy policy;

	try {
	    policy = new ProxyPolicy(ProxyPolicy.IMPERSONATION,
				     testPolicy);
	    fail("Did not throw exception as expected");
	} catch (IllegalArgumentException e) {
	}

	try {
	    policy = new ProxyPolicy(ProxyPolicy.INDEPENDENT,
				     testPolicy);
	    fail("Did not throw exception as expected");
	} catch (IllegalArgumentException e) {
	}

    }

    public void testCreateProxyCertInfo2() throws Exception {

	ProxyPolicy policy = new ProxyPolicy(testOid, testPolicy);
	ProxyCertInfo info = new ProxyCertInfo(policy);

	assertEquals(Integer.MAX_VALUE, info.getPathLenConstraint());

	assertEquals(testPolicy, info.getProxyPolicy().getPolicyAsString());
	assertEquals(testOid, info.getProxyPolicy().getPolicyLanguage());

	ByteArrayOutputStream bOut = new ByteArrayOutputStream();
	ASN1OutputStream dOut = ASN1OutputStream.create(bOut);
	dOut.writeObject(info);

	ByteArrayInputStream bIn =
	    new ByteArrayInputStream(bOut.toByteArray());
	ASN1InputStream dIn = new ASN1InputStream(bIn);
	ASN1Primitive obj = dIn.readObject();

	ProxyCertInfo testInfo = new ProxyCertInfo((ASN1Sequence)obj);


	assertEquals(Integer.MAX_VALUE, testInfo.getPathLenConstraint());

	assertEquals(testPolicy, testInfo.getProxyPolicy().getPolicyAsString());
	assertEquals(testOid, testInfo.getProxyPolicy().getPolicyLanguage());
    }
}
