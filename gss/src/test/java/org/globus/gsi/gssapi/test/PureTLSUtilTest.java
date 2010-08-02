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
package org.globus.gsi.gssapi.test;


import org.globus.gsi.gssapi.PureTLSUtil;

import COM.claymoresystems.cert.X509Name;


import java.util.Vector;

import junit.framework.TestCase;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class PureTLSUtilTest extends TestCase {
    
    private Log logger = LogFactory.getLog(PureTLSUtilTest.class);
    
    public void testSimple() throws Exception {

	X509Name name;
	Vector dn;
	Vector rdn;

	name = PureTLSUtil.getX509Name("/C=US");
	logger.debug(name.getNameString());
	dn = name.getName();
	assertEquals(1, dn.size());

	name = PureTLSUtil.getX509Name("/C=US/O=ANL");
	logger.debug(name.getNameString());
	dn = name.getName();
	assertEquals(2, dn.size());

	name = PureTLSUtil.getX509Name("/C=US/O=Globus/O=ANL/OU=MCS/CN=gawor/CN=proxy");
	assertEquals("C=US,O=Globus,O=ANL,OU=MCS,CN=gawor,CN=proxy", 
		     name.getNameString());
	logger.debug(name.getNameString());
	dn = name.getName();
	assertEquals(6, dn.size());

	name = PureTLSUtil.getX509Name("/C=US/O=Globus/O=ANL/OU=MCS/CN=gawor/CN=host/pitcairn.mcs.anl.gov");
	logger.debug(name.getNameString());
	dn = name.getName();
	assertEquals(6, dn.size());
	rdn = (Vector)dn.elementAt(dn.size()-1);
	assertEquals(1, rdn.size());
	assertEquals("CN", ((String[])rdn.elementAt(0))[0]);
	assertEquals("host/pitcairn.mcs.anl.gov", ((String[])rdn.elementAt(0))[1]);
	
	name = PureTLSUtil.getX509Name("/C=US/O=Globus/O=ANL/OU=MCS/CN=host/pitcairn.mcs.anl.gov/CN=gawor");
	logger.debug(name.getNameString());
	dn = name.getName();
	assertEquals(6, dn.size());
	rdn = (Vector)dn.elementAt(dn.size()-2);
	assertEquals(1, rdn.size());
	assertEquals("CN", ((String[])rdn.elementAt(0))[0]);
	assertEquals("host/pitcairn.mcs.anl.gov", ((String[])rdn.elementAt(0))[1]);

	name = PureTLSUtil.getX509Name("/C=US/CN=host/pitcairn.mcs.anl.gov/CN=gawor+OU=ANL");
	logger.debug(name.getNameString());
	dn = name.getName();
	assertEquals(3, dn.size());
	rdn = (Vector)dn.elementAt(dn.size()-1);
	assertEquals(2, rdn.size());
	assertEquals("CN", ((String[])rdn.elementAt(0))[0]);
	assertEquals("gawor", ((String[])rdn.elementAt(0))[1]);
	assertEquals("OU", ((String[])rdn.elementAt(1))[0]);
	assertEquals("ANL", ((String[])rdn.elementAt(1))[1]);

	name = PureTLSUtil.getX509Name("/C=US/CN=gawor+EmailAddress=gawor@anl.gov/CN=host/pitcairn.mcs.anl.gov");
	logger.debug(name.getNameString());
	dn = name.getName();
	assertEquals(3, dn.size());
	rdn = (Vector)dn.elementAt(dn.size()-2);
	assertEquals(2, rdn.size());
	assertEquals("CN", ((String[])rdn.elementAt(0))[0]);
	assertEquals("gawor", ((String[])rdn.elementAt(0))[1]);
	assertEquals("EMAILADDRESS", ((String[])rdn.elementAt(1))[0]);
	assertEquals("gawor@anl.gov", ((String[])rdn.elementAt(1))[1]);
    }


    public void testMalformed() throws Exception {

	X509Name name;
	Vector dn;
	Vector rdn;

        try {
            name = PureTLSUtil.getX509Name("DC=US");
            fail("did not throw exception as expected");
        } catch (Exception e) {
        }

        try {
            name = PureTLSUtil.getX509Name("DC=US/O=ANL");
            fail("did not throw exception as expected");
        } catch (Exception e) {
        }
    }

}
