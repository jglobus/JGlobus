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
package org.globus.gsi.filestore;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.globus.gsi.stores.ResourceSigningPolicy;
import org.globus.gsi.testutils.FileSetupUtil;
import java.util.Collection;
import org.globus.gsi.SigningPolicy;
import org.globus.util.GlobusResource;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class TestFileBasedSigningPolicy {

    FileSetupUtil testPolicy1;

    @Before
    public void setUp() throws Exception {

        // JGLOBUS-103
        this.testPolicy1 =
                new FileSetupUtil(
                        "certificateUtilTest/validPolicy1.signing_policy");
    }


    @Test
    public void testSigningPolicy() throws Exception {

        this.testPolicy1.copyFileToTemp();

        ResourceSigningPolicy filePolicy =
                new ResourceSigningPolicy(new GlobusResource(testPolicy1.getAbsoluteFilename()));

        Collection<SigningPolicy> policies = filePolicy.getSigningPolicies();

        assert (policies != null);

        assert (policies.size() == 2);

        // assert policy values here
        assertFalse(filePolicy.hasChanged());

        policies = filePolicy.getSigningPolicies();

        assert (policies != null);

        assertFalse(filePolicy.hasChanged());

        testPolicy1.modifyFile();

        policies = filePolicy.getSigningPolicies();

        assert (policies != null);

        assertTrue(filePolicy.hasChanged());
    }

	// @Test
	// public void testPolicyFilter() {
	//
	// FilenameFilter filter = new SigningPolicyFilter();
	//
	// // Null checks
	// boolean worked = false;
	// try {
	// filter.accept(null, null);
	// } catch (IllegalArgumentException e) {
	// worked = true;
	// }
	// assert worked;
	//
	// // null dir name
	// assert (filter.accept(null, "foo.signing_policy"));
	//
	// // dir name ignored
	// assert (filter.accept(new File("bar"), "foo.signing_policy"));
	//
	// assertFalse(filter.accept(null, "foo.r"));
	//
	// assertFalse(filter.accept(null, "foo.SIGNING_POLICY"));
	//
	// assertFalse(filter.accept(null, "foo.signing"));
	//
	// }

    @After
    public void tearDown() throws Exception {
        this.testPolicy1.deleteFile();
    }

}
