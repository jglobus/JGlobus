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
import org.globus.gsi.stores.ResourceCRL;
import org.globus.gsi.testutils.FileSetupUtil;
import java.io.File;
import java.security.cert.X509CRL;
import org.globus.common.CoGProperties;
import org.globus.util.GlobusResource;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class TestFileBasedCRL {

    FileSetupUtil testCrl1;

    @Before
    public void setUp() throws Exception {

        CoGProperties.getDefault().setProperty(CoGProperties.CRL_CACHE_LIFETIME, "1");
        CoGProperties.getDefault().setProperty(CoGProperties.CERT_CACHE_LIFETIME, "1");
        this.testCrl1 = new FileSetupUtil("certificateUtilTest/validCrl.r0");
    }


    @Test
    public void testGetCrl() throws Exception {

        this.testCrl1.copyFileToTemp();

        String tempFileName = this.testCrl1.getAbsoluteFilename();

        ResourceCRL fileCrl = new ResourceCRL(false, new GlobusResource(tempFileName));

//        assert (fileCrl != null);

        X509CRL crl = fileCrl.getCrl();

        assert (crl != null);

        assertFalse(fileCrl.hasChanged());

        crl = fileCrl.getCrl();

        assert (crl != null);

        assertFalse(fileCrl.hasChanged());

        this.testCrl1.modifyFile();

        crl = fileCrl.getCrl();

        assert (crl != null);

        assertTrue(fileCrl.hasChanged());
    }

//    @Test
//    public void testGetCrlFilter() {
//
//        FilenameFilter filter = FileBasedCRL.getCrlFilter();
//
//        // Null checks
//        boolean worked = false;
//        try {
//            filter.accept(null, null);
//        } catch (IllegalArgumentException e) {
//            worked = true;
//        }
//        assert worked;
//
//        // null dir name
//        assert (filter.accept(null, "foo.r1"));
//
//        // dir name ignored
//        assert (filter.accept(new File("bar"), "foo.r9"));
//
//        // only single digit at end
//        assertFalse(filter.accept(null, "foo.r10"));
//
//        // only single digit at end
//        assertFalse(filter.accept(null, "foo.rbar"));
//
//        // the most common usage. *.0
//        assertTrue(filter.accept(null, "foo.r0"));
//
//    }
    public static boolean deleteDir(File dir) {
		if (dir.isDirectory()) {
			String[] dirContent = dir.list();
			for (int i=0; i<dirContent.length; i++){
				boolean success = deleteDir(new File(dir, dirContent[i]));
				if (!success) {
					return false;
				}
			}
		} // The directory is now empty so delete it
		return dir.delete();
	}
    @After
    public void tearDown() throws Exception {
        //this.testCrl1.deleteFile();
        deleteDir(this.testCrl1.getTempFile());
    }

}
