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
import org.globus.gsi.stores.ResourceTrustAnchor;
import org.globus.gsi.testutils.FileSetupUtil;

import java.io.File;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import org.globus.common.CoGProperties;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class TestFileBasedTrustAnchor {

    FileSetupUtil testCert1;

    @Before
    public void setUp() throws Exception {

        CoGProperties.getDefault().setProperty(CoGProperties.CRL_CACHE_LIFETIME, "1");
        CoGProperties.getDefault().setProperty(CoGProperties.CERT_CACHE_LIFETIME, "1");
        this.testCert1 = new FileSetupUtil("certificateUtilTest/1c3f2ca8.0");
    }


    @Test
    public void testGetTrustAnchor() throws Exception {

        this.testCert1.copyFileToTemp();

        String tempFileURL = this.testCert1.getURL().toExternalForm();

        ResourceTrustAnchor fileAnchor = new ResourceTrustAnchor("classpath:/certificateUtilTest/1c3f2ca8.0");

//        assert (fileAnchor != null);

        TrustAnchor anchor = fileAnchor.getSecurityObject();

        assert (anchor != null);

        X509Certificate cert = anchor.getTrustedCert();
        assert (cert != null);

        assertFalse(fileAnchor.hasChanged());

        anchor = fileAnchor.getSecurityObject();

        assert (anchor != null);

        assertFalse(fileAnchor.hasChanged());

        fileAnchor = new ResourceTrustAnchor(tempFileURL);

        this.testCert1.modifyFile();

        anchor = fileAnchor.getSecurityObject();

        assert (anchor != null);

        assertTrue(fileAnchor.hasChanged());

    }


//    @Test
//    public void testGetTrustAnchorFilter() {
//
//        FilenameFilter filter = new TrustAnchorFilter();
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
//        assert (filter.accept(null, "foo.1"));
//
//        // dir name ignored
//        assert (filter.accept(new File("bar"), "foo.9"));
//
//        // only single digit at end
//        assertFalse(filter.accept(null, "foo.10"));
//
//        // only single digit at end
//        assertFalse(filter.accept(null, "foo.bar"));
//
//        // the most common usage. *.0
//        assertTrue(filter.accept(null, "foo.0"));
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
    public void tearDown() {

        //this.testCert1.deleteFile();
        deleteDir(this.testCert1.getTempFile());
    }
}
