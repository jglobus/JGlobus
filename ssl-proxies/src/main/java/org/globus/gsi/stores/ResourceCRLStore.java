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

package org.globus.gsi.stores;

import org.apache.commons.logging.LogFactory;

import org.apache.commons.logging.Log;

import java.io.File;
import java.io.FilenameFilter;
import java.security.cert.X509CRL;


import org.globus.util.GlobusResource;

/**
 * Fill Me
 */
public class ResourceCRLStore extends ResourceSecurityWrapperStore<ResourceCRL, X509CRL> {

    private static CrlFilter filter = new CrlFilter();
    private static final int MIN_NAME_LENGTH = 3;
    private Log logger = LogFactory.getLog(getClass().getCanonicalName());

    @Override
    public ResourceCRL create(GlobusResource globusResource) throws ResourceStoreException {
        return new ResourceCRL(false, globusResource);
    }

    @Override
    protected Log getLog() {
        return logger;
    }

    @Override
    public FilenameFilter getDefaultFilenameFilter() {
        return filter;
    }

    /**
     * This filter identifies file whose names are valid for crl files.
     */
    public static class CrlFilter implements FilenameFilter {

        public boolean accept(File dir, String file) {

            if (file == null) {
                throw new IllegalArgumentException();
            }

            int length = file.length();

            return length > MIN_NAME_LENGTH && file.endsWith(".r09");
        }
    }
}
