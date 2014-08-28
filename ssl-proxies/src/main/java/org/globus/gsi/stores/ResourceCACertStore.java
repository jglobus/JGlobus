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

import org.apache.commons.logging.Log;

import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.io.FilenameFilter;
import java.security.cert.TrustAnchor;

import org.globus.util.GlobusResource;


/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 29, 2009
 * Time: 11:49:20 AM
 * To change this template use File | Settings | File Templates.
 */
public class ResourceCACertStore extends ResourceSecurityWrapperStore<ResourceTrustAnchor, TrustAnchor> {

    private static FilenameFilter filter = new TrustAnchorFilter();
    private Log logger = LogFactory.getLog(getClass().getCanonicalName());

    @Override
    public ResourceTrustAnchor create(GlobusResource globusResource) throws ResourceStoreException {
        return new ResourceTrustAnchor(false, globusResource);
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
     * File filter for determining a Trust Anchor
     */
    public static class TrustAnchorFilter implements FilenameFilter {

        public boolean accept(File dir, String file) {

            if (file == null) {
                throw new IllegalArgumentException();
            }
            int length = file.length();
            return length > 2
                    && file.charAt(length - 2) == '.'
                    && file.charAt(length - 1) >= '0'
                    && file.charAt(length - 1) <= '9';
        }
    }
}
