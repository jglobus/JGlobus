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

import org.globus.gsi.util.CertificateLoadUtil;
import org.globus.util.GlobusResource;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.cert.X509CRL;

public class ResourceCRL extends AbstractResourceSecurityWrapper<X509CRL> {

    private static final SecurityObjectFactory<X509CRL> FACTORY =
            new SecurityObjectFactory<X509CRL>() {
                public X509CRL create(GlobusResource resource) throws ResourceStoreException {
                    try {
                        InputStream is = resource.getInputStream();
                        try {
                            return CertificateLoadUtil.loadCrl(new BufferedInputStream(is));
                        } finally {
                            try {
                                is.close();
                            } catch (IOException ignored) {
                            }
                        }
                    } catch (IOException e) {
                        throw new ResourceStoreException(e);
                    } catch (GeneralSecurityException e) {
                        throw new ResourceStoreException(e);
                    }
                }
            };

    public ResourceCRL(String fileName) throws ResourceStoreException {
    	super(FACTORY, false, fileName);
    }

    public ResourceCRL(boolean inMemory, GlobusResource globusResource) throws ResourceStoreException {
    	super(FACTORY, inMemory, globusResource);
    }

    public ResourceCRL(String fileName, X509CRL crl) throws ResourceStoreException {
    	super(FACTORY, false, fileName, crl);
    }

    public X509CRL getCrl() throws ResourceStoreException {
        return getSecurityObject();
    }

    public void store() throws ResourceStoreException {
        //TODO: does this need an implementation
    }
}
