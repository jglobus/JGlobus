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

import org.globus.gsi.util.CertificateIOUtil;
import org.globus.gsi.util.CertificateLoadUtil;
import org.globus.util.GlobusResource;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;


/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 29, 2009
 * Time: 11:37:52 AM
 * To change this template use File | Settings | File Templates.
 */
public class ResourceTrustAnchor extends AbstractResourceSecurityWrapper<TrustAnchor> {


    public ResourceTrustAnchor(String fileName) throws ResourceStoreException {
    	super(false);
        init(globusResolver.getResource(fileName));
    }

    public ResourceTrustAnchor(boolean inMemory, GlobusResource globusResource) throws ResourceStoreException {
    	super(inMemory);
        init(globusResource);
    }

    public ResourceTrustAnchor(String fileName, TrustAnchor cachedAnchor) throws ResourceStoreException {
    	super(false);
        init(globusResolver.getResource(fileName), cachedAnchor);
    }

    public ResourceTrustAnchor(boolean inMemory, GlobusResource globusResource, TrustAnchor cachedAnchor) throws ResourceStoreException {
    	super(inMemory);
        init(globusResource, cachedAnchor);
    }

    public TrustAnchor getTrustAnchor() throws ResourceStoreException {
        return super.getSecurityObject();
    }

    @Override
    protected TrustAnchor create(GlobusResource globusResource) throws ResourceStoreException {
        X509Certificate certificate;
        try {
            InputStream inputStream = globusResource.getInputStream();
            try {
                certificate = CertificateLoadUtil.loadCertificate(new BufferedInputStream(inputStream));
            } finally {
                try {
                    inputStream.close();
                } catch (IOException ignored) {
                }
            }
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        } catch (GeneralSecurityException e) {
            throw new ResourceStoreException(e);
        }

        return new TrustAnchor(certificate, null);
    }

    public void store() throws ResourceStoreException {
        try {
            CertificateIOUtil.writeCertificate(this.getTrustAnchor().getTrustedCert(), globusResource.getFile());
        } catch (CertificateEncodingException e) {
            throw new ResourceStoreException(e);
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        }
    }
}
