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
import org.globus.gsi.util.CertificateIOUtil;
import org.globus.gsi.util.CertificateLoadUtil;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;

import org.springframework.core.io.Resource;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 29, 2009
 * Time: 11:37:52 AM
 * To change this template use File | Settings | File Templates.
 */
public class ResourceTrustAnchor extends AbstractResourceSecurityWrapper<TrustAnchor> {
	private Log logger = LogFactory.getLog(getClass().getCanonicalName());

    public ResourceTrustAnchor(String fileName) throws ResourceStoreException {
        init(resolver.getResource(fileName));
    }

    public ResourceTrustAnchor(Resource resource) throws ResourceStoreException {
        init(resource);
    }

    public ResourceTrustAnchor(String fileName, TrustAnchor cachedAnchor) throws ResourceStoreException {
        init(resolver.getResource(fileName), cachedAnchor);
    }

    public ResourceTrustAnchor(Resource resource, TrustAnchor cachedAnchor) throws ResourceStoreException {
        init(resource, cachedAnchor);
    }

    public TrustAnchor getTrustAnchor() throws ResourceStoreException {
        return super.getSecurityObject();
    }

    @Override
    protected TrustAnchor create(Resource resource) throws ResourceStoreException {
        X509Certificate certificate;
        InputStream inputStream = null;
        try {
        	inputStream = resource.getInputStream();
            certificate = CertificateLoadUtil.loadCertificate(inputStream);
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        } catch (GeneralSecurityException e) {
            throw new ResourceStoreException(e);
        }finally{
        	try {
        		if(inputStream != null){
        			inputStream.close();
        		}
			} catch (IOException e) {
				logger.warn("Unable to close stream.");
			}
        }

        return new TrustAnchor(certificate, null);
    }

    public void store() throws ResourceStoreException {
        try {
            CertificateIOUtil.writeCertificate(this.getTrustAnchor().getTrustedCert(), resource.getFile());
        } catch (CertificateEncodingException e) {
            throw new ResourceStoreException(e);
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        }
    }
}
