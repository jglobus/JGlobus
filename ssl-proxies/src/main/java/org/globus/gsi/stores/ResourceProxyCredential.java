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
import org.globus.gsi.CredentialException;
import org.globus.gsi.X509Credential;
import org.globus.util.GlobusResource;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;

/**
 * JGLOBUS-87 : document me
 *
 * @author Tom Howe
 */
public class ResourceProxyCredential extends AbstractResourceSecurityWrapper<X509Credential>
        implements CredentialWrapper {

    private static final SecurityObjectFactory<X509Credential> FACTORY =
            new SecurityObjectFactory<X509Credential>() {
                private Log logger = LogFactory.getLog(getClass());

                public X509Credential create(GlobusResource globusResource)
                        throws ResourceStoreException {
                    InputStream keyInputStream = null;
                    InputStream certInputStream = null;
                    try {
                        keyInputStream = new BufferedInputStream(globusResource.getInputStream());
                        certInputStream = new BufferedInputStream(globusResource.getInputStream());
                        return new X509Credential(keyInputStream, certInputStream);
                    } catch (IOException e) {
                        throw new ResourceStoreException(e);
                    } catch (CredentialException e) {
                        throw new ResourceStoreException(e);
                    } finally {

                        if (keyInputStream != null) {
                            try {
                                keyInputStream.close();
                            } catch (Exception e) {
                                logger.warn("Unable to close stream.");
                            }
                        }
                        if (certInputStream != null) {
                            try {
                                certInputStream.close();
                            } catch (Exception e) {
                                logger.warn("Unable to close stream.");
                            }
                        }
                    }
                }
            };

    public ResourceProxyCredential(String locationPattern) throws ResourceStoreException {
    	super(FACTORY, false, locationPattern);
    }

    public ResourceProxyCredential(GlobusResource globusResource) throws ResourceStoreException {
    	super(FACTORY, false, globusResource);
    }

    public ResourceProxyCredential(String filename, X509Credential object) throws ResourceStoreException {
    	super(FACTORY, false, filename, object);
    }

    public ResourceProxyCredential(boolean inMemory, GlobusResource globusResource, X509Credential object) throws ResourceStoreException {
    	super(FACTORY, inMemory, globusResource, object);
    }

    public X509Credential getCredential() throws ResourceStoreException {
        return getSecurityObject();
    }

    public void store() throws ResourceStoreException {
        try {
            X509Credential credential = getCredential();
            credential.writeToFile(globusResource.getFile());
        } catch (IOException ioe) {
            throw new ResourceStoreException(ioe);
        } catch (CertificateEncodingException e) {
            throw new ResourceStoreException(e);
        }
    }
}
