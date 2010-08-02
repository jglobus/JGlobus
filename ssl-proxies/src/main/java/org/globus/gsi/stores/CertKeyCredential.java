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

import org.globus.gsi.CredentialException;
import org.globus.gsi.X509Credential;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;

import org.apache.commons.io.FileUtils;
import org.springframework.core.io.Resource;

/**
 * Fill Me
 */

public class CertKeyCredential implements SecurityObjectWrapper<X509Credential>, Storable, CredentialWrapper {

    protected Resource certFile;
    protected Resource keyFile;

    private long certLastModified = -1;
    private long keyLastModified = -1;
    private X509Credential credential;
    private boolean changed;

    public CertKeyCredential(Resource certResource, Resource keyResource) throws ResourceStoreException {
        init(certResource, keyResource);
    }

    public CertKeyCredential(Resource certResource, Resource keyResource, X509Credential credential)
            throws ResourceStoreException {
        this.certFile = certResource;
        try {
            if (!certResource.exists()) {
                FileUtils.touch(certResource.getFile());
                this.certLastModified = certResource.lastModified();
            }
            this.keyFile = keyResource;
            if (!keyResource.exists()) {
                FileUtils.touch(keyResource.getFile());
                this.keyLastModified = keyResource.lastModified();
            }
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        }
        this.credential = credential;
    }

    protected void init(Resource initCertResource, Resource initKeyResource) throws ResourceStoreException {

        if ((initCertResource == null) || (initKeyResource == null)) {
            throw new IllegalArgumentException();
        }

        this.certFile = initCertResource;
        this.keyFile = initKeyResource;
        this.credential = createObject(this.certFile, this.keyFile);
        try {
            this.certLastModified = this.certFile.lastModified();
            this.keyLastModified = this.keyFile.lastModified();
        } catch (IOException ioe) {
            throw new ResourceStoreException(ioe);
        }
    }

    protected void init(Resource initCertFile, Resource keyResource, X509Credential initCredential)
            throws ResourceStoreException {

        if (initCredential == null) {
            // FIXME: better exception?
            throw new IllegalArgumentException("Object cannot be null");
        }
        this.credential = initCredential;
        this.certFile = initCertFile;
        this.keyFile = keyResource;
    }


    public void refresh() throws ResourceStoreException {
        long cLatestLastModified;
        long kLatestLastModified;
        this.changed = false;
        try {
            cLatestLastModified = this.certFile.lastModified();
            kLatestLastModified = this.keyFile.lastModified();
        } catch (IOException ioe) {
            throw new ResourceStoreException(ioe);
        }
        if ((this.certLastModified < cLatestLastModified) || (this.keyLastModified < kLatestLastModified)) {
            this.credential = createObject(this.certFile, this.keyFile);
            this.certLastModified = cLatestLastModified;
            this.keyLastModified = kLatestLastModified;
            this.changed = true;
        }
    }

    public Resource getCertificateFile() {
        return this.certFile;
    }

    public Resource getKeyFile() {
        return this.keyFile;
    }

    // for creation of credential from a file

    protected X509Credential createObject(Resource certSource, Resource keySource)
            throws ResourceStoreException {
        InputStream certIns;
        InputStream keyIns;
        try {
            certIns = certSource.getInputStream();
            keyIns = keySource.getInputStream();
            return new X509Credential(certIns, keyIns);
        } catch (FileNotFoundException e) {
            throw new ResourceStoreException(e);
        } catch (CredentialException e) {
            throw new ResourceStoreException(e);
        } catch (IOException ioe) {
            throw new ResourceStoreException(ioe);
        }
    }

    public X509Credential getSecurityObject() throws ResourceStoreException {
        refresh();
        return credential;
    }

    public boolean hasChanged() {
        return this.changed;
    }

    public X509Credential getCredential() throws ResourceStoreException {
        return getSecurityObject();
    }

    public void store() throws ResourceStoreException {
        try {
            this.credential.writeToFile(this.certFile.getFile(), this.keyFile.getFile());
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        } catch (CertificateEncodingException e) {
            throw new ResourceStoreException(e);
        }
    }

    public String getAlias() {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }
}
