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
import org.globus.util.GlobusResource;

/**
 * Fill Me
 */

public class CertKeyCredential implements SecurityObjectWrapper<X509Credential>, Storable, CredentialWrapper {

    protected GlobusResource globusCertFile;
    protected GlobusResource globusKeyFile;

    private long certLastModified = -1;
    private long keyLastModified = -1;
    private X509Credential credential;
    private boolean changed;

    public CertKeyCredential(GlobusResource certResource, GlobusResource keyResource) throws ResourceStoreException {
        init(certResource, keyResource);
    }

    public CertKeyCredential(GlobusResource certResource, GlobusResource keyResource, X509Credential credential)
            throws ResourceStoreException {
        this.globusCertFile = certResource;
        try {
            if (!certResource.exists()) {
                FileUtils.touch(certResource.getFile());
                this.certLastModified = certResource.lastModified();
            }
            this.globusKeyFile = keyResource;
            if (!keyResource.exists()) {
                FileUtils.touch(keyResource.getFile());
                this.keyLastModified = keyResource.lastModified();
            }
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        }
        this.credential = credential;
    }

    protected void init(GlobusResource initCertResource, GlobusResource initKeyResource) throws ResourceStoreException {

        if ((initCertResource == null) || (initKeyResource == null)) {
            throw new IllegalArgumentException();
        }

        this.globusCertFile = initCertResource;
        this.globusKeyFile = initKeyResource;
        this.credential = createObject(this.globusCertFile, this.globusKeyFile);
        try {
            this.certLastModified = this.globusCertFile.lastModified();
            this.keyLastModified = this.globusKeyFile.lastModified();
        } catch (IOException ioe) {
            throw new ResourceStoreException(ioe);
        }
    }

    protected void init(GlobusResource initCertFile, GlobusResource keyResource, X509Credential initCredential)
            throws ResourceStoreException {

        if (initCredential == null) {
            // JGLOBUS-88 : better exception?
            throw new IllegalArgumentException("Object cannot be null");
        }
        this.credential = initCredential;
        this.globusCertFile = initCertFile;
        this.globusKeyFile = keyResource;
    }

    public void refresh() throws ResourceStoreException {
        long cLatestLastModified;
        long kLatestLastModified;
        this.changed = false;
        try {
            cLatestLastModified = this.globusCertFile.lastModified();
            kLatestLastModified = this.globusKeyFile.lastModified();
        } catch (IOException ioe) {
            throw new ResourceStoreException(ioe);
        }
        if ((this.certLastModified < cLatestLastModified) || (this.keyLastModified < kLatestLastModified)) {
            this.credential = createObject(this.globusCertFile, this.globusKeyFile);
            this.certLastModified = cLatestLastModified;
            this.keyLastModified = kLatestLastModified;
            this.changed = true;
        }
    }

    public GlobusResource getCertificateFile() {
        return this.globusCertFile;
    }

    public GlobusResource getKeyFile() {
        return this.globusKeyFile;
    }

    // for creation of credential from a file
    protected X509Credential createObject(GlobusResource certSource, GlobusResource keySource)
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
            this.credential.writeToFile(this.globusCertFile.getFile(), this.globusKeyFile.getFile());
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
