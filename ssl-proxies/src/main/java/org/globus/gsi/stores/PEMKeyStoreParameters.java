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

import java.security.KeyStore;
import java.security.KeyStore.ProtectionParameter;

/**
 * This parameter class provides all of the options for creating a FileBasedKeyStore.
 * <p>
 * It is immutable.
 *
 * @version ${vesion}
 * @since 1.0
 */
public class PEMKeyStoreParameters
        implements KeyStore.LoadStoreParameter {

    private String certDirs;
    private String defaultCertDir;
    private String userCertFilename;
    private String userKeyFilename;
    private KeyStore.ProtectionParameter protectionParameter;
    private String proxyFilename;

    /**
     * This is the simplest constructor which only accepts a directory where all of the security material is stored.
     * New security material written to this KeyStore will be stored in this directory as well.
     *
     * @param initDefaultCertDir The directory for storage of security material
     */
    public PEMKeyStoreParameters(String initDefaultCertDir) {
        this.defaultCertDir = initDefaultCertDir;
    }

    /**
     * This is a slightly more complicated constructor which allows the user to specify one or more directory where the
     * certificates are currently stored.  The user can also specify a default directory where new security material
     * can be stored.
     *
     * @param initCertDirs       Directories where security material exists.
     * @param initDefaultCertDir A default directory for the storage of security material
     */
    public PEMKeyStoreParameters(String initCertDirs, String initDefaultCertDir) {
        this.certDirs = initCertDirs;
        this.defaultCertDir = initDefaultCertDir;
    }

    /**
     * A Constructor supporting the initial storage directories for the certificates, the default storage directory,
     * the filename of the user's certificate file, the file name of the user's key file and a ProtectionParameter.
     *
     * @param initCertDirs            Directories where security material exists.
     * @param initDefaultCertDir      A default directory for the storage of security material.
     * @param initUserCertFileName    The file name for the user's certificate.
     * @param initUserKeyFileName     The file name for the user's key.
     * @param initProtectionParameter A protection parameter for this keystore.
     */
    public PEMKeyStoreParameters(String initCertDirs, String initDefaultCertDir, String initUserCertFileName,
                                       String initUserKeyFileName, ProtectionParameter initProtectionParameter) {
        this(initCertDirs, initDefaultCertDir);
        this.userCertFilename = initUserCertFileName;
        this.userKeyFilename = initUserKeyFileName;
        this.protectionParameter = initProtectionParameter;
    }

    /**
     * This constructor is for users who have a proxy certificate in addition to other security materials.
     *
     * @param initCertDirs       Directories where security material exists.
     * @param initDefaultCertDir A default directory for the storage of security material.
     * @param initProxyFileName  The file name for the user's proxy certificate.
     */
    public PEMKeyStoreParameters(String initCertDirs, String initDefaultCertDir, String initProxyFileName) {
        this(initCertDirs, initDefaultCertDir);
        this.proxyFilename = initProxyFileName;
    }

    /**
     * This is the full constructor for users with proxy certificates.
     *
     * @param initCertDirs            Directories where security material exists.
     * @param initDefaultCertDir      A default directory for the storage of security material.
     * @param initUserCertFileName    The file name for the user's certificate.
     * @param initUserKeyFileName     The file name for the user's key.
     * @param initProtectionParameter A protection parameter for this keystore.
     * @param initProxyFileName       The file name for the user's proxy certificate.
     */
    public PEMKeyStoreParameters(String initCertDirs, String initDefaultCertDir, String initUserCertFileName,
                                       String initUserKeyFileName, ProtectionParameter initProtectionParameter,
                                       String initProxyFileName) {
        this(initCertDirs, initDefaultCertDir, initUserCertFileName, initUserKeyFileName, initProtectionParameter);
        this.proxyFilename = initProxyFileName;
    }

    public ProtectionParameter getProtectionParameter() {
        return this.protectionParameter;
    }

    public String getCertDirs() {
        return certDirs;
    }

    public String getDefaultCertDir() {
        return defaultCertDir;
    }

    public String getUserCertFilename() {
        return this.userCertFilename;
    }

    public String getUserKeyFilename() {
        return this.userKeyFilename;
    }

    public String getProxyFilename() {
        return this.proxyFilename;
    }
}
