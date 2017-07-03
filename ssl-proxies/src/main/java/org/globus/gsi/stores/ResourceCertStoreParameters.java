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

import java.security.cert.CertStoreParameters;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 29, 2009
 * Time: 1:06:39 PM
 * To change this template use File | Settings | File Templates.
 */
public class ResourceCertStoreParameters implements CertStoreParameters {

    private String certLocationPattern;
    private String crlLocationPattern;

    /**
     * Please use the {@link Stores} class to generate Key/Cert stores
     */
    public ResourceCertStoreParameters(String certLocationPattern, String crlLocationPattern) {
        this.certLocationPattern = certLocationPattern;
        this.crlLocationPattern = crlLocationPattern;
    }

//    public ResourceCertStoreParameters(String... initLocations) {
//        if (initLocations != null) {
//            this.certLocations = new String[initLocations.length];
//            System.arraycopy(initLocations, 0, this.certLocations, 0, initLocations.length);
//        }
//    }

//    public String[] getCertLocations() {
//        String[] returnArray = new String[certLocations.length];
//        System.arraycopy(certLocations, 0, returnArray, 0, certLocations.length);
//        return returnArray;
//    }

    public String getCrlLocationPattern() {
        return crlLocationPattern;
    }


    public String getCertLocationPattern() {
        return certLocationPattern;
    }


    /**
     * Makes a copy of this <code>CertStoreParameters</code>.
     * <p>
     * The precise meaning of "copy" may depend on the class of the
     * <code>CertStoreParameters</code> object. A typical implementation
     * performs a "deep copy" of this object, but this is not an absolute
     * requirement. Some implementations may perform a "shallow copy" of some or
     * all of the fields of this object.
     * <p>
     * Note that the <code>CertStore.getInstance</code> methods make a copy of
     * the specified <code>CertStoreParameters</code>. A deep copy
     * implementation of <code>clone</code> is safer and more robust, as it
     * prevents the caller from corrupting a shared <code>CertStore</code> by
     * subsequently modifying the contents of its initialization parameters.
     * However, a shallow copy implementation of <code>clone</code> is more
     * appropriate for applications that need to hold a reference to a parameter
     * contained in the <code>CertStoreParameters</code>. For example, a shallow
     * copy clone allows an application to release the stores of a particular
     * <code>CertStore</code> initialization parameter immediately, rather than
     * waiting for the garbage collection mechanism. This should be done with
     * the utmost care, since the <code>CertStore</code> may still be in use by
     * other threads.
     * <p>
     * Each subclass should state the precise behavior of this method so that
     * users and developers know what to expect.
     *
     * @return a copy of this <code>CertStoreParameters</code>
     */
    public Object clone() {
        try {
            return super.clone();
        } catch (CloneNotSupportedException e) {
            /* Cannot happen */
            throw new InternalError(e.toString());
        }
    }

}
