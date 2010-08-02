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
package org.globus.gsi.proxy;

import org.globus.gsi.proxy.ext.ProxyCertInfo;

import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;

/**
 * A restricted proxy policy handler interface. All policy handlers must
 * implement this interface.
 */
public interface ProxyPolicyHandler {

    /**
     * @param proxyCertInfo the <code>ProxyCertInfo</code> extension found in
     *                      the restricted proxy certificate.
     * @param certPath      the certificate path being validated.
     * @param index         the index of the certificate in the certPath that is
     *                      being validated - the index of the restricted proxy
     *                      certificate.
     * @throws CertPathValidatorException if policy validation fails.
     */
    void validate(
            ProxyCertInfo proxyCertInfo,
            CertPath certPath,
            int index)
            throws CertPathValidatorException;
}
