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
package org.globus.gsi.provider;

import javax.security.auth.x500.X500Principal;

import org.globus.gsi.SigningPolicy;

/**
 * // FIXME: Maybe a provider  access to this?
 */
public interface SigningPolicyStore {

    /**
     * FixMe: Document me
     *
     * @param caPrincipal Document Me.
     * @return Document Me.
     * @throws SigningPolicyStoreException Document Me.
     */
    SigningPolicy getSigningPolicy(X500Principal caPrincipal) throws SigningPolicyStoreException;
}
