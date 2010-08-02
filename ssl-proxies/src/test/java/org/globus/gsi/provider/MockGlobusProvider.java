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

import java.security.Provider;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class MockGlobusProvider extends Provider {

    public MockGlobusProvider() {

        super("GlobusTest", 1.0, "Globus Security Providers");
        put("CertStore.MockCertStore", MockCertStore.class.getCanonicalName());
        put("KeyStore.MockKeyStore", MockKeyStore.class.getCanonicalName());
    }
}

