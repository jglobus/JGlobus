/*
 * Copyright 2006-2009 University of Illinois
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.globus.gridshib.security.x509;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * An arbitrary, non-critical X.509 extension.
 *
 * @see org.globus.gridshib.security.x509.X509Extension
 *
 * @since 0.3.0
 */
public class NonCriticalX509Extension extends X509Extension {

    static Log logger =
        LogFactory.getLog(NonCriticalX509Extension.class.getName());

    /**
     * The criticality of a non-critical certificate
     * extension is false by definition.
     */
    protected static final boolean CRITICAL = false;

    /**
     * Creates an instance of <code>NonCriticalX509Extension</code>
     * with the given OID.  The extension is marked as non-critical.
     * <p>
     * The initial value of an instance created with this
     * constructor is null.  Call the
     * {@link org.globus.gsi.X509Extension#setValue(byte[])}
     * method of the superclass to set the value of this
     * extension.
     *
     * @param oid the OID of the certificate extension
     */
    public NonCriticalX509Extension(String oid) {
        super(oid);
        super.setCritical(CRITICAL);
    }

    /**
     * Creates an instance of <code>NonCriticalX509Extension</code>
     * with the given OID and value.  The extension is marked as
     * non-critical.
     *
     * @param oid the OID of the certificate extension
     * @param value the byte value of the certificate extension
     *              (not octet string encoded)
     */
    public NonCriticalX509Extension(String oid, byte[] value) {
        super(oid, CRITICAL, value);
    }

    /**
     * This method does nothing.  It simply preserves the criticality
     * of this <code>NonCriticalX509Extension</code> instance.
     *
     * @see X509Extension#setCritical(boolean)
     */
    public final void setCritical(boolean critical) { return; }
}
