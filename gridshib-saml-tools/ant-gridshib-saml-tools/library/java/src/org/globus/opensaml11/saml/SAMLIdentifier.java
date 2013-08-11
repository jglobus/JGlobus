/*
 *  Copyright 2001-2005 Internet2
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.globus.opensaml11.saml;

import java.security.SecureRandom;

/**
 *  Encapsulates generation of identifiers and pseudo-random data for SAML objects
 *
 * @author     Scott Cantor (created February 3, 2005)
 * @author     Tom Scavo
 */
public interface SAMLIdentifier
{
    /**
     *  Obtains a new identifier in string form
     *
     * @return  The identifier in string form
     * @exception   org.globus.opensaml11.saml.SAMLException   Raised if a problem occurs while generating the value
     */
    public String getIdentifier() throws SAMLException;

    /**
     * <p>Generate a sequence of random bytes using the
     * given <code>SecureRandom</code> object.</p>
     *
     * @param random a secure random number generator
     * @param n the number of random bytes to generate
     * @return the random bytes or null if the
     *         <code>random</code> argument is null
     *
     * @see java.security.SecureRandom
     */
    public byte[] generateRandomBytes(SecureRandom random, int n);

    /**
     * <p>Generate a sequence of random bytes.
     *
     * @param n the number of random bytes to generate
     * @return the random bytes
     *
     */
    public byte[] generateRandomBytes(int n);
}
