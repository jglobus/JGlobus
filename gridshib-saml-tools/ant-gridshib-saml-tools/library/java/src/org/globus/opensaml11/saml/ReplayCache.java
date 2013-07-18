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

/**
 *  Interface to a potentially persistent replay cache for uniquely-keyed objects
 *
 * @author     Scott Cantor (created February 3, 2005)
 */
public interface ReplayCache
{
    /**
     *  Checks the replay cache for the existence of a key value and if not,
     *  inserts the new key with the specified expiration time.
     *
     * @param key   The key value to search for and insert
     * @param expires   A time at which this key can be forgotten
     * @return  true iff the key does not exist or has expired
     * @exception   SAMLException   Raised if an error occurs while checking the cache
     */
    public boolean check(String key, java.util.Date expires) throws SAMLException;
}
