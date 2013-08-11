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

package org.globus.opensaml11.saml.provider;

import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeMap;

import org.globus.opensaml11.saml.ReplayCache;
import org.globus.opensaml11.saml.SAMLConfig;
import org.globus.opensaml11.saml.SAMLException;

/**
 *  Interface to a potentially persistent replay cache for uniquely-keyed objects
 *
 * @author     Scott Cantor (created February 3, 2005)
 */
public class MemoryReplayCacheProvider implements ReplayCache
{
    private TreeMap replayExpMap = new TreeMap();
    private HashSet replayCache = new HashSet();
    private int skew = 1000 * SAMLConfig.instance().getIntProperty("org.globus.opensaml11.saml.clock-skew");

    public MemoryReplayCacheProvider(org.w3c.dom.Element e) {
    }

    /**
     *  Checks the replay cache for the existence of a key value and if not,
     *  inserts the new key with the specified expiration time.
     *
     * @param key   The key value to search for and insert
     * @param expires   A time at which this key can be forgotten
     * @return  true iff the key does not exist or has expired
     * @exception   SAMLException   Raised if an error occurs while checking the cache
     */
    public boolean check(String key, Date expires) throws SAMLException
    {
        synchronized(this) {
            // Garbage collect any expired entries.
            Set trash = replayExpMap.headMap(new Long(expires.getTime()-skew)).keySet();
            for (Iterator i = trash.iterator(); i.hasNext(); replayCache.remove(replayExpMap.get(i.next())))
                ;
            trash.clear();

            // If it's already been seen, bail.
            if (!replayCache.add(key))
                return false;

            // Not a multi-map, so if there's duplicate timestamp, increment by a millisecond.
            long stamp = expires.getTime() + skew;
            while (replayExpMap.containsKey(new Long(stamp)))
                stamp++;

            // Add the pair to the expiration map.
            replayExpMap.put(new Long(stamp), key);
            return true;
        }
    }
}
