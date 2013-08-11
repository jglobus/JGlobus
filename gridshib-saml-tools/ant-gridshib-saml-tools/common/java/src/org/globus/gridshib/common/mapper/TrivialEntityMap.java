/*
 * Copyright 2007-2009 University of Illinois
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.globus.gridshib.common.mapper;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * A trivial implementation of the <code>EntityMap</code>
 * interface such that each <code>entityID</code> maps
 * to a single DN.
 *
 * @see org.globus.gridshib.common.mapper.EntityMap
 *
 * @since 0.3.0
 */
public class TrivialEntityMap implements EntityMap  {

    private static Log logger =
        LogFactory.getLog(TrivialEntityMap.class.getName());

    private Map map = null;

    public TrivialEntityMap() {
        this.map = new HashMap();
    }

    public void addMapping(String entityID, String dn) {

        Set s = new HashSet(); s.add(dn);
        this.map.put(entityID, s);
    }

    /**
     * @see org.globus.gridshib.common.mapper.EntityMap
     */
    public boolean hasMetadata(String entityID) {
        return this.map.containsKey(entityID);
    }

    /**
     * @see org.globus.gridshib.common.mapper.EntityMap
     *
     * @since 0.6.0
     */
    public Set getDNs(String entityID) {

        Object o = this.map.get(entityID);
        if (o != null) { return (HashSet)o; }
        return null;
    }

    /**
     * Gets the trusted X.500 distinguished name (DN) for
     * the given SAML entity.
     *
     * @param entityID the unique identifier of the entity
     * @return         the corresponding DN in RFC2253 format,
     *                 or null if no such DN exists
     *
     * @see org.globus.gridshib.common.mapper.EntityMap
     */
    public String getDN(String entityID) {

        Set dns = getDNs(entityID);
        if (dns == null) {
            return null;
        } else {
            assert dns.iterator().hasNext();
            return (String)dns.iterator().next();
        }
    }

    /**
     * @see org.globus.gridshib.common.mapper.EntityMap
     */
    public X509Certificate getX509Certificate(String entityID) {
        return null;
    }
}
