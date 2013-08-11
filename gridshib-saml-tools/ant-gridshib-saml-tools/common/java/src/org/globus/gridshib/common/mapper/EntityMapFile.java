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

import java.io.File;
import java.security.cert.X509Certificate;
import java.net.URI;
import java.util.Iterator;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.LoadException;
import org.globus.gridshib.common.SetMapFile;

/**
 * An implementation of the <code>EntityMap</code> interface
 * backed by a <code>Loadable</code> map of <code>String</code>
 * into <code>Set</code> of <code>String</code> (i.e., a
 * <code>SetMap</code>).  Since this implementation extends
 * <code>SetMapFile</code>, the underlying resource is an
 * ordinary file in the filesystem.
 *
 * @see org.globus.gridshib.common.mapper.EntityMap
 * @see org.globus.gridshib.common.SetMapFile
 */
public class EntityMapFile extends SetMapFile implements EntityMap  {

    private static Log logger =
        LogFactory.getLog(EntityMapFile.class.getName());

    /**
     * @see org.globus.gridshib.common.SetMapFile
     */
    public EntityMapFile(URI uri) throws LoadException {
        super(uri);
    }

    /**
     * @see org.globus.gridshib.common.SetMapFile
     */
    public EntityMapFile(String pathname) throws LoadException {
        super(pathname);
    }

    /**
     * @see org.globus.gridshib.common.SetMapFile
     */
    public EntityMapFile(File file) throws LoadException {
        super(file);
    }

    /**
     * @see org.globus.gridshib.common.mapper.EntityMap
     */
    public boolean hasMetadata(String entityID) {
        try {
            boolean b = getKeySet().contains(entityID);
            logger.info("Mapping contains entityID " + entityID);
            return b;
        } catch (LoadException e) {
            String msg = "Unable to reload mapping";
            logger.error(msg, e);
            return false;
        }
    }

    /**
     * @see org.globus.gridshib.common.mapper.EntityMap
     *
     * @since 0.6.0
     */
    public Set getDNs(String entityID) {
        try {
            Set dns = getImageSet(entityID);
            if (dns == null) {
                logger.info("Unable to map entityID (" + entityID + ")");
            } else {
                logger.info("Mapped entityID (" + entityID +
                            ") to DNs: " + dns.toString());
            }
            return dns;
        } catch (LoadException e) {
            String msg = "Unable to reload mapping while trying to " +
                         "map entityID (" + entityID + ")";
            logger.error(msg, e);
            return null;
        }
    }

    /**
     * Gets a trusted X.500 distinguished name (DN) for
     * the given SAML entity.  Returns an arbitrary element
     * taken from the set of elements obtained by invoking the
     * {@link #getDNs(String)} method.
     *
     * @param entityID the unique identifier of the entity
     * @return         a corresponding DN in RFC2253 format,
     *                 or null if no such DN exists
     *
     * @see org.globus.gridshib.common.mapper.EntityMap
     */
    public String getDN(String entityID) {

        Set dns = getDNs(entityID);
        if (dns == null) {
            return null;
        } else {
            Iterator i = dns.iterator();
            if (i.hasNext()) {
                return (String)i.next();
            } else {
                return null;
            }
        }
    }

    /**
     * This flat file-based implementation of the
     * <code>EntityMap</code> interface does not
     * encode certificates, so this method always
     * returns null.
     *
     * @see org.globus.gridshib.common.mapper.EntityMap
     */
    public X509Certificate getX509Certificate(String entityID) {
        return null;
    }
}
