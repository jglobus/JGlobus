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
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.LoadException;

/**
 * The <em>GridShib Entity Mapper</em> is a container for
 * implementations of the <code>EntityMap</code> interface.
 * It provides an overarching API across a set of
 * registered entity mappings.  An <em>entity mapping</em>
 * maps a SAML entity to an X.509 entity, that is, for all
 * practical purposes it maps an entityID to a DN.  If such
 * a mapping exists, a relying party trusts the SAML entity
 * if and only if it trusts the X.509 entity.
 */
public class GridShibEntityMapper {

    private static Log logger =
        LogFactory.getLog(GridShibEntityMapper.class.getName());

    /**
     * A set of <code>EntityMap</code> instances registered
     * with this <code>GridShibEntityMapper</code>.
     */
    private static Set entityMappings = new LinkedHashSet();

    /**
     * Register an entity mapping with the GridShib Entity Mapper.
     *
     * @param map a non-null instance of the <code>EntityMap</code>
     *        interface
     * @return true if and only if the <code>EntityMap</code>
     *         instance was successfully registered
     */
    public static boolean register(EntityMap map) {

        if (map == null) {
            String msg = "Registration aborted: null map";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }

        return entityMappings.add(map);
    }

    /**
     * Register one or more entity mappings with the GridShib
     * Entity Mapper.  If the given path corresponds to an
     * ordinary file, an instance of <code>EntityMapFile</code>
     * is created.  If the given path corresponds to a
     * directory, an instance of <code>EntityMapDir</code> is
     * created.  In either case, method #register(EntityMap) is
     * invoked on the resulting instance.
     *
     * @param path a non-null path to one or more potential
     *        instances of the <code>EntityMap</code> interface
     * @return true if and only if the <code>EntityMap</code>
     *         instance corresponding to the given path was
     *         successfully registered
     *
     * @see org.globus.gridshib.common.mapper.EntityMapFile
     * @see org.globus.gridshib.common.mapper.EntityMapDir
     */
    public static boolean register(String path) throws LoadException {

        if (path == null) {
            String msg = "Registration aborted: null path";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }

        EntityMap entityMap = null;
        File file = new File(path);
        if (file.isFile()) {
            logger.debug("Entity map path is a file: " + path);
            entityMap = new EntityMapFile(file);
        } else if (file.isDirectory()) {
            logger.debug("Entity map path is a directory: " + path);
            entityMap = new EntityMapDir(file);
        } else {
            String msg = "Entity map path is neither a file " +
                         "nor a directory: " + path;
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }

        return register(entityMap);
    }

    /**
     * Determines whether the SAML entity represented
     * by the given <code>entityID</code> has metadata.
     *
     * @param entityID the entityID of the SAML entity
     * @return true if and only if the SAML entity has
     *         metadata
     *
     * @see org.globus.gridshib.common.mapper.EntityMap
     */
    public static boolean hasMetadata(String entityID) {
        Iterator i = entityMappings.iterator();
        while (i.hasNext()) {
            if (((EntityMap)i.next()).hasMetadata(entityID)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Search all registered entity mappings for the
     * given <code>entityID</code> and return the set of
     * DNs associated with that entity.  Assume there is
     * at most one such entity mapping (i.e., stop
     * searching as soon as the <code>entityID</code>
     * is found).
     *
     * @param entityID the SAML entityID to be mapped
     * @return the corresponding set of DNs (if any)
     */
    public static Set getDNs(String entityID) {
        Set dns;
        Iterator i = entityMappings.iterator();
        while (i.hasNext()) {
            dns = ((EntityMap)i.next()).getDNs(entityID);
            if (dns != null) { return dns; }
        }
        return null;
    }

    /**
     * Search all registered entity mappings for the
     * given <code>entityID</code> and return the DN
     * associated with that entity.  Assume there is
     * at most one such entity mapping (i.e., stop
     * searching as soon as the <code>entityID</code>
     * is found).
     *
     * @param entityID the SAML entityID to be mapped
     * @return the corresponding DN (if any) in RFC2253 format
     */
    public static String getDN(String entityID) {
        String dn;
        Iterator i = entityMappings.iterator();
        while (i.hasNext()) {
            dn = ((EntityMap)i.next()).getDN(entityID);
            if (dn != null) { return dn; }
        }
        return null;
    }

    /**
     * Search all registered entity mappings for the
     * given <code>entityID</code> and return the X.509
     * certificate associated with that entity.  Assume
     * there is at most one such entity mapping to be found.
     *
     * @param entityID the SAML entityID to be mapped
     * @return the corresponding X.509 certificate (if any)
     */
    public static X509Certificate getX509Certificate(String entityID) {
        X509Certificate cert;
        Iterator i = entityMappings.iterator();
        while (i.hasNext()) {
            cert = ((EntityMap)i.next()).getX509Certificate(entityID);
            if (cert != null) { return cert; }
        }
        return null;
    }
}
