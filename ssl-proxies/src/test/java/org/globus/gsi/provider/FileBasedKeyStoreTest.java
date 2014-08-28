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

import org.globus.gsi.stores.PEMKeyStore;

import org.apache.commons.logging.Log;

import org.apache.commons.logging.LogFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Properties;


import org.globus.util.GlobusPathMatchingResourcePatternResolver;
import org.junit.Test;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 30, 2009
 * Time: 1:01:14 PM
 * To change this template use File | Settings | File Templates.
 */
public class FileBasedKeyStoreTest {
    private PEMKeyStore keystore = new PEMKeyStore();
    private GlobusPathMatchingResourcePatternResolver globusResolver = new GlobusPathMatchingResourcePatternResolver();
    private Log logger = LogFactory.getLog(FileBasedKeyStoreTest.class.getCanonicalName());

    @Test
    public void testIO() throws Exception {
        InputStream is;
        ByteArrayOutputStream os;
        Properties props = new Properties();
        props.put(PEMKeyStore.KEY_FILENAME, "classpath:/key.pem");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        props.store(baos, "sample");
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        keystore.engineLoad(bais, null);
        Enumeration en = keystore.engineAliases();
        while (en.hasMoreElements()) {
            logger.debug("en.nextElement().toString() = " + en.nextElement().toString());
        }
        os = new ByteArrayOutputStream();
//        keystore.engineStore(os, null);

//        keystore.engineStore(os, password);
    }
}
