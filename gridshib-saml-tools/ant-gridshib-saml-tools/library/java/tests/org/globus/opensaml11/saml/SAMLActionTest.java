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

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import junit.framework.TestCase;

/**
 * @author Scott Cantor
 */
public class SAMLActionTest extends TestCase
{
    private String xmlpath = "data/org/globus/opensaml11/saml/SAMLActionTest.xml";

    public SAMLActionTest(String arg0)
    {
        super(arg0);
        Logger.getRootLogger().setLevel(Level.OFF);
    }

    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(SAMLActionTest.class);
    }

    public void testSAMLAction() throws Exception
    {
        SAMLAction obj = new SAMLAction(new FileInputStream(xmlpath));
        obj.setNamespace(SAMLAction.SAML_ACTION_NAMESPACE_UNIX);
        SAMLAction obj2 = new SAMLAction(new ByteArrayInputStream(obj.toString().getBytes()));
        assertEquals(obj.getData(),obj2.getData());
        assertEquals(obj2.getNamespace(),SAMLAction.SAML_ACTION_NAMESPACE_UNIX);
    }
}
