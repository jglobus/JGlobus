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

import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.util.Hashtable;

import javax.xml.namespace.QName;

import org.apache.log4j.Category;
import org.apache.log4j.NDC;
import org.w3c.dom.*;
import org.xml.sax.SAXException;

/**
 *  Abstract base class for all SAML conditions
 *
 * @author     Scott Cantor (created March 30, 2002)
 */
public abstract class SAMLCondition extends SAMLObject implements Cloneable
{
    /**  Maps SAML condition types (as XML QNames) to Java class implementations */
    protected static Hashtable conditionTypeMap = new Hashtable();

    /**
     *  Registers a class to handle a specific SAML condition type when parsing XML
     *
     * @param type          The condition type or element name
     * @param className     The Java class that handles this condition
     */
    public static void regFactory(QName type, String className)
    {
        conditionTypeMap.put(type, className);
    }

    /**
     *  Unregisters a class to handle a specific SAML condition type when parsing XML
     *
     * @param type          The condition type or element name
     */
    public static void unregFactory(QName type)
    {
        conditionTypeMap.remove(type);
    }

    /**
     *  Locates an implementation class for a condition and constructs it based
     *  on the DOM provided.
     *
     * @param e     The root of a DOM containing the SAML condition
     * @return SAMLCondition    A constructed condition object
     *
     * @throws SAMLException    Thrown if an error occurs while constructing the object
     */
    public static SAMLCondition getInstance(Element e)
        throws SAMLException
    {
        if (e == null)
            throw new MalformedException(SAMLException.RESPONDER, "SAMLCondition.getInstance() given an empty DOM");

        try
        {
            if (XML.isElementNamed(e,XML.SAML_NS,"Condition"))
            {
                String className = (String)conditionTypeMap.get(XML.getQNameAttribute(e, XML.XSI_NS, "type"));
                if (className == null)
                    throw new UnsupportedExtensionException(SAMLException.RESPONDER, "SAMLCondition.getInstance() unable to locate an implementation of specified condition type");
                Class implementation = Class.forName(className);
                Class[] paramtypes = {Element.class};
                Object[] params = {e};
                Constructor ctor = implementation.getDeclaredConstructor(paramtypes);
                return (SAMLCondition)ctor.newInstance(params);
            }
            else
            {
                String className = (String)conditionTypeMap.get(new QName(e.getNamespaceURI(), e.getLocalName()));
                if (className == null)
                    throw new UnsupportedExtensionException(SAMLException.RESPONDER, "SAMLCondition.getInstance() unable to locate an implementation of specified condition type");
                Class implementation = Class.forName(className);
                Class[] paramtypes = {Element.class};
                Object[] params = {e};
                Constructor ctor = implementation.getDeclaredConstructor(paramtypes);
                return (SAMLCondition)ctor.newInstance(params);
            }
        }
        catch (ClassNotFoundException ex)
        {
            throw new SAMLException(SAMLException.REQUESTER, "SAMLCondition.getInstance() unable to locate implementation class for condition", ex);
        }
        catch (NoSuchMethodException ex)
        {
            throw new SAMLException(SAMLException.REQUESTER, "SAMLCondition.getInstance() unable to bind to constructor for condition", ex);
        }
        catch (InstantiationException ex)
        {
            throw new SAMLException(SAMLException.REQUESTER, "SAMLCondition.getInstance() unable to build implementation object for condition", ex);
        }
        catch (IllegalAccessException ex)
        {
            throw new SAMLException(SAMLException.REQUESTER, "SAMLCondition.getInstance() unable to access implementation of condition", ex);
        }
        catch (java.lang.reflect.InvocationTargetException ex)
        {
            ex.printStackTrace();
            Throwable e2 = ex.getTargetException();
            if (e2 instanceof SAMLException)
                throw (SAMLException)e2;
            else
                throw new SAMLException(SAMLException.REQUESTER, "SAMLCondition.getInstance() caught unknown exception while building condition object: " + e2.getMessage());
        }
    }

    /**
     *  Locates an implementation class for a condition and constructs it based
     *  on the stream provided.
     *
     * @param in     The stream to deserialize from
     * @return SAMLCondition    A constructed condition object
     *
     * @throws SAMLException    Thrown if an error occurs while constructing the object
     */
    public static SAMLCondition getInstance(InputStream in)
        throws SAMLException
    {
        try
        {
            Document doc = XML.parserPool.parse(in);
            return getInstance(doc.getDocumentElement());
        }
        catch (SAXException e)
        {
            NDC.push("getInstance");
            Category.getInstance("SAMLCondition").error("caught an exception while parsing a stream:\n" + e.getMessage());
            NDC.pop();
            throw new MalformedException("SAMLCondition.getInstance() caught exception while parsing a stream",e);
        }
        catch (java.io.IOException e)
        {
            NDC.push("getInstance");
            Category.getInstance("SAMLCondition").error("caught an exception while parsing a stream:\n" + e.getMessage());
            NDC.pop();
            throw new MalformedException("SAMLCondition.getInstance() caught exception while parsing a stream",e);
        }
    }
}

