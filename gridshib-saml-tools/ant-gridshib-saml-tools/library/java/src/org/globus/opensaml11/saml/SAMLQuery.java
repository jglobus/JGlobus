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
 *  Abstract base class for all SAML queries
 *
 * @author     Scott Cantor (created March 25, 2002)
 */
public abstract class SAMLQuery extends SAMLObject implements Cloneable
{
    /**  Maps SAML query types (as XML QNames) to Java class implementations */
    protected static Hashtable queryTypeMap = new Hashtable();

    /**
     *  Registers a class to handle a specific SAML query type when parsing XML
     *
     * @param type          The query type or element name
     * @param className     The Java class that handles this query
     */
    public static void regFactory(QName type, String className)
    {
        queryTypeMap.put(type, className);
    }

    /**
     *  Unregisters a class to handle a specific SAML query type when parsing XML
     *
     * @param type          The query type or element name
     */
    public static void unregFactory(QName type)
    {
        queryTypeMap.remove(type);
    }

    /**
     *  Locates an implementation class for a query and constructs it based
     *  on the DOM provided.
     *
     * @param e     The root of a DOM containing the SAML query
     * @return SAMLQuery        A constructed query object
     *
     * @throws org.globus.opensaml11.saml.SAMLException    Thrown if an error occurs while constructing the object
     */
    public static SAMLQuery getInstance(Element e)
        throws SAMLException
    {
        if (e == null)
            throw new MalformedException(SAMLException.RESPONDER, "SAMLQuery.getInstance() given an empty DOM");

        try
        {
            if (XML.isElementNamed(e,XML.SAMLP_NS,"Query") || XML.isElementNamed(e,XML.SAMLP_NS,"SubjectQuery"))
            {
                String className = (String)queryTypeMap.get(XML.getQNameAttribute(e, XML.XSI_NS, "type"));
                if (className == null)
                    throw new UnsupportedExtensionException(SAMLException.RESPONDER, "SAMLQuery.getInstance() unable to locate an implementation of specified query type");
                Class implementation = Class.forName(className);
                Class[] paramtypes = {Element.class};
                Object[] params = {e};
                Constructor ctor = implementation.getDeclaredConstructor(paramtypes);
                return (SAMLQuery)ctor.newInstance(params);
            }
            else
            {
                String className = (String)queryTypeMap.get(new QName(e.getNamespaceURI(), e.getLocalName()));
                if (className == null)
                    throw new UnsupportedExtensionException(SAMLException.RESPONDER, "SAMLQuery.getInstance() unable to locate an implementation of specified query type");
                Class implementation = Class.forName(className);
                Class[] paramtypes = {Element.class};
                Object[] params = {e};
                Constructor ctor = implementation.getDeclaredConstructor(paramtypes);
                return (SAMLQuery)ctor.newInstance(params);
            }
        }
        catch (ClassNotFoundException ex)
        {
            throw new SAMLException(SAMLException.REQUESTER, "SAMLQuery.getInstance() unable to locate implementation class for query", ex);
        }
        catch (NoSuchMethodException ex)
        {
            throw new SAMLException(SAMLException.REQUESTER, "SAMLQuery.getInstance() unable to bind to constructor for query", ex);
        }
        catch (InstantiationException ex)
        {
            throw new SAMLException(SAMLException.REQUESTER, "SAMLQuery.getInstance() unable to build implementation object for query", ex);
        }
        catch (IllegalAccessException ex)
        {
            throw new SAMLException(SAMLException.REQUESTER, "SAMLQuery.getInstance() unable to access implementation of query", ex);
        }
        catch (java.lang.reflect.InvocationTargetException ex)
        {
            ex.printStackTrace();
            Throwable e2 = ex.getTargetException();
            if (e2 instanceof SAMLException)
                throw (SAMLException)e2;
            else
                throw new SAMLException(SAMLException.REQUESTER, "SAMLQuery.getInstance() caught unknown exception while building query object: " + e2.getMessage());
        }
    }

    /**
     *  Locates an implementation class for a query and constructs it based
     *  on the stream provided.
     *
     * @param in     The stream to deserialize from
     * @return SAMLQuery        A constructed query object
     *
     * @throws org.globus.opensaml11.saml.SAMLException    Thrown if an error occurs while constructing the object
     */
    public static SAMLQuery getInstance(InputStream in)
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
            Category.getInstance("SAMLQuery").error("caught an exception while parsing a stream:\n" + e.getMessage());
            NDC.pop();
            throw new MalformedException("SAMLQuery.getInstance() caught exception while parsing a stream",e);
        }
        catch (java.io.IOException e)
        {
            NDC.push("getInstance");
            Category.getInstance("SAMLQuery").error("caught an exception while parsing a stream:\n" + e.getMessage());
            NDC.pop();
            throw new MalformedException("SAMLQuery.getInstance() caught exception while parsing a stream",e);
        }
    }
}
