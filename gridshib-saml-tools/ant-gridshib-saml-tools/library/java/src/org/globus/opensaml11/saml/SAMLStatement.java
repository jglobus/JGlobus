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
 *  Abstract base class for all SAML statements
 *
 * @author     Scott Cantor (created March 25, 2002)
 */
public abstract class SAMLStatement extends SAMLObject implements Cloneable
{
    /**  Maps SAML statement types (as XML QNames) to Java class implementations */
    protected static Hashtable statementTypeMap = new Hashtable();

    /**
     *  Registers a class to handle a specific SAML statement type when parsing XML
     *
     * @param type          The statement type or element name
     * @param className     The Java class that handles this query
     */
    public static void regFactory(QName type, String className) {
        statementTypeMap.put(type, className);
    }

    /**
     *  Unregisters a class to handle a specific SAML statement type when parsing XML
     *
     * @param type          The statement type or element name
     */
    public static void unregFactory(QName type) {
        statementTypeMap.remove(type);
    }

    /**
     *  Locates an implementation class for a statement and constructs it based
     *  on the DOM provided.
     *
     * @param e     The root of a DOM containing the SAML statement
     * @return SAMLStatement    A constructed statement object
     *
     * @throws org.globus.opensaml11.saml.SAMLException    Thrown if an error occurs while constructing the object
     */
    public static SAMLStatement getInstance(Element e) throws SAMLException {
        if (e == null)
            throw new MalformedException(
                SAMLException.RESPONDER,
                "SAMLStatement.getInstance() given an empty DOM");

        try
        {
            if (XML.isElementNamed(e,XML.SAML_NS,"Statement") ||
                XML.isElementNamed(e,XML.SAML_NS,"SubjectStatement")) {
                QName type = XML.getQNameAttribute(e, XML.XSI_NS, "type");
                String className = (String)statementTypeMap.get(type);
                if (className == null)
                    throw new UnsupportedExtensionException(
                        SAMLException.RESPONDER,
                        "SAMLStatement.getInstance() unable to locate " +
                        "an implementation of statement type " + type);
                Class implementation = Class.forName(className);
                Class[] paramtypes = {Element.class};
                Object[] params = {e};
                Constructor ctor = implementation.getDeclaredConstructor(paramtypes);
                return (SAMLStatement)ctor.newInstance(params);
            } else {
                QName type = new QName(e.getNamespaceURI(), e.getLocalName());
                String className = (String)statementTypeMap.get(type);
                if (className == null)
                    throw new UnsupportedExtensionException(
                        SAMLException.RESPONDER,
                        "SAMLStatement.getInstance() unable to locate " +
                        "an implementation of statement type " + type);
                Class implementation = Class.forName(className);
                Class[] paramtypes = {Element.class};
                Object[] params = {e};
                Constructor ctor = implementation.getDeclaredConstructor(paramtypes);
                return (SAMLStatement)ctor.newInstance(params);
            }
        }
        catch (ClassNotFoundException ex)
        {
            throw new SAMLException(
                SAMLException.REQUESTER,
                "SAMLStatement.getInstance() unable to locate implementation class for statement", ex);
        }
        catch (NoSuchMethodException ex)
        {
            throw new SAMLException(
                SAMLException.REQUESTER,
                "SAMLStatement.getInstance() unable to bind to constructor for statement", ex);
        }
        catch (InstantiationException ex)
        {
            throw new SAMLException(
                SAMLException.REQUESTER,
                "SAMLStatement.getInstance() unable to build implementation object for statement", ex);
        }
        catch (IllegalAccessException ex)
        {
            throw new SAMLException(
                SAMLException.REQUESTER,
                "SAMLStatement.getInstance() unable to access implementation of statement", ex);
        }
        catch (java.lang.reflect.InvocationTargetException ex)
        {
            ex.printStackTrace();
            Throwable e2 = ex.getTargetException();
            if (e2 instanceof SAMLException)
                throw (SAMLException)e2;
            else
                throw new SAMLException(
                    SAMLException.REQUESTER,
                    "SAMLStatement.getInstance() caught unknown exception while building statement object: " + e2.getMessage());
        }
    }

    /**
     *  Locates an implementation class for a statement and constructs it based
     *  on the stream provided.
     *
     * @param in     The stream to deserialize from
     * @return SAMLStatement    A constructed statement object
     *
     * @throws org.globus.opensaml11.saml.SAMLException    Thrown if an error occurs while constructing the object
     */
    public static SAMLStatement getInstance(InputStream in) throws SAMLException {
        try
        {
            Document doc = XML.parserPool.parse(in);
            return getInstance(doc.getDocumentElement());
        }
        catch (SAXException e)
        {
            NDC.push("getInstance");
            Category.getInstance("SAMLStatement").error("caught an exception while parsing a stream:\n" + e.getMessage());
            NDC.pop();
            throw new MalformedException("SAMLStatement.getInstance() caught exception while parsing a stream",e);
        }
        catch (java.io.IOException e)
        {
            NDC.push("getInstance");
            Category.getInstance("SAMLStatement").error("caught an exception while parsing a stream:\n" + e.getMessage());
            NDC.pop();
            throw new MalformedException("SAMLStatement.getInstance() caught exception while parsing a stream",e);
        }
    }
}

