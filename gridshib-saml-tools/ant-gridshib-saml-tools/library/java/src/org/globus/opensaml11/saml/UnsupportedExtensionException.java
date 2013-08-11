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

import java.util.Collection;

import javax.xml.namespace.QName;

import org.w3c.dom.Element;

/**
 *  Indicates that a message contained information requiring extension code
 *  that has not been registered with the SAML runtime.
 *
 * @author     Scott Cantor (created January 2, 2003)
 */
public class UnsupportedExtensionException extends SAMLException implements Cloneable
{
    /**
     *  Creates a new UnsupportedExtensionException
     *
     * @param  e    The root of a DOM tree
     * @exception  org.globus.opensaml11.saml.SAMLException   Raised if an exception occurs while constructing
     *                              the object.
     */
    protected UnsupportedExtensionException(Element e)
        throws SAMLException
    {
        super(e);
    }

    /**
     *  Creates a new UnsupportedExtensionException
     *
     * @param  msg    The detail message
     */
    public UnsupportedExtensionException(String msg)
    {
        super(msg);
    }

    /**
     *  Creates a new UnsupportedExtensionException
     *
     * @param  msg    The detail message
     * @param  e      The exception to be wrapped in a UnsupportedExtensionException
     */
    public UnsupportedExtensionException(String msg, Exception e)
    {
        super(msg,e);
    }

    /**
     *  Creates a new UnsupportedExtensionException
     *
     * @param  codes  A collection of QNames
     * @param  msg    The detail message
     */
    public UnsupportedExtensionException(Collection codes, String msg)
    {
        super(codes,msg);
    }

    /**
     *  Creates a new UnsupportedExtensionException wrapping an existing exception <p>
     *
     *  The existing exception will be embedded in the new one, and its message
     *  will become the default message for the UnsupportedExtensionException.</p>
     *
     * @param  codes  A collection of QNames
     * @param  e      The exception to be wrapped in a UnsupportedExtensionException
     */
    public UnsupportedExtensionException(Collection codes, Exception e)
    {
        super(codes,e);
    }

    /**
     *  Creates a new UnsupportedExtensionException from an existing exception. <p>
     *
     *  The existing exception will be embedded in the new one, but the new
     *  exception will have its own message.</p>
     *
     * @param  codes  A collection of QNames
     * @param  msg    The detail message
     * @param  e      The exception to be wrapped in a UnsupportedExtensionException
     */
    public UnsupportedExtensionException(Collection codes, String msg, Exception e)
    {
        super(codes,msg,e);
    }

    /**
     *  Creates a new UnsupportedExtensionException
     *
     * @param  code   A status code
     * @param  msg    The detail message
     */
    public UnsupportedExtensionException(QName code, String msg)
    {
        super(code,msg);
    }

    /**
     *  Creates a new UnsupportedExtensionException wrapping an existing exception <p>
     *
     *  The existing exception will be embedded in the new one, and its message
     *  will become the default message for the UnsupportedExtensionException.</p>
     *
     * @param  code   A status code
     * @param  e      The exception to be wrapped in a UnsupportedExtensionException
     */
    public UnsupportedExtensionException(QName code, Exception e)
    {
        super(code,e);
    }

    /**
     *  Creates a new UnsupportedExtensionException from an existing exception. <p>
     *
     *  The existing exception will be embedded in the new one, but the new
     *  exception will have its own message.</p>
     *
     * @param  code   A status code
     * @param  msg    The detail message
     * @param  e      The exception to be wrapped in a UnsupportedExtensionException
     */
    public UnsupportedExtensionException(QName code, String msg, Exception e)
    {
        super(code,msg,e);
    }
}

