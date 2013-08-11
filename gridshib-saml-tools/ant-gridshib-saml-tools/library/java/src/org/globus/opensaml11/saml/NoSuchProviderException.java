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


/**
 *  Indicates that the specified implementation of a pluggable interface
 *  does not exist or is unknown.
 *
 * @author     Scott Cantor (created February 2, 2005)
 */
public class NoSuchProviderException extends SAMLException implements Cloneable
{
    /**
     *  Creates a new NoSuchProviderException
     *
     * @param  e    The root of a DOM tree
     * @exception  SAMLException   Raised if an exception occurs while constructing
     *                              the object.
     */
    protected NoSuchProviderException(org.w3c.dom.Element e)
        throws SAMLException
    {
        super(e);
    }

    /**
     *  Creates a new NoSuchProviderException
     *
     * @param  msg    The detail message
     */
    public NoSuchProviderException(String msg)
    {
        super(msg);
    }

    /**
     *  Creates a new NoSuchProviderException
     *
     * @param  msg    The detail message
     * @param  e      The exception to be wrapped in a NoSuchProviderException
     */
    public NoSuchProviderException(String msg, Exception e)
    {
        super(msg,e);
    }
}

