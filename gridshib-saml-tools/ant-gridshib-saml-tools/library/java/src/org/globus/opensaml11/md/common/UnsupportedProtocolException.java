/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.globus.opensaml11.md.common;

import java.util.Collection;

import javax.xml.namespace.QName;
import org.globus.opensaml11.saml.SAMLException;
import org.w3c.dom.Element;

/**
 * Indicates that an error occurred before or during the processing of a SAML request/response exchange.
 * <P>
 *
 *
 *
 * @author Scott Cantor (created November 17, 2001)
 */
public class UnsupportedProtocolException extends SAMLException implements Cloneable {

    /**
     * Creates a new UnsupportedProtocolException
     *
     * @param e
     *            The root of a DOM tree
     * @exception SAMLException
     *                Raised if an exception occurs while constructing the object.
     */
    protected UnsupportedProtocolException(Element e) throws SAMLException {

        super(e);
    }

    /**
     * Creates a new UnsupportedProtocolException
     *
     * @param msg
     *            The detail message
     */
    public UnsupportedProtocolException(String msg) {

        super(msg);
    }

    /**
     * Creates a new UnsupportedProtocolException
     *
     * @param msg
     *            The detail message
     * @param e
     *            The exception to be wrapped in a UnsupportedProtocolException
     */
    public UnsupportedProtocolException(String msg, Exception e) {

        super(msg, e);
    }

    /**
     * Creates a new UnsupportedProtocolException
     *
     * @param codes
     *            A collection of QNames
     * @param msg
     *            The detail message
     */
    public UnsupportedProtocolException(Collection codes, String msg) {

        super(codes, msg);
    }

    /**
     * Creates a new UnsupportedProtocolException wrapping an existing exception
     * <p>
     *
     * The existing exception will be embedded in the new one, and its message will become the default message for the
     * UnsupportedProtocolException.
     * </p>
     *
     * @param codes
     *            A collection of QNames
     * @param e
     *            The exception to be wrapped in a UnsupportedProtocolException
     */
    public UnsupportedProtocolException(Collection codes, Exception e) {

        super(codes, e);
    }

    /**
     * Creates a new UnsupportedProtocolException from an existing exception.
     * <p>
     *
     * The existing exception will be embedded in the new one, but the new exception will have its own message.
     * </p>
     *
     * @param codes
     *            A collection of QNames
     * @param msg
     *            The detail message
     * @param e
     *            The exception to be wrapped in a UnsupportedProtocolException
     */
    public UnsupportedProtocolException(Collection codes, String msg, Exception e) {

        super(codes, msg, e);
    }

    /**
     * Creates a new UnsupportedProtocolException
     *
     * @param code
     *            A status code
     * @param msg
     *            The detail message
     */
    public UnsupportedProtocolException(QName code, String msg) {

        super(code, msg);
    }

    /**
     * Creates a new UnsupportedProtocolException wrapping an existing exception
     * <p>
     *
     * The existing exception will be embedded in the new one, and its message will become the default message for the
     * UnsupportedProtocolException.
     * </p>
     *
     * @param code
     *            A status code
     * @param e
     *            The exception to be wrapped in a UnsupportedProtocolException
     */
    public UnsupportedProtocolException(QName code, Exception e) {

        super(code, e);
    }

    /**
     * Creates a new UnsupportedProtocolException from an existing exception.
     * <p>
     *
     * The existing exception will be embedded in the new one, but the new exception will have its own message.
     * </p>
     *
     * @param code
     *            A status code
     * @param msg
     *            The detail message
     * @param e
     *            The exception to be wrapped in a UnsupportedProtocolException
     */
    public UnsupportedProtocolException(QName code, String msg, Exception e) {

        super(code, msg, e);
    }
}
