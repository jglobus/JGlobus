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
 *  Interface to generic SAML binding implementations. The setVersion method should
 *  not be called without synchronization, but binding implementations <b>must</b> be
 *  threadsafe with respect to the actual binding operations.
 *
 * @author     Scott Cantor (created November 25, 2001)
 */
public interface SAMLBinding
{
    /** SAML SOAP binding protocol */
    public final static String SOAP = "urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding";

    /**
     * @deprecated
     * Deprecated constant name for SAML SOAP binding protocol
     */
    public final static String SAML_SOAP_HTTPS = SOAP;

    /**
     *  Used by requester to send a SAML request to an authority, and obtain a
     *  response in return, with hook context
     *
     * @param  endpoint         Defines the endpoint to communicate with
     * @param  request          SAML request to send
     * @param  callCtx         Context data to pass to registered hooks for this call
     * @return                    SAML response received from authority
     * @exception  SAMLException  Base class of exceptions that may be thrown
     *      during processing
     */
    public abstract SAMLResponse send(String endpoint, SAMLRequest request, Object callCtx)
        throws SAMLException;

    /**
     *  Used by requester to send a SAML request to an authority, and obtain a
     *  response in return
     *
     * @param  endpoint         Defines the endpoint to communicate with
     * @param  request          SAML request to send
     * @return                    SAML response received from authority
     * @exception  SAMLException  Base class of exceptions that may be thrown
     *      during processing
     */
    public SAMLResponse send(String endpoint, SAMLRequest request)
        throws SAMLException;

    /**
     *  Used by responder to process the receipt of a SAML request, with hook context
     *
     * @param  reqContext         A generic placeholder for binding-specific
     *      request context
     * @param  callCtx          Context data to pass to registered hooks for this call
     * @param  minorVersion      Minor version to support
     * @return                    A SAML request
     * @exception  SAMLException  Base class of exceptions that may be thrown
     *      during processing
     */
    public abstract SAMLRequest receive(Object reqContext, Object callCtx, int minorVersion)
        throws SAMLException;

    /**
     *  Used by responder to process the receipt of a SAML request
     *
     * @param  reqContext         A generic placeholder for binding-specific
     *      request context
     * @param  minorVersion       Minor version to support
     * @return                    A SAML request
     * @exception  SAMLException  Base class of exceptions that may be thrown
     *      during processing
     */
    public abstract SAMLRequest receive(Object reqContext, int minorVersion)
        throws SAMLException;

    /**
     *  Return a response or fault to a requester with hook context
     *
     * @param  respContext              A generic placeholder for
     *      binding-specific response context
     * @param  response                 The SAML response to return (optional)
     * @param  e                        An exception to translate into a binding
     *      fault (optional)
     * @param  callCtx         Context data to pass to registered hooks for this call
     * @exception  SAMLException        Base class of exceptions that may be thrown
     *      during processing
     */
    public abstract void respond(Object respContext, SAMLResponse response, SAMLException e, Object callCtx)
        throws SAMLException;

    /**
     *  Return a response or fault to a requester
     *
     * @param  respContext              A generic placeholder for
     *      binding-specific response context
     * @param  response                 The SAML response to return (optional)
     * @param  e                        An exception to translate into a binding
     *      fault (optional)
     * @exception  SAMLException        Base class of exceptions that may be thrown
     *      during processing
     */
    public abstract void respond(Object respContext, SAMLResponse response, SAMLException e)
        throws SAMLException;

}
