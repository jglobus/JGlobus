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

import org.w3c.dom.Element;

/**
 *  Interface for SAML SOAP binding implementations. The addHook method must
 *  be synchronized by the caller with respect to other binding methods.
 *
 * @author     Scott Cantor (created February 3, 2005)
 */
public interface SAMLSOAPBinding extends SAMLBinding
{

    /**
     *  Callback interface provided by client application enabling post-construction
     *  modification or examination of SOAP envelope. For example,
     *  a caller may embed security information and/or sign the envelope,
     *  or insert additional headers as required.
     *
     * @author Scott Cantor
     */
    public interface SOAPHook {

        /**
         *  Callback hook enabling incoming envelope examination.
         *
         * @param envelope  The SOAP envelope after insertion of the SAML protocol message
         * @param globalCtx  Context data to pass to registered hooks on each call
         * @param  callCtx         Context data to pass to registered hooks for this call
         * @return  true iff receipt of message should proceed
         * @throws  org.globus.opensaml11.saml.SAMLException   Raised by hook if an error occurs, aborts receipt
         */
        public abstract boolean incoming(Element envelope, Object globalCtx, Object callCtx)
            throws SAMLException;

        /**
         *  Callback hook enabling outgoing envelope modification.
         *
         * @param envelope  The SOAP envelope after insertion of the SAML protocol message
         * @param globalCtx  Context data to pass to registered hooks on each call
         * @param  callCtx         Context data to pass to registered hooks for this call
         * @return  true iff transmission of message should proceed
         * @throws  org.globus.opensaml11.saml.SAMLException   Raised by hook if an error occurs, aborts transmission
         */
        public abstract boolean outgoing(Element envelope, Object globalCtx, Object callCtx)
            throws SAMLException;
    }

    /**
     *  Packages a SAML request for transmission via SOAP
     *
     * @param request   The SAML request to prepare
     * @param callCtx   Context data to pass to registered hooks for this call
     * @return  A SOAP envelope compliant with the SOAP binding
     * @throws org.globus.opensaml11.saml.SAMLException    Raised if an error occurs in preparing the SOAP message
     */
    public abstract Element sendRequest(SAMLRequest request, Object callCtx)
        throws SAMLException;

    /**
     *  Unpacks a SAML request from a SOAP envelope
     *
     * @param envelope  The SOAP envelope received
     * @param callCtx   Context data to pass to registered hooks for this call
     * @return  The SAML request received
     * @throws org.globus.opensaml11.saml.SAMLException    Raised if the SAML request cannot be unpacked successfully
     */
    public abstract SAMLRequest recvRequest(Element envelope, Object callCtx)
        throws SAMLException;

    /**
     *  Packages a SAML response for transmission via SOAP
     *
     * @param response   The SAML response to prepare (may be null)
     * @param e         An exception to package for transmission as a SOAP fault
     * @param callCtx   Context data to pass to registered hooks for this call
     * @return  A SOAP envelope compliant with the SOAP binding
     * @throws org.globus.opensaml11.saml.SAMLException    Raised if an error occurs in preparing the SOAP message
     */
    public abstract Element sendResponse(SAMLResponse response, SAMLException e, Object callCtx)
        throws SAMLException;

    /**
     *  Unpacks a SAML response from a SOAP envelope
     *
     * @param envelope  The SOAP envelope received
     * @param callCtx   Context data to pass to registered hooks for this call
     * @return  The SAML response received
     * @throws org.globus.opensaml11.saml.SAMLException    Raised if the SAML response cannot be unpacked successfully
     *      or if it contains an error
     */
    public abstract SAMLResponse recvResponse(Element envelope, Object callCtx) throws
        SAMLException;

    /**
     *  Attach a SOAP hook.
     *
     * @param h Hook interface to attach
     */
    public abstract void addHook(SOAPHook h);

    /**
     *  Attach a SOAP hook.
     *
     * @param h Hook interface to attach
     * @param globalCtx  Context data to pass to registered hooks on each call
     */
    public abstract void addHook(SOAPHook h, Object globalCtx);
}
