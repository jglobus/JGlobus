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

import java.net.HttpURLConnection;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 *  Interface for SAML SOAP HTTP binding implementations. The addHook method must
 *  be synchronized by the caller with respect to other binding methods.
 *
 * @author     Scott Cantor (created February 3, 2005)
 */
public interface SAMLSOAPHTTPBinding extends SAMLSOAPBinding
{
    /**
     *  Callback interface provided by client application enabling
     *  post-construction examination/modification of HTTP exchange. For example,
     *  a caller may embed security information, authenticate the peer, etc.
     *
     * @author Scott Cantor
     */
    public interface HTTPHook {

        /**
         *  Callback hook enabling HTTP request header examination.
         *
         * @param r  The HTTP request context
         * @param globalCtx  Context data to pass to registered hooks on each call
         * @param  callCtx         Context data to pass to registered hooks for this call
         * @return  true iff processing of message should proceed
         */
        public abstract boolean incoming(HttpServletRequest r, Object globalCtx, Object callCtx)
            throws SAMLException;

        /**
         *  Callback hook enabling HTTP response header modification.
         *
         * @param r  The HTTP response context
         * @param globalCtx  Context data to pass to registered hooks on each call
         * @param  callCtx         Context data to pass to registered hooks for this call
         * @return  true iff transmission of message should proceed
         */
        public abstract boolean outgoing(HttpServletResponse r, Object globalCtx, Object callCtx)
            throws SAMLException;

        /**
         *  Callback hook enabling HTTP response header examination.
         *
         * @param conn  The HTTP connection
         * @param globalCtx  Context data to pass to registered hooks on each call
         * @param  callCtx         Context data to pass to registered hooks for this call
         * @return  true iff processing of message should proceed
         */
        public abstract boolean incoming(HttpURLConnection conn, Object globalCtx, Object callCtx)
            throws SAMLException;

        /**
         *  Callback hook enabling HTTP request header modification.
         *
         * @param conn  The HTTP connection
         * @param globalCtx  Context data to pass to registered hooks on each call
         * @param  callCtx         Context data to pass to registered hooks for this call
         * @return  true iff transmission of message should proceed
         */
        public abstract boolean outgoing(HttpURLConnection conn, Object globalCtx, Object callCtx)
            throws SAMLException;
    }

    /**
     *  Attach an HTTP hook.
     *
     * @param h Hook interface to attach
     */
    public abstract void addHook(HTTPHook h);

    /**
     *  Attach an HTTP hook.
     *
     * @param h Hook interface to attach
     * @param hookData  Context data to pass to registered hooks
     */
    public abstract void addHook(HTTPHook h, Object hookData);
}
