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

package org.globus.opensaml11.md.metadata;

import org.w3c.dom.Element;

/**
 * <p>
 * Corresponds to SAML Metadata Schema "EndpointType".
 * </p>
 * <p>
 * "The complex type EndpointType describes a SAML protocol binding endpoint at which a SAML entity can be sent protocol
 * messages." That is, it is to SAML what a URL is to HTTP, the address of one end of a conversation. The exact meaning
 * depends on the SAML binding (is this a Browser POST, a Web Service request, or what).
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public interface Endpoint {

	public String getBinding(); // URI identifying a SAML binding

	public String getLocation(); // URI(URL) of the message destination

	public String getResponseLocation(); // optional second URI(URL) destination

	public Element getElement(); // punch through to XML content if permitted
}
