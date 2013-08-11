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

import org.globus.opensaml11.saml.SAMLAttribute;

import java.util.Iterator;

/**
 * <p>
 * Corresponds to SAML Metadata Schema "AttributeConsumingServiceType".
 * 
 * @author Scott Cantor
 */
public interface AttributeConsumingService {

    public String getName();

    public String getName(String lang);

    public String getDescription();

    public String getDescription(String lang);

    public class RequestedAttribute {

        public SAMLAttribute attribute;
        public boolean required;
    }

    public Iterator /* <RequestedAttribute> */getRequestedAttributes();
}
