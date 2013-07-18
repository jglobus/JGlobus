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

import org.globus.opensaml11.saml.provider.SecureRandomIDProvider;

/**
 *  Factory for the SAMLIdentifier interface
 *
 * @author     Scott Cantor (created January 31, 2005)
 */
public class SAMLIdentifierFactory
{
    /**
     *  Obtains a default provider of the SAMLIdentifier interface
     *
     * @return  The SAMLIdentifier provider
     */
    public static SAMLIdentifier getInstance() {
        try {
            return getInstance(SAMLConfig.instance().getProperty("org.globus.opensaml11.saml.provider.id"));
        }
        catch (NoSuchProviderException e) {
            // Worst case...
            return new SecureRandomIDProvider();
        }
    }

    /**
     *  Obtains a specific provider of the SAMLIdentifier interface
     *
     * @return  The SAMLIdentifier provider
     * @exception   org.globus.opensaml11.saml.NoSuchProviderException   Raised if an error occurs while obtaining an instance
     *      of the interface
     */
    public static SAMLIdentifier getInstance(String provider) throws NoSuchProviderException {
        try {
            return (SAMLIdentifier)Class.forName(provider).newInstance();
        }
        catch (Exception e) {
            throw new NoSuchProviderException(
                    "getInstance() unable to build instance of ID provider (" + provider + "): " + e.getMessage(), e
                    );
        }
    }
}
