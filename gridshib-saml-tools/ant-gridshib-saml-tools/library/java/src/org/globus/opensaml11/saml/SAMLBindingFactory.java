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

import java.lang.reflect.Constructor;

import org.w3c.dom.Element;

/**
 *  Factory for the SAMLBinding interface
 *
 * @author     Scott Cantor (created February 3, 2005)
 */
public class SAMLBindingFactory
{
    /**
     *  Obtains a default provider of the SAMLBinding interface
     *
     * @param   binding     URI that identifies the desired protocol binding
     * @return  The SAMLBinding provider
     * @throws   org.globus.opensaml11.saml.NoSuchProviderException   Raised if an error occurs while obtaining an instance
     *      of the interface
     */
    public static SAMLBinding getInstance(String binding) throws NoSuchProviderException {
        return getInstance(binding, null, SAMLConfig.instance().getDefaultBindingProvider(binding));
    }

    /**
     *  Obtains a default provider of the SAMLBinding interface
     *
     * @param   binding     URI that identifies the desired protocol binding
     * @param e     A DOM element as input to configuring the provider
     * @return  The SAMLBinding provider
     * @throws   org.globus.opensaml11.saml.NoSuchProviderException   Raised if an error occurs while obtaining an instance
     *      of the interface
     */
    public static SAMLBinding getInstance(String binding, Element e) throws NoSuchProviderException {
        return getInstance(binding, e, SAMLConfig.instance().getDefaultBindingProvider(binding));
    }

    /**
     *  Obtains a specific provider of the SAMLBinding interface
     *
     * @param   binding     URI that identifies the desired protocol binding
     * @param provider  Name of the provider class to build
     * @return  The SAMLBinding provider
     * @throws   org.globus.opensaml11.saml.NoSuchProviderException   Raised if an error occurs while obtaining an instance
     *      of the interface
     */
    public static SAMLBinding getInstance(String binding, String provider) throws NoSuchProviderException {
        return getInstance(binding, null, provider);
    }

    /**
     *  Obtains a specific provider of the SAMLBinding interface
     *
     * @param   binding     URI that identifies the desired protocol binding
     * @param e     A DOM element as input to configuring the provider
     * @param provider  Name of the provider class to build
     * @return  The SAMLBinding provider
     * @throws   org.globus.opensaml11.saml.NoSuchProviderException   Raised if an error occurs while obtaining an instance
     *      of the interface
     */
    public static SAMLBinding getInstance(String binding, Element e, String provider) throws NoSuchProviderException {
        try {
            Class implementation = Class.forName(provider);
            Class[] paramtypes = {String.class, Element.class};
            Object[] params = {binding, e};
            Constructor ctor = implementation.getDeclaredConstructor(paramtypes);
            return (SAMLBinding)ctor.newInstance(params);
        }
        catch (Exception ex) {
            throw new NoSuchProviderException(
                    "getInstance() unable to build instance of binding provider (" + provider + "): " + ex.getMessage(), ex
                    );
        }
    }
}
