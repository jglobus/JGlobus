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

/*
 * PluggableConfigurationComponent.java
 * 
 * Classes that implement a Pluggable configuration service
 * must also implement this interface.
 * 
 * After loading a class by passing the type= attribute to
 * Class.forName(), a specific sanity check can be performed
 * by verifying that the loaded class implements this interface.
 * This ensures that it really is a Plugin.
 * 
 * The initialize() method is then called, passing a DOM
 * node that represents the configuration information for
 * the plugin, either as opaque inline XML or from a 
 * loaded external file.
 * 
 * Note: in earlier releases the DOM node was passed to
 * the constructor, but it is safer to support a default
 * (no argument) constructor and handle initialization though
 * an interface like this.
 * 
 * Note: To be useful, the implementing class must also
 * implement some functional interface, such as Trust or
 * AAP. This interface just manages the load and initialization
 * part.
 * 
 * For examples of use, see one of the builtin implementation
 * classes (XMLMetadataImpl, ...).
 */
package org.globus.opensaml11.md.common;

import org.globus.opensaml11.saml.SAMLException;
import org.w3c.dom.Element;

public interface PluggableConfigurationComponent {
    
    public abstract void 
    initialize(Element dom) 
    	throws 
    	SAMLException,
    	ShibbolethConfigurationException; // for other problems
    
}