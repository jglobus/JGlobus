/*
 * Copyright 2009 University of Illinois
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.globus.gridshib.security;

import java.util.Set;

/**
 * A <em>security attribute</em> is associated with the
 * security context for an authenticated user.  For example,
 * security attributes may be gleaned from security tokens the
 * user presents at the time of authentication.  These are
 * sometimes called <em>pushed</em> attributes.  Attributes
 * may be <em>pulled</em> as well, and these too are added
 * to the set of security attributes associated with the user.
 * <p>
 * This interface defines a security attribute as a name-value
 * pair whose name is a simple string and whose value is a
 * set of strings.  One string in the set of value strings is
 * distinguished in some manner, to be determined by the
 * implementation.
 *
 * @since 0.5.4
 */
public interface SecurityAttributes {

    /**
     * Adds the given value to the set of values
     * associated with the attribute having the given name.
     * If the value set already contains the given value,
     * then the attribute is not modified and this method
     * returns false.
     *
     * @param name  the attribute name
     * @param value an attribute value
     *
     * @return true if and only if the given value was added
     *         to the set of values associated with the
     *         attribute of the given name
     */
    public boolean addAttributeValue(String name, String value);

    /**
     * Removes the attribute of the given name.  If such
     * an attribute does not exist, this method returns
     * false.
     *
     * @param name  the attribute name
     *
     * @return true if and only if the attribute of the
     *         given name is removed
     */
    public boolean removeAttribute(String name);

    /**
     * Gets the distinguished value associated with the
     * attribute of the given name.  If the attribute
     * does not exist, then this method returns null.
     * <b)
     * Determination of the distinguished attribute value
     * is an implementation choice.
     *
     * @param name  the attribute name
     *
     * @return the distinguished value associated with
     *         this attribute
     */
    public String getAttributeValue(String name);

    /**
     * Gets the set of values associated with the
     * attribute of the given name.  If the attribute does
     * not exist, then this method returns the empty set.
     *
     * @param name  the attribute name
     *
     * @return the value set associated with this attribute
     */
    public Set getAttributeValues(String name);

    /**
     * Gets the set of all attribute names associated with
     * an implementation of this interface.  If there are no
     * attributes associated with the implementation in question,
     * this method returns the empty set.
     *
     * @return the set of attribute names associated with
     *         this <code>SecurityAttributes</code> instance
     */
    public Set getAttributeNames();
}
