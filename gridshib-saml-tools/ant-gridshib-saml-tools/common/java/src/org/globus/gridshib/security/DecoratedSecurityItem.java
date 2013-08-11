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

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * A <em>decorated security item</em> is an issued security item
 * decorated with attributes.
 * <p>
 * This implementation of the <code>SecurityAttributes</code>
 * interface implements the value set as a <code>LinkedHashSet</code>.
 * Thus the distinguished attribute value, as given by the
 * {@link #getAttributeValue(String)} method, is the first value
 * in the ordered set of values.
 *
 * @see org.globus.gridshib.security.BaseSecurityItem
 * @see org.globus.gridshib.security.SecurityAttributes
 *
 * @since 0.5.4
 */
public abstract class DecoratedSecurityItem extends BaseSecurityItem
                                         implements SecurityAttributes {

    static Log logger =
        LogFactory.getLog(DecoratedSecurityItem.class.getName());

    /**
     * @exception java.lang.IllegalArgumentException
     *            if either <code>id</code> or <code>issuer</code>
     *            are null
     *
     * @since 0.5.4
     */
    public DecoratedSecurityItem(String id, String issuer) {

        super(id, issuer);
    }

    private Map attributes = new HashMap();

    /**
     * @exception java.lang.IllegalArgumentException
     *            if either argument is null
     */
    public boolean addAttributeValue(String name, String value) {

        if (name == null) {
            throw new IllegalArgumentException("Null name argument");
        }

        if (value == null) {
            throw new IllegalArgumentException("Null value argument");
        }

        assert (this.attributes != null);

        Set values;
        if (this.attributes.containsKey(name)) {
            values = (LinkedHashSet)this.attributes.get(name);
        } else {
            values = new LinkedHashSet();
        }
        boolean added = values.add(value);
        if (added) {
            this.attributes.put(name, values);
        }
        return added;
    }

    /**
     * @exception java.lang.IllegalArgumentException
     *            if the <code>name</code> argument is null
     */
    public boolean removeAttribute(String name) {

        if (name == null) {
            throw new IllegalArgumentException("Null name argument");
        }

        assert (this.attributes != null);

        return (this.attributes.remove(name) != null);
    }

    /**
     * @exception java.lang.IllegalArgumentException
     *            if the <code>name</code> argument is null
     */
    public String getAttributeValue(String name) {

        if (name == null) {
            throw new IllegalArgumentException("Null name argument");
        }

        assert (this.attributes != null);

        Set values;
        if (this.attributes.containsKey(name)) {
            values = (LinkedHashSet)this.attributes.get(name);
        } else {
            values = new LinkedHashSet();
        }
        if (values.isEmpty()) {
            return null;
        }
        return (String)values.iterator().next();
    }

    /**
     * @exception java.lang.IllegalArgumentException
     *            if the <code>name</code> argument is null
     */
    public Set getAttributeValues(String name) {

        if (name == null) {
            throw new IllegalArgumentException("Null name argument");
        }

        assert (this.attributes != null);

        if (this.attributes.containsKey(name)) {
            return (LinkedHashSet)this.attributes.get(name);
        } else {
            return new LinkedHashSet();
        }
    }

    public Set getAttributeNames() {

        assert (this.attributes != null);

        return this.attributes.keySet();
    }
}
