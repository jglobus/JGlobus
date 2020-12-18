/*
 * Copyright 2007-2009 University of Illinois
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

package org.globus.gridshib.security.saml;

import java.util.HashSet;
import java.util.Iterator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.opensaml11.saml.SAMLAttribute;

/**
 * An attribute abstraction
 *
 * @since 0.3.0
 */
public class AttributeSet extends HashSet {

    static Log logger =
        LogFactory.getLog(AttributeSet.class.getName());

    public boolean add(Object o) {

        if (o == null || !(o instanceof SAMLAttribute)) { return false; }

        SAMLAttribute newAttribute = (SAMLAttribute)o;
        //boolean isNewAttribute = true;

        /* requires SAMLAttribute.equals(Object)
        // merge attribute values into existing attributes:
        Iterator attributes = this.iterator();
        while (attributes.hasNext()) {
            SAMLAttribute oldAttribute = (SAMLAttribute)attributes.next();
            if (newAttribute.equals(oldAttribute)) {
                //isNewAttribute = false;
                // merge attribute values
                String[] values = oldAttribute.getValues();
                for (int i = 0; i < values.length; i++) {
                    newAttribute.addValue(values[i]);
                }
                assert (super.remove(oldAttribute));  // BUG
                break;
            }
        }
        */

        logger.debug("Adding attribute: " + newAttribute.toString());
        return super.add(newAttribute);
    }

    public AttributeSet cloneSet() throws CloneNotSupportedException {

        AttributeSet newAttributes = new AttributeSet();

        // clone this AttributeSet:
        int n = 0;
        Iterator attributes = this.iterator();
        while (attributes.hasNext()) {
            n++;
            SAMLAttribute attribute = (SAMLAttribute)attributes.next();
            if (!newAttributes.add((SAMLAttribute)attribute.clone())) {
                String msg = "Failed to clone AttributeSet";
                throw new RuntimeException(msg);
            }
        }
        assert (n == newAttributes.size());
        logger.debug("Cloned " + n + " SAML attribute" +
                     ((n == 1) ? "" : "s"));

        return newAttributes;
    }
}
