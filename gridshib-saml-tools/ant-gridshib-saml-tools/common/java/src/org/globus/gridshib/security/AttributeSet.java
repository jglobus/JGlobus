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

package org.globus.gridshib.security;

import java.util.HashSet;
import java.util.Iterator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * An attribute abstraction
 */
public class AttributeSet extends HashSet {

    static Log logger =
        LogFactory.getLog(AttributeSet.class.getName());

    public boolean add(Object o) {

        if (o == null || !(o instanceof BasicAttribute)) { return false; }

        BasicAttribute newAttribute = (BasicAttribute)o;
        //boolean isNewAttribute = true;

        // merge attribute values into existing attributes:
        Iterator attributes = this.iterator();
        while (attributes.hasNext()) {
            BasicAttribute oldAttribute = (BasicAttribute)attributes.next();
            if (newAttribute.equals(oldAttribute)) {
                //isNewAttribute = false;
                // merge attribute values
                String[] values = oldAttribute.getValues();
                for (int i = 0; i < values.length; i++) {
                    newAttribute.addValue(values[i]);
                }
                if (!super.remove(oldAttribute)) {
                    String msg =
                        "Failed to maintain integrity of AttributeSet";
                    throw new RuntimeException(msg);
                }
                break;
            }
        }

        return super.add(newAttribute);
    }
}
