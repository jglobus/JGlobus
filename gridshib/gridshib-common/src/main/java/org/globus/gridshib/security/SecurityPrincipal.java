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

/**
 * A <code>SecurityPrincipal</code> is a named, issued
 * security item.  Instances of <code>SecurityPrincipal</code>
 * are distinguished by type.
 *
 * @since 0.5.4
 */
public interface SecurityPrincipal extends IssuedSecurityItem {

    public String getName();

    public String getType();
}
