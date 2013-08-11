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

package org.globus.gridshib.common;

/**
 * An interface for loadable (i.e., cached) objects.
 * A typical implementation would be a file-based set.
 */
public interface Loadable {

    /**
     * Loads this <code>Loadable</code> object.
     * This method MUST call #resetLastLoaded()
     * after a successful load.  When this method
     * returns, the #isLoaded() method MUST
     * subsequently return true.
     *
     * @throws org.globus.gridshib.common.LoadException
     *         If unable to load this <code>Loadable</code>
     *         object
     */
    public void load() throws LoadException;

    /**
     * Determines if this <code>Loadable</code> object
     * has been loaded.
     *
     * @return true if and only if this <code>Loadable</code>
     *         object has been loaded.
     */
    public boolean isLoaded();

    /**
     * Gets the <code>lastLoaded</code> property of this
     * <code>Loadable</code> object.
     *
     * @return the time since this <code>Loadable</code>
     *         object was last loaded
     */
    public long getLastLoaded();

    /**
     * Resets the <code>lastLoaded</code> property of this
     * <code>Loadable</code> object.
     */
    public void resetLastLoaded();

    /**
     * Determine if this <code>Loadable</code> object
     * needs to be reloaded.
     *
     * @return true if and only if this <code>Loadable</code>
     *         object is stale (i.e., needs to be reloaded)
     */
    public boolean isStale();
}
