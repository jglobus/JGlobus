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

package org.globus.opensaml11.md.common;

/**
 * Signals that an error occurred while taking actions specified by implementors of <code>ResourceWatchdog</code>
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public class ResourceWatchdogExecutionException extends Exception {

	public ResourceWatchdogExecutionException(String message) {

		super(message);
	}

}
