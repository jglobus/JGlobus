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

package org.globus.opensaml11.saml.artifact;

/**
 * <p>Indicates a invalid argument to a method or constructor.
 * A special constructor is provided:
 * {@link #InvalidArgumentException( int, int )}.
 * Use this constructor if an unexpected length is encountered.</p>
 *
 * @author Tom Scavo
 */
public class InvalidArgumentException extends IllegalArgumentException
                                   implements SAMLArtifactChecking {

  /**
   * Constructs a <code>InvalidArgumentException</code> object
   * with a default detail message.
   */
  public InvalidArgumentException() {
    super( INVALID_ARG_ERROR_MSG );
  }

  /**
   * Constructs a <code>InvalidArgumentException</code> object
   * with the specified detail message.
   *
   * @param message the detail message
   */
  public InvalidArgumentException( String message ) {
    super( message );
  }

  /**
   * Constructs a <code>InvalidArgumentException</code> object
   * with a detail message that mentions the two given lengths.
   *
   * @param found the found length
   * @param expected the expected length
   */
  public InvalidArgumentException( int found, int expected ) {
    super( LENGTH_ERROR_MSG + ": " + found +
           " (expected " + expected + ")" );
  }

}


