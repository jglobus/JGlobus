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
 * <p>Indicates an error occurred while parsing an artifact.
 * Two special constructors are provided:</p>
 * <ul>
 *   <li>{@link #ArtifactParseException( int, int )}:
 *   use this constructor if an unexpected length is
 *   encountered while parsing an artifact</li>
 *   <li>{@link #ArtifactParseException( org.globus.opensaml11.saml.artifact.Artifact.TypeCode, org.globus.opensaml11.saml.artifact.Artifact.TypeCode )}:
 *   use this constructor if an unexpected type code is
 *   encountered while parsing an artifact</li>
 * </ul>
 *
 * @author Tom Scavo
 */
public class ArtifactParseException extends Exception
                                 implements SAMLArtifactChecking {

  /**
   * Constructs a <code>ArtifactParseException</code> object
   * with a default detail message.
   */
  public ArtifactParseException() {
    super( PARSE_ERROR_MSG );
  }

  /**
   * Constructs a <code>ArtifactParseException</code> object
   * with the specified detail message.
   *
   * @param message the detail message
   */
  public ArtifactParseException( String message ) {
    super( message );
  }

  /**
   * Constructs a <code>ArtifactParseException</code> object
   * with a detail message that mentions the two given lengths.
   *
   * @param found the found length
   * @param expected the expected length
   */
  public ArtifactParseException( int found, int expected ) {
    super( LENGTH_ERROR_MSG + ": " + found +
           " (expected " + expected + ")" );
  }

  /**
   * Constructs a <code>ArtifactParseException</code> object
   * with a detail message that mentions the two given type codes.
   *
   * @param found the found length
   * @param expected the expected length
   */
  public ArtifactParseException( Artifact.TypeCode found,
                                 Artifact.TypeCode expected ) {
    super( TYPE_CODE_ERROR_MSG + ": " + found.toString() +
           " (expected " + expected.toString() + ")" );
  }

}


