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
 * <p>Indicates an error occurred while trying to locate a parser.
 *
 * @author Tom Scavo
 */
public class ArtifactParserException extends Exception
                                  implements SAMLArtifactChecking {

  /**
   * Constructs a <code>ArtifactParserException</code> object
   * with a default detail message.
   */
  public ArtifactParserException() {
    super( PARSER_ERROR_MSG );
  }

  /**
   * Constructs a <code>ArtifactParserException</code> object
   * with the specified detail message.
   *
   * @param message the detail message
   */
  public ArtifactParserException( String message ) {
    super( message );
  }

}


