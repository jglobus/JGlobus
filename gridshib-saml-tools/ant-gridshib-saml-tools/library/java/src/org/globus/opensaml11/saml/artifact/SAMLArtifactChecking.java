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
 * Useful constants for artifact implementations.
 *
 * @author Tom Scavo
 */
public interface SAMLArtifactChecking {

  // numeric constants:
  public static final int IDENTIFIER_LENGTH = 20;
  public static final int HANDLE_LENGTH = 20;

  // error messages:
  public static final String INVALID_ARG_ERROR_MSG =
    "Invalid argument";
  public static final String NULL_ARG_ERROR_MSG =
    "Null argument";
  public static final String TYPE_CODE_ERROR_MSG =
    "Unexpected type code";
  public static final String LENGTH_ERROR_MSG =
    "Unexpected length";
  public static final String PARSER_ERROR_MSG =
    "Unable to locate parser";
  public static final String PARSE_ERROR_MSG =
    "Unknown artifact parse error";

}

