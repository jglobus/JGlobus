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

import org.globus.opensaml11.saml.artifact.ArtifactParseException;
import org.globus.opensaml11.saml.artifact.ArtifactParserException;
import org.globus.opensaml11.saml.artifact.ByteSizedSequence;

/**
 * <p>An <code>Artifact</code> is an encoded sequence
 * of bytes.  By definition, every <code>Artifact</code> has a
 * two-byte <code>TypeCode</code>, which uniquely identifies
 * the <code>Artifact</code>.  Each implementation uniquely
 * defines the structure of the
 * <code>RemainingArtifact</code> component.</p>
 *
 * <p>Associated with each <code>Artifact</code> is a
 * <code>Parser</code>, which is used to parse encoded strings
 * into <code>Artifact</code> objects.  Every implementation
 * must provide its own <code>Parser</code> as defined by this
 * interface.</p>
 *
 * @author Tom Scavo
 */
public interface Artifact extends ByteSizedSequence {

  /**
   * Get the <code>typeCode</code> property of this
   * <code>Artifact</code> object.
   *
   * @return the <code>typeCode</code> property
   */
  public TypeCode getTypeCode();

  /**
   * Get the <code>remainingArtifact</code> property of this
   * <code>Artifact</code> object.
   *
   * @return the <code>remainingArtifact</code> property
   */
  public RemainingArtifact getRemainingArtifact();

  /**
   * A <code>TypeCode</code>, being a subcomponent of
   * <code>Artifact</code>, is a sequence of bytes.
   */
  public static interface TypeCode extends ByteSizedSequence {
    /**
     * Get the parser associated with this
     * <code>Artifact.TypeCode</code> object.
     * The typeCode determines the parser (since the
     * typeCode determines the artifact).
     *
     * @return the parser
     *
     * @exception org.globus.opensaml11.saml.artifact.ArtifactParserException
     *            if unable to get the <code>Parser</code>
     *            associated with this <code>Artifact</code>.
     */
    public Parser getParser() throws ArtifactParserException;
  }

  /**
   * A <code>RemainingArtifact</code>, being a subcomponent of
   * <code>Artifact</code>, is a sequence of bytes.
   */
  public static interface RemainingArtifact extends ByteSizedSequence {}

  /**
   * Encode this <code>Artifact</code> object.
   *
   * @return the encoded artifact
   */
  public String encode();

  /**
   * A <code>Parser</code> is used to parse (decode) an encoded
   * <code>Artifact</code>.
   */
  public static interface Parser {
    /**
     * Parse the given string.
     *
     * @param s the string to be parsed
     *
     * @return the artifact obtained from parsing the string
     *
     * @exception org.globus.opensaml11.saml.artifact.ArtifactParseException
     *            if unable to parse the string.
     */
    public Artifact parse( String s ) throws ArtifactParseException;
  }

}

