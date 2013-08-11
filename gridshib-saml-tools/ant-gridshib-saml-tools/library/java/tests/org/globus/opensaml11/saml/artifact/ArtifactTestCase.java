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

import junit.framework.TestCase;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.globus.opensaml11.saml.artifact.Artifact;
import org.globus.opensaml11.saml.artifact.SAMLArtifact;

/**
 * A specialized JUnit <code>TestCase</code> for artifacts.
 *
 * @author     Tom Scavo
 */
public class ArtifactTestCase extends TestCase {

  public ArtifactTestCase() {}

  public ArtifactTestCase( String arg ) {
    super( arg );
  }

  protected void setUp() throws Exception {
    super.setUp();
    Logger.getRootLogger().setLevel(Level.OFF);
  }

  protected void tearDown() throws Exception {
    super.tearDown();
  }

  /**
   * Computations and tests shared by all artifacts.
   * The input argument is encoded, a parser is obtained,
   * and then the encoded artifact is parsed.  The
   * resulting artifact is compared to the input argument
   * and returned to the caller.
   *
   * @param artifact the SAML artifact to be duplicated
   *
   * @return an artifact equivalent to the input argument
   */
  public static Artifact duplicate( SAMLArtifact artifact ) throws Exception {

    Artifact tempArtifact;

    // basic round-trip computation:
    try {
      Artifact.Parser parser =
        SAMLArtifact.getTypeCode( artifact.encode() ).getParser();
      tempArtifact = parser.parse( artifact.encode() );
    } catch ( Exception e ) {
      throw e;
    }

    // general tests:
    assertEquals( "Artifacts not equal", artifact, tempArtifact );
    assertEquals( "Type codes not equal",
                  artifact.getTypeCode(),
                  tempArtifact.getTypeCode() );
    assertEquals( "Remaining artifacts not equal",
                  artifact.getRemainingArtifact(),
                  tempArtifact.getRemainingArtifact() );

    // another round-trip computation:
    try {
      Artifact.Parser parser = artifact.getTypeCode().getParser();
      tempArtifact = parser.parse( artifact.encode() );
    } catch ( Exception e ) {
      throw e;
    }

    return tempArtifact;

  }

}
