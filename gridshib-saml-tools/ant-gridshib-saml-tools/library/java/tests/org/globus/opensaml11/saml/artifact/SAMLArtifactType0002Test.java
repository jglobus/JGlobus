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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;

/**
 * Test SAML artifacts
 *
 * @author     Tom Scavo
 */
public class SAMLArtifactType0002Test extends ArtifactTestCase {

  // default URI string:
  private static String providerIdStr = "https://idp.org/SAML";

  public SAMLArtifactType0002Test() {}

  public SAMLArtifactType0002Test( String arg ) {
    super( arg );
  }

  public static void main( String[] args ) {

    // process command-line arg:
    if ( args.length > 0 ) {
      providerIdStr = args[0];
    }

    junit.textui.TestRunner.run( SAMLArtifactType0002Test.class );

  }

  protected void setUp() throws Exception {
    super.setUp();
  }

  protected void tearDown() throws Exception {
    super.tearDown();
  }

  /**
   * Test a type&nbsp;0x0002 artifact.
   */
  public void testSAMLArtifactType0002() throws Exception {
    SAMLArtifact artifact;
    URI providerId;

    // artifact type 0x0002:
    try {
      providerId = new URI( providerIdStr );
    } catch ( URISyntaxException e ) {
      throw e;
    }

    artifact = new SAMLArtifactType0002( providerId );

    Artifact tempArtifact = ArtifactTestCase.duplicate( artifact );

    // recover assertionHandle:
    byte[] handle1 = ((SAMLArtifactType0002) artifact).getAssertionHandle();
    byte[] handle2 = ((SAMLArtifactType0002) tempArtifact).getAssertionHandle();
    assertTrue( "Assertion handles not equal",
                Arrays.equals( handle1, handle2 ) );
    // recover sourceLocation:
    URI location1 = ((SAMLArtifactType0002) artifact).getSourceLocation();
    URI location2 = ((SAMLArtifactType0002) tempArtifact).getSourceLocation();
    assertTrue( "Source locations not equal",
                location1.equals( location2 ) );

    // test bogus assertion handle:
    byte[] assertionHandle = Util.concat( handle1, handle2 );
    try {
      artifact = new SAMLArtifactType0002( assertionHandle, location1 );
      assertTrue( "Invalid assertionHandle did not throw exception",
                  true );
    } catch ( Exception e ) {
      assertTrue( "Wrong exception type for invalid assertionHandle",
                  e instanceof IllegalArgumentException );
    }

  }

}
