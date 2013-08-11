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

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.globus.opensaml11.saml.SAMLConfig;
import org.globus.opensaml11.saml.SAMLIdentifier;
import org.globus.opensaml11.saml.artifact.Artifact;
import org.globus.opensaml11.saml.artifact.SAMLArtifact;
import org.globus.opensaml11.saml.artifact.SAMLArtifactType0001;
import org.globus.opensaml11.saml.artifact.Util;

/**
 * Test SAML artifacts
 *
 * @author     Tom Scavo
 */
public class SAMLArtifactType0001Test extends ArtifactTestCase {

  // default URI string:
  private static String providerIdStr = null;

  private static SAMLIdentifier idgen = null;

  public SAMLArtifactType0001Test() {}

  public SAMLArtifactType0001Test( String arg ) {
    super( arg );
  }

  public static void main( String[] args ) {

    // process command-line arg:
    if ( args.length > 0 ) {
      providerIdStr = args[0];
    }

    junit.textui.TestRunner.run( SAMLArtifactType0001Test.class );

  }

  protected void setUp() throws Exception {
    super.setUp();
    idgen = SAMLConfig.instance().getDefaultIDProvider();
  }

  protected void tearDown() throws Exception {
    super.tearDown();
  }

  /**
   * Test a type&nbsp;0x0001 artifact.
   */
  public void testSAMLArtifactType0001() throws Exception {
    SAMLArtifact artifact;
    byte[] sourceId;

    // compute sourceId:
    if ( providerIdStr == null ) {
      sourceId = idgen.generateRandomBytes(20);
    } else {
      try {
        sourceId = Util.generateSourceId( providerIdStr );
      } catch ( NoSuchAlgorithmException e ) {
        throw e;
      }
    }

    // artifact type 0x0001:
    artifact = new SAMLArtifactType0001( sourceId );

    Artifact tempArtifact = ArtifactTestCase.duplicate( artifact );

    // recover sourceId:
    byte[] sourceId1 = ((SAMLArtifactType0001) artifact).getSourceId();
    byte[] sourceId2 = ((SAMLArtifactType0001) tempArtifact).getSourceId();
    assertTrue( "SourceIds not equal",
                Arrays.equals( sourceId1, sourceId2 ) );
    // recover assertionHandle:
    byte[] handle1 = ((SAMLArtifactType0001) artifact).getAssertionHandle();
    byte[] handle2 = ((SAMLArtifactType0001) tempArtifact).getAssertionHandle();
    assertTrue( "Assertion handles not equal",
                Arrays.equals( handle1, handle2 ) );

    // test bogus sourceId:
    sourceId = Util.concat( sourceId1, sourceId2 );
    try {
      artifact = new SAMLArtifactType0001( sourceId, handle1 );
      assertTrue( "Invalid sourceId did not throw exception",
                  true );
    } catch ( Exception e ) {
      assertTrue( "Wrong exception type for invalid sourceId",
                  e instanceof IllegalArgumentException );
    }

    // test bogus assertion handle:
    byte[] assertionHandle = Util.concat( handle1, handle2 );
    try {
      artifact = new SAMLArtifactType0001( sourceId1, assertionHandle );
      assertTrue( "Invalid assertionHandle did not throw exception",
                  true );
    } catch ( Exception e ) {
      assertTrue( "Wrong exception type for invalid assertionHandle",
                  e instanceof IllegalArgumentException );
    }

  }

}
