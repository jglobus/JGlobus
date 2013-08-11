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
import java.security.NoSuchAlgorithmException;

import org.globus.opensaml11.saml.SAMLConfig;
import org.globus.opensaml11.saml.SAMLIdentifier;
import org.globus.opensaml11.saml.artifact.Artifact;
import org.globus.opensaml11.saml.artifact.SAMLArtifact;
import org.globus.opensaml11.saml.artifact.SAMLArtifactType0001;
import org.globus.opensaml11.saml.artifact.SAMLArtifactType0002;
import org.globus.opensaml11.saml.artifact.Util;

/**
 * Print SAML artifacts.  Takes one optional argument
 * a URI (typically a providerId). For example:
 * <pre>java ArtifactTester https://idp.org/saml</pre>
 *
 * @author     Tom Scavo
 */
public class ArtifactTest {

  // default URI string:
  private static String providerIdStr = "https://idp.org/SAML";

  // a single handle used throughout:
  private static byte[] handle;

  private static SAMLIdentifier idgen = SAMLConfig.instance().getDefaultIDProvider();

  public static void main( String args[] ) throws Exception {

    // process command-line args:
    if ( args.length > 0 ) {
      providerIdStr = args[0];
    }

    // compute handle:
    handle = idgen.generateRandomBytes(20);

    System.out.println( "Begin printing." );

    printSAMLArtifactType0001();
    printSAMLArtifactType0002();

    System.out.println( "End printing." );

  }

  /**
   * Print two type&nbsp;0x0001 artifacts, one with a random
   * <code>sourceId</code> and another with a computed
   * <code>sourceId</code>.  The latter is computed by
   * taking the SHA-1 hash of the given providerId.
   */
  static void printSAMLArtifactType0001() throws Exception {
    SAMLArtifact artifact;
    byte[] sourceId;

    // artifact type 0x0001 (with random sourceId):
    sourceId = idgen.generateRandomBytes(20);
    artifact = new SAMLArtifactType0001( sourceId, handle );
    printResults( artifact );

    // artifact type 0x0001 (with computed sourceId):
    try {
      sourceId = Util.generateSourceId( providerIdStr );
    } catch ( NoSuchAlgorithmException e ) {
      throw e;
    }
    artifact = new SAMLArtifactType0001( sourceId, handle );
    printResults( artifact, providerIdStr );
  }

  /**
   * Print a type&nbsp;0x0002 artifact using the given
   * providerId.
   */
  static void printSAMLArtifactType0002() throws Exception {
    SAMLArtifact artifact;
    URI providerId;

    // artifact type 0x0002:
    providerId = new URI( providerIdStr );

    artifact = new SAMLArtifactType0002( handle, providerId );
    printResults( artifact, providerId );
  }

  static void printResults( Artifact artifact ) throws Exception {
    printResults( artifact, null );
  }

  static void printResults( Artifact artifact, Object o ) throws Exception {

    if ( artifact == null ) { return; }

    // print heading:
    Artifact.TypeCode typeCode = artifact.getTypeCode();
    String msg = "Artifact Type " + typeCode.toString();
    msg += " (size = " + artifact.size() + ")";
    System.out.println( msg );

    // print URI:
    if ( o != null ) {
      System.out.println( "URI:     " + o.toString() );
    } else {
      System.out.println( "URI:     NONE" );
    }

    // print hex-encoded artifact:
    System.out.println( "Hex:     " + artifact.toString() );

    // print base64-encoded artifact:
    System.out.println( "Base64:  " + artifact.encode() );

    // print ruler:
    System.out.println( "         ----------------------------------------------------------------------" );
    System.out.println( "         1234567890123456789012345678901234567890123456789012345678901234567890" );
    System.out.println( "                  1         2         3         4         5         6         7" );
    System.out.println( "         ----------------------------------------------------------------------" );

  }

}
