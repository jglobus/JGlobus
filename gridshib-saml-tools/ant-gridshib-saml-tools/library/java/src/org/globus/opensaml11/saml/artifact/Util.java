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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * <p>An artifact utility class.</p>
 *
 * @author Tom Scavo
 */
public final class Util {

  private static MessageDigest messageDigest = null;

  private Util() {}

  /**
   * <p>Generate a <code>sourceId</code> from the given
   * string using the given <code>MessageDigest</code>
   * object.</p>
   *
   * @param md a <code>MessageDigest</code> object
   * @param s an arbitrary string
   *
   * @return the SHA-1 hash of the string or null if
   *         either argument is null
   *
   * @see java.security.MessageDigest
   */
  public static byte[] generateSourceId( MessageDigest md, String s ) {
    if ( md == null || s == null ) { return null; }
    return md.digest( s.getBytes() );
  }

  /**
   * <p>Generate a <code>sourceId</code> from the given
   * string.  Instantiate a local <code>MessageDigest</code>
   * object as needed.</p>
   *
   * @param s an arbitrary string
   *
   * @return the SHA-1 hash of the string
   *
   * @exception java.security.NoSuchAlgorithmException
   *            if the Java implementation does not support
   *            the "SHA-1" hash algorithm.
   *
   * @see java.security.MessageDigest
   */
  public static byte[] generateSourceId( String s )
                                  throws NoSuchAlgorithmException {
    if ( messageDigest == null ) {
      messageDigest = MessageDigest.getInstance( "SHA-1" );
    }
    return generateSourceId( messageDigest, s );
  }

  /**
   * <p>A convenience method to generate a <code>sourceId</code>
   * from the given <code>providerId</code>.  The URI is simply
   * converted to a string before it is hashed.</p>
   *
   * @param providerId the providerId of the artifact issuer
   *
   * @return the SHA-1 hash of the providerId or null if the
   *         argument is null
   *
   * @exception java.security.NoSuchAlgorithmException
   *            if the Java implementation does not support
   *            the "SHA-1" hash algorithm.
   *
   * @see java.security.MessageDigest
   */
  public static byte[] generateSourceId( URI providerId )
                                  throws NoSuchAlgorithmException {
    if ( providerId == null ) { return null; }
    return generateSourceId( providerId.toString() );
  }

  /**
   * Concatenate two byte arrays.
   *
   * @param left_bytes An array of bytes.
   * @param right_bytes Another array of bytes.
   *
   * @return Yet another byte array, the concatenation of the
   *         given byte arrays.
   */
  public static byte[] concat( byte[] left_bytes, byte[] right_bytes ) {
    if ( left_bytes == null ) { return right_bytes; }
    if ( right_bytes == null ) { return left_bytes; }
    byte[] bytes = new byte[ left_bytes.length + right_bytes.length ];
    System.arraycopy( left_bytes, 0, bytes, 0, left_bytes.length );
    System.arraycopy( right_bytes, 0, bytes, left_bytes.length, right_bytes.length );
    return bytes;
  }

}

