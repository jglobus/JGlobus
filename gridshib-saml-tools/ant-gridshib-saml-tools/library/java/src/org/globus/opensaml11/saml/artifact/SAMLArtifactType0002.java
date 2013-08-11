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
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;

import org.apache.commons.codec.binary.Base64;

import org.globus.opensaml11.saml.SAMLConfig;
import org.globus.opensaml11.saml.artifact.Artifact;
import org.globus.opensaml11.saml.artifact.ArtifactParseException;
import org.globus.opensaml11.saml.artifact.SAMLArtifact;
import org.globus.opensaml11.saml.artifact.Util;

/**
 * <p>This class implements a type&nbsp;0x0002 artifact as
 * specified by SAML&nbsp;V1.1.</p>
 *
 * <pre>TypeCode            := 0x0002
 *RemainingArtifact   := AssertionHandle SourceLocation
 *AssertionHandle     := 20-byte_sequence
 *SourceLocation      := URI</pre>
 *
 * <p>Since the URI is arbitrary, a type&nbsp;0x0002
 * artifact is of indeterminate size.</p>
 *
 * <p>The <code>AssertionHandle</code> is a sequence
 * of random bytes that points to an
 * authentication assertion at the IdP.</p>
 *
 * <p>Before the artifact is base64-encoded, the URI
 * is converted to a sequence of bytes based on UTF-8.
 * While parsing an encoded artifact, this encoding
 * process is reversed.</p>
 *
 * @author Tom Scavo
 */
public class SAMLArtifactType0002 extends SAMLArtifact {

  /**
   * The type code of this <code>Artifact</code> object.
   */
  public static final Artifact.TypeCode TYPE_CODE =
    new TypeCode( (byte) 0x00, (byte) 0x02 );

  /*
   * A private <code>Charset</code> representation of UTF-8.
   * If the JVM does not support this <code>Charset</code>
   * (every conformant JVM does, by the way), this statement
   * throws an <code>UnsupportedCharsetException</code>.  The
   * latter is a subclass of <code>RuntimeException</code>
   * (i.e., an unchecked exception) and therefore does not
   * need to be caught.
   */
  private static final Charset UTF8 = Charset.forName( "UTF-8" );

  /**
   * This constructor initializes the
   * <code>remainingArtifact</code> property by calling
   * the corresponding constructor of this implementation
   * of <code>Artifact.RemainingArtifact</code>.
   * <p>
   * This constructor throws an (unchecked)
   * <code>NullArgumentException</code> if its argument is null.
   *
   * @param sourceLocation the desired source location
   *        of this <code>SAMLArtifactType0002</code> object
   *
   * @see org.globus.opensaml11.saml.artifact.SAMLArtifactType0002.RemainingArtifact
   * @see NullArgumentException
   */
  public SAMLArtifactType0002( URI sourceLocation ) {
    checkNullArg( sourceLocation );
    this.typeCode = TYPE_CODE;
    this.remainingArtifact = new RemainingArtifact( sourceLocation );
  }

  /**
   * This constructor initializes the
   * <code>remainingArtifact</code> property by calling
   * the corresponding constructor of this implementation
   * of <code>Artifact.RemainingArtifact</code>.
   * <p>
   * This constructor throws a <code>NullArgumentException</code>
   * or <code>InvalidArgumentException</code> if any of its
   * arguments are null or invalid, respectively.
   * These exceptions are unchecked.
   *
   * @param assertionHandle the desired assertion handle
   *        of this <code>SAMLArtifactType0002</code> object
   *
   * @param sourceLocation the desired source location
   *        of this <code>SAMLArtifactType0002</code> object
   *
   * @see org.globus.opensaml11.saml.artifact.SAMLArtifactType0002.RemainingArtifact
   * @see NullArgumentException
   * @see InvalidArgumentException
   */
  public SAMLArtifactType0002( byte[] assertionHandle, URI sourceLocation ) {
    checkHandleArg( assertionHandle );
    checkNullArg( sourceLocation );
    this.typeCode = TYPE_CODE;
    this.remainingArtifact =
      new RemainingArtifact( assertionHandle, sourceLocation );
  }

  /**
   * This constructor initializes the
   * <code>remainingArtifact</code> property to the
   * given value.
   * <p>
   * This constructor throws an (unchecked)
   * <code>NullArgumentException</code> if its argument is null.
   *
   * @param remainingArtifact the desired value of
   *        the <code>remainingArtifact</code> property
   *        of this <code>SAMLArtifactType0002</code> object
   *
   * @see org.globus.opensaml11.saml.artifact.SAMLArtifactType0002.RemainingArtifact
   * @see NullArgumentException
   */
  public SAMLArtifactType0002( Artifact.RemainingArtifact remainingArtifact ) {
    checkNullArg( remainingArtifact );
    this.typeCode = TYPE_CODE;
    this.remainingArtifact = remainingArtifact;
  }

  /**
   * A convenience method that returns the
   * <code>assertionHandle</code> property of this implementation
   * of <code>Artifact.RemainingArtifact</code>.
   *
   * @return the <code>assertionHandle</code> property
   *
   * @see org.globus.opensaml11.saml.artifact.SAMLArtifactType0002.RemainingArtifact
   */
  public byte[] getAssertionHandle() {
    return ((RemainingArtifact) this.remainingArtifact).getAssertionHandle();
  }

  /**
   * A convenience method that returns the
   * <code>sourceLocation</code> property of this implementation
   * of <code>Artifact.RemainingArtifact</code>.
   *
   * @return the <code>sourceLocation</code> property
   *
   * @see org.globus.opensaml11.saml.artifact.SAMLArtifactType0002.RemainingArtifact
   */
  public URI getSourceLocation() {
    return ((RemainingArtifact) this.remainingArtifact).getSourceLocation();
  }

  /**
   * An implementation of <code>Artifact.RemainingArtifact</code>
   * for type&nbsp;0x0002 artifacts (via extension of
   * <code>SAMLArtifact.RemainingArtifact</code>).
   * This class defines two properties
   * (<code>assertionHandle</code> and <code>sourceLocation</code>).
   */
  public static final class RemainingArtifact
                    extends SAMLArtifact.RemainingArtifact {

    private byte[] assertionHandle;
    private URI sourceLocation;
    private byte[] sourceLocationBytes;

    /**
     * This constructor initializes the <code>sourceLocation</code>
     * property of this <code>RemainingArtifact</code>
     * object to the given value.  The <code>assertionHandle</code>
     * property is initialized to a sequence of random bytes.
     *
     * @param sourceLocation a source location
     */
    public RemainingArtifact( URI sourceLocation ) {
      byte[] assertionHandle = SAMLConfig.instance().getDefaultIDProvider().generateRandomBytes( HANDLE_LENGTH );
      RemainingArtifact ra;
      ra = new RemainingArtifact( assertionHandle, sourceLocation );
      this.assertionHandle = ra.assertionHandle;
      this.sourceLocation = ra.sourceLocation;
      this.sourceLocationBytes = ra.sourceLocationBytes;
    }

    /**
     * This constructor initializes the properties
     * of this <code>RemainingArtifact</code>
     * object to the given values.
     * <p>
     * This constructor throws a <code>NullArgumentException</code>
     * or <code>InvalidArgumentException</code> if any of its
     * arguments are null or invalid, respectively.
     * These exceptions are unchecked.
     *
     * @param assertionHandle an assertion handle
     *
     * @param sourceLocation a source location
     *
     * @see NullArgumentException
     * @see InvalidArgumentException
     */
    public RemainingArtifact( byte[] assertionHandle, URI sourceLocation ) {
      checkHandleArg( assertionHandle );
      checkNullArg( sourceLocation );
      this.assertionHandle = assertionHandle;
      this.sourceLocation = sourceLocation;
      String s = sourceLocation.toString();
      byte[] bytes;
      ByteBuffer bb = UTF8.encode( CharBuffer.wrap(s) );
      bytes = new byte[ bb.remaining() ];
      bb.duplicate().get( bytes );
      this.sourceLocationBytes = bytes;
    }

    /**
     * Get the <code>assertionHandle</code> property of this
     * <code>Artifact.RemainingArtifact</code> object.
     *
     * return the <code>assertionHandle</code> property
     */
    public byte[] getAssertionHandle() { return this.assertionHandle; }

    /**
     * Get the <code>sourceLocation</code> property of this
     * <code>Artifact.RemainingArtifact</code> object.
     *
     * return the <code>sourceLocation</code> property
     */
    public URI getSourceLocation() { return this.sourceLocation; }

    public int size() {
      return this.assertionHandle.length + this.sourceLocationBytes.length;
    }

    public byte[] getBytes() {
      byte[] bytes0 = this.assertionHandle;
      byte[] bytes1 = this.sourceLocationBytes;
      return Util.concat( bytes0, bytes1 );
    }

    public int hashCode() {
      return this.assertionHandle.hashCode() &
             this.sourceLocationBytes.hashCode();
    }

  }

  /**
   * An implementation of <code>Artifact.Parser</code>
   * for type&nbsp;0x0002 artifacts.
   */
  public static final class Parser implements Artifact.Parser {

    /**
     * Parse the given encoded string.
     *
     * @param s the encoded string
     *
     * @return an artifact that may be cast to type
     * <code>SAMLArtifactType0002</code>
     *
     * @exception ArtifactParseException
     *            if the length of the decoded string is
     *            less than the minimum length, or the
     *            type code is incorrect, or
     *            the tail portion of the parsed string
     *            is not a valid URI
     *
     * @see org.apache.commons.codec.binary.Base64
     */
    public Artifact parse( String s ) throws ArtifactParseException {

      // check total length:
      byte[] bytes = Base64.decodeBase64( s.getBytes() );
      int minLength = 2 + HANDLE_LENGTH;
      if ( bytes.length < minLength ) {
        throw new ArtifactParseException( bytes.length, minLength );
      }

      // check type code:
      TypeCode typeCode =
        new TypeCode( bytes[0], bytes[1] );
      if ( ! typeCode.equals( TYPE_CODE ) ) {
        throw new ArtifactParseException( typeCode, TYPE_CODE );
      }

      // extract the assertion handle:
      byte[] assertionHandle = new byte[ HANDLE_LENGTH ];
      System.arraycopy( bytes, 2, assertionHandle, 0, HANDLE_LENGTH );

      // extract the remaining bytes:
      int length = bytes.length - minLength;
      byte[] remainingBytes = new byte[ length ];
      System.arraycopy( bytes, minLength, remainingBytes, 0, length );

      // convert the remaining bytes to a string:
      ByteBuffer bb = ByteBuffer.wrap( remainingBytes );
      String decodedStr = UTF8.decode( bb.duplicate() ).toString();

      // convert the string to an URI:
      URI uri;
      try {
        uri = new URI( decodedStr );
      } catch ( URISyntaxException e ) {
        throw new ArtifactParseException( e.getMessage() );
      }

      return new SAMLArtifactType0002( assertionHandle, uri );

    }

  }

}

