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

import org.apache.commons.codec.binary.Base64;

import org.globus.opensaml11.saml.SAMLConfig;
import org.globus.opensaml11.saml.artifact.Artifact;
import org.globus.opensaml11.saml.artifact.ArtifactParseException;
import org.globus.opensaml11.saml.artifact.SAMLArtifact;
import org.globus.opensaml11.saml.artifact.Util;

/**
 * <p>This class implements a type&nbsp;0x0001 artifact as
 * specified by SAML&nbsp;V1.1.</p>
 *
 * <pre>TypeCode            := 0x0001
 *RemainingArtifact   := SourceId AssertionHandle
 *SourceId            := 20-byte_sequence
 *AssertionHandle     := 20-byte_sequence</pre>
 *
 * <p>Thus a type&nbsp;0x0001 artifact is of size 42&nbsp;bytes
 * (unencoded).</p>
 *
 * <p>The <code>SourceId</code> is an arbitrary sequence
 * of bytes.  In practice, the <code>SourceId</code> is
 * the SHA-1 hash of the IdP providerId.</p>
 *
 * <p>The <code>AssertionHandle</code> is a sequence
 * of random bytes that points to an
 * authentication assertion at the IdP.</p>
 *
 * @author Tom Scavo
 */
public class SAMLArtifactType0001 extends SAMLArtifact {

  /**
   * The type code of this <code>Artifact</code> object.
   */
  public static final Artifact.TypeCode TYPE_CODE =
    new TypeCode( (byte) 0x00, (byte) 0x01 );

  /**
   * This constructor initializes the
   * <code>remainingArtifact</code> property by calling
   * the corresponding constructor of this implementation
   * of <code>Artifact.RemainingArtifact</code>.
   * <p>
   * This constructor throws a <code>NullArgumentException</code>
   * or <code>InvalidArgumentException</code> if its argument is
   * null or invalid, respectively.  These exceptions are unchecked.
   *
   * @param sourceId the desired source Id
   *        of this <code>SAMLArtifactType0001</code> object
   *
   * @see org.globus.opensaml11.saml.artifact.SAMLArtifactType0001.RemainingArtifact
   * @see NullArgumentException
   * @see InvalidArgumentException
   */
  public SAMLArtifactType0001( byte[] sourceId ) {
    checkIdentifierArg( sourceId );
    this.typeCode = TYPE_CODE;
    this.remainingArtifact = new RemainingArtifact( sourceId );
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
   * @param sourceId the desired source Id
   *        of this <code>SAMLArtifactType0001</code> object
   *
   * @param assertionHandle the desired assertion handle
   *        of this <code>SAMLArtifactType0001</code> object
   *
   * @see org.globus.opensaml11.saml.artifact.SAMLArtifactType0001.RemainingArtifact
   * @see NullArgumentException
   * @see InvalidArgumentException
   */
  public SAMLArtifactType0001( byte[] sourceId, byte[] assertionHandle ) {
    checkIdentifierArg( sourceId );
    checkHandleArg( assertionHandle );
    this.typeCode = TYPE_CODE;
    this.remainingArtifact = new RemainingArtifact( sourceId, assertionHandle );
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
   *        of this <code>SAMLArtifactType0001</code> object
   *
   * @see org.globus.opensaml11.saml.artifact.SAMLArtifactType0001.RemainingArtifact
   * @see NullArgumentException
   */
  public SAMLArtifactType0001( Artifact.RemainingArtifact remainingArtifact ) {
    checkNullArg( remainingArtifact );
    this.typeCode = TYPE_CODE;
    this.remainingArtifact = remainingArtifact;
  }

  /**
   * A convenience method that returns the
   * <code>sourceId</code> property of this implementation
   * of <code>Artifact.RemainingArtifact</code>.
   *
   * @return the <code>sourceId</code> property
   *
   * @see org.globus.opensaml11.saml.artifact.SAMLArtifactType0001.RemainingArtifact
   */
  public byte[] getSourceId() {
    return ((RemainingArtifact) this.remainingArtifact).getSourceId();
  }

  /**
   * A convenience method that returns the
   * <code>assertionHandle</code> property of this implementation
   * of <code>Artifact.RemainingArtifact</code>.
   *
   * @return the <code>assertionHandle</code> property
   *
   * @see org.globus.opensaml11.saml.artifact.SAMLArtifactType0001.RemainingArtifact
   */
  public byte[] getAssertionHandle() {
    return ((RemainingArtifact) this.remainingArtifact).getAssertionHandle();
  }

  /**
   * An implementation of <code>Artifact.RemainingArtifact</code>
   * for type&nbsp;0x0001 artifacts (via extension of
   * <code>SAMLArtifact.RemainingArtifact</code>).
   * This class defines two properties
   * (<code>sourceId</code> and <code>assertionHandle</code>).
   */
  public static final class RemainingArtifact
                    extends SAMLArtifact.RemainingArtifact {

    private byte[] sourceId;
    private byte[] assertionHandle;

    /**
     * This constructor initializes a property
     * of this <code>RemainingArtifact</code>
     * object to the given value.
     * <p>
     * This constructor throws a <code>NullArgumentException</code>
     * or <code>InvalidArgumentException</code> if its argument is
     * null or invalid, respectively.  These exceptions are unchecked.
     *
     * @param sourceId a source Id
     *
     * @see NullArgumentException
     * @see InvalidArgumentException
     */
    public RemainingArtifact( byte[] sourceId ) {
      checkIdentifierArg( sourceId );
      this.sourceId = sourceId;
      this.assertionHandle = SAMLConfig.instance().getDefaultIDProvider().generateRandomBytes( HANDLE_LENGTH );
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
     * @param sourceId a source Id
     * @param assertionHandle an assertion handle
     *
     * @see NullArgumentException
     * @see InvalidArgumentException
     */
    public RemainingArtifact( byte[] sourceId, byte[] assertionHandle ) {
      checkIdentifierArg( sourceId );
      checkHandleArg( assertionHandle );
      this.sourceId = sourceId;
      this.assertionHandle = assertionHandle;
    }

    /**
     * Get the <code>sourceId</code> property of this
     * <code>Artifact.RemainingArtifact</code> object.
     *
     * return the <code>sourceId</code> property
     */
    public byte[] getSourceId() { return this.sourceId; }

    /**
     * Get the <code>assertionHandle</code> property of this
     * <code>Artifact.RemainingArtifact</code> object.
     *
     * return the <code>assertionHandle</code> property
     */
    public byte[] getAssertionHandle() { return this.assertionHandle; }

    public int size() {
      return this.sourceId.length + this.assertionHandle.length;
    }

    public byte[] getBytes() {
      byte[] bytes0 = this.sourceId;
      byte[] bytes1 = this.assertionHandle;
      return Util.concat( bytes0, bytes1 );
    }

    public int hashCode() {
      return this.sourceId.hashCode() & this.assertionHandle.hashCode();
    }

  }

  /**
   * An implementation of <code>Artifact.Parser</code>
   * for type&nbsp;0x0001 artifacts.
   */
  public static final class Parser implements Artifact.Parser {

    /**
     * Parse the given encoded string.
     *
     * @param s the encoded string
     *
     * @return an artifact that may be cast to type
     * <code>SAMLArtifactType0001</code>
     *
     * @exception ArtifactParseException
     *            if the length of the decoded string is
     *            not equal to the required length, or the
     *            type code is incorrect
     *
     * @see org.apache.commons.codec.binary.Base64
     */
    public Artifact parse( String s ) throws ArtifactParseException {

      // check total length:
      byte[] bytes = Base64.decodeBase64( s.getBytes() );
      int expectedLength = 2 + IDENTIFIER_LENGTH + HANDLE_LENGTH;
      if ( bytes.length != expectedLength ) {
        throw new ArtifactParseException( bytes.length, expectedLength );
      }

      // check type code:
      TypeCode typeCode =
        new TypeCode( (byte) bytes[0], (byte) bytes[1] );
      if ( ! typeCode.equals( TYPE_CODE ) ) {
        throw new ArtifactParseException( typeCode, TYPE_CODE );
      }

      // create and return the artifact:
      byte[] sourceId = new byte[ IDENTIFIER_LENGTH ];
      System.arraycopy( bytes, 2, sourceId, 0, IDENTIFIER_LENGTH );
      byte[] assertionHandle = new byte[ HANDLE_LENGTH ];
      System.arraycopy( bytes, 2 + IDENTIFIER_LENGTH, assertionHandle, 0, HANDLE_LENGTH );
      return new SAMLArtifactType0001( sourceId, assertionHandle );

    }

  }

}

