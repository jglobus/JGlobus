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

import java.util.Arrays;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import org.globus.opensaml11.saml.artifact.Artifact;
import org.globus.opensaml11.saml.artifact.ArtifactParserException;
import org.globus.opensaml11.saml.artifact.InvalidArgumentException;
import org.globus.opensaml11.saml.artifact.NullArgumentException;
import org.globus.opensaml11.saml.artifact.SAMLArtifactChecking;
import org.globus.opensaml11.saml.artifact.TwoByteSequence;
import org.globus.opensaml11.saml.artifact.Util;

/**
 * <p>The <code>SAMLArtifact</code> abstract class is a partial
 * implementation of the <code>Artifact</code> interface.
 * In particular, this class provides a final
 * implementation of the <code>Artifact.TypeCode</code>
 * interface.  To complete the implementation, a subclass
 * <strong>must</strong> implement the
 * <code>Artifact.RemainingArtifact</code>
 * and <code>Artifact.Parser</code> interfaces.</p>
 *
 * <p>A <em>SAML artifact</em> has three components:
 * 1)&nbsp;a two-byte type code, 2)&nbsp;a precise
 * definition of "remaining artifact," and
 * 3)&nbsp;an encoding scheme.
 * The encoding is fixed (base64) whereas the type code
 * and "remaining artifact" vary from artifact to
 * artifact.</p>
 *
 * <p>The formal definition of a <em>SAML artifact</em>
 * is given by the following productions:</p>
 *
 * <pre>SAMLArtifact        := base64(TypeCode RemainingArtifact)
 *TypeCode            := Byte1 Byte2</pre>
 *
 * <p>An implementation must specify a type code value
 * and provide a definition for <code>RemainingArtifact</code>
 * to complete the grammar.</p>
 *
 * <p>Subclasses of <code>SAMLArtifact</code>
 * <strong>must</strong> adhere to certain naming conventions.
 * First of all, the name of the subclass is always
 * "SAMLArtifactType" followed by the hex encoding of the type
 * code.  For instance, a subclass that implements a type
 * 0x0001 artifact is called <code>SAMLArtifactType0001</code>.
 * Moreover, each class <strong>must</strong> contain an
 * implementation of <code>Artifact.Parser</code> called
 * (simply) <code>Parser</code>.  In this way, the
 * {@link org.globus.opensaml11.saml.artifact.SAMLArtifact.TypeCode#getParser()} method can locate
 * the appropriate parser on-demand (based on type code).</p>
 *
 * @author Tom Scavo
 */
public abstract class SAMLArtifact implements Artifact,
                                              SAMLArtifactChecking {

  /**
   * The <code>typeCode</code> property
   * of this <code>SAMLArtifact</code> object.
   */
  protected Artifact.TypeCode typeCode = null;

  /**
   * The <code>remainingArtifact</code> property
   * of this <code>SAMLArtifact</code> object.
   */
  protected Artifact.RemainingArtifact remainingArtifact = null;

  protected SAMLArtifact() {}

  public Artifact.TypeCode getTypeCode() {
    return this.typeCode;
  }

  public Artifact.RemainingArtifact getRemainingArtifact() {
    return this.remainingArtifact;
  }

  public int size() {
    return this.typeCode.size() + this.remainingArtifact.size();
  }

  public byte[] getBytes() {
    byte[] bytes0 = this.typeCode.getBytes();
    byte[] bytes1 = this.remainingArtifact.getBytes();
    return Util.concat( bytes0, bytes1 );
  }

  /**
   * Encode this <code>SAMLArtifact</code> object using the
   * base64 encoding method.
   *
   * @return the encoded artifact
   *
   * @see org.apache.commons.codec.binary.Base64
   */
  public String encode() {
    return new String( Base64.encodeBase64( this.getBytes() ) );
  }

  /**
   * Encode this <code>SAMLArtifact</code> object using a
   * simple hex encoding method.
   *
   * @return the encoded artifact
   *
   * @see org.apache.commons.codec.binary.Hex
   */
  public String toString() {
    return new String( Hex.encodeHex( this.getBytes() ) );
  }

  public boolean equals( Object o ) {
    if ( !( o instanceof SAMLArtifact ) ) { return false; }
    SAMLArtifact artifact = (SAMLArtifact) o;
    return Arrays.equals( this.getBytes(), artifact.getBytes() );
  }

  public int hashCode() {
    return this.typeCode.hashCode() & this.remainingArtifact.hashCode();
  }

  /* nested classes */

  /**
   * A <code>TypeCode</code> is an arbitrary two-byte sequence.
   * The most important method defined by this class is
   * the {@link org.globus.opensaml11.saml.artifact.SAMLArtifact.TypeCode#getParser()} method.
   */
  public static final class TypeCode extends TwoByteSequence
                                  implements Artifact.TypeCode {

    // constants:
    private static final String CLASS_NAME_PREFIX =
      "org.globus.opensaml11.saml.artifact.SAMLArtifactType";
    private static final String CLASS_NAME_SUFFIX =
      "$Parser";

    /**
     * The workhorse constructor.
     */
    public TypeCode( byte b0, byte b1 ) { super( b0, b1 ); }

    /**
     * A convenience constructor.
     */
    public TypeCode( short tc ) { super( tc ); }

    /**
     * Converts this <code>TypeCode</code> object to a string.
     * The two bytes are hex-encoded and prefixed by "0x".
     * The result is the string equivalent of a hex integer.
     *
     * @return a string version of this type code
     */
    public String toString() {
      return "0x" + super.toString();
    }

    /**
     * Gets the <code>Artifact.Parser</code> object corresponding
     * to this <code>TypeCode</code>.
     *
     * @return an artifact parser
     */
    public Artifact.Parser getParser() throws ArtifactParserException {
      String typeCodeStr = super.toString();
      String className = CLASS_NAME_PREFIX + typeCodeStr + CLASS_NAME_SUFFIX;
      Artifact.Parser parser;
      try {
        parser = (Artifact.Parser) Class.forName( className ).newInstance();
      } catch ( Exception e ) {
        throw new ArtifactParserException( e.getMessage() );
      }
      return parser;
    }

  }

  /**
   * Subclasses of <code>SAMLArtifact</code> must extend this abstract
   * class or implement <code>Artifact.RemainingArtifact</code> from
   * scratch.
   */
  public abstract static class RemainingArtifact
                    implements Artifact.RemainingArtifact {

    /**
     * Encode this <code>Artifact.RemainingArtifact</code>
     * object using a simple hex encoding method.
     *
     * @return the encoded <code>remainingArtifact</code>
     *
     * @see org.apache.commons.codec.binary.Hex
     */
    public String toString() {
      return new String( Hex.encodeHex( this.getBytes() ) );
    }

    /**
     * Compares this <code>Artifact.RemainingArtifact</code>
     * object to the given object.  If the latter is not an
     * instance of <code>Artifact.RemainingArtifact</code>,
     * the method immediately returns false.
     *
     * @return true if and only if the given object is equivalent
     *         to this <code>Artifact.RemainingArtifact</code>
     *         object
     */
    public boolean equals( Object o ) {
      if ( !( o instanceof Artifact.RemainingArtifact ) ) {
        return false;
      }
      Artifact.RemainingArtifact ra = (Artifact.RemainingArtifact) o;
      return Arrays.equals( this.getBytes(), ra.getBytes() );
    }

  }

  /**
   * Subclasses of <code>SAMLArtifact</code> must extend this
   * (trivial) abstract class or implement
   * <code>Artifact.Parser</code> from scratch.
   */
  public abstract static class Parser
                    implements Artifact.Parser {}

  /* static methods */

  /**
   * Pre-parses an encoded artifact.  This method
   * determines the type code of the encoded artifact.  Knowing
   * the type code, the corresponding parser may be obtained
   * with {@link org.globus.opensaml11.saml.artifact.SAMLArtifact.TypeCode#getParser()}, for
   * instance.
   *
   * @param s the string to be parsed
   *
   * @return the type code of the encoded artifact
   */
  public static Artifact.TypeCode getTypeCode( String s ) {
    byte[] bytes = Base64.decodeBase64( s.getBytes() );
    return new TypeCode( (byte) bytes[0], (byte) bytes[1] );
  }

  public static void checkHandleArg( byte[] handle ) {
    checkNullArg( handle );
    int n = handle.length;
    if ( n != HANDLE_LENGTH ) {
      throw new InvalidArgumentException( n, HANDLE_LENGTH );
    }
  }

  public static void checkIdentifierArg( byte[] identifier ) {
    checkNullArg( identifier );
    int n = identifier.length;
    if ( n != IDENTIFIER_LENGTH ) {
      throw new InvalidArgumentException( n, IDENTIFIER_LENGTH );
    }
  }

  public static void checkNullArg( Object obj ) {
    if ( obj == null ) {
      throw new NullArgumentException();
    }
  }

}
