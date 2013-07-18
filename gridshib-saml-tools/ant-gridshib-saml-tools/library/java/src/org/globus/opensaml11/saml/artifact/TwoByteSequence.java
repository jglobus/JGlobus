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

import org.globus.opensaml11.saml.artifact.ByteSizedSequence;

import org.apache.commons.codec.binary.Hex;

/**
 * <p>A <code>TwoByteSequence</code> is an arbitrary sequence
 * of two bytes.</p>
 *
 * @author Tom Scavo
 */
public class TwoByteSequence implements ByteSizedSequence {

  protected byte byte0, byte1;

  /**
   * The workhorse constructor.
   */
  public TwoByteSequence( byte byte0, byte byte1 ) {
    this.byte0 = byte0; this.byte1 = byte1;
  }

  /**
   * A convenience constructor.
   */
  public TwoByteSequence( short s ) {
    // unsigned shift right 8 bits:
    this.byte0 = (byte) ( s >>> 8 );
    this.byte1 = (byte) s;
  }

  /**
   * Get the size of this sequence of bytes.
   * The size of course is 2.
   *
   * @return always returns 2
   */
  public int size() { return 2; }

  public byte[] getBytes() {
    byte[] bytes = new byte[2];
    bytes[0] = this.byte0;
    bytes[1] = this.byte1;
    return bytes;
  }

  /**
   * Converts this sequence of bytes to a string.
   * This method hex-encodes this
   * <code>TwoByteSequence</code> object.
   *
   * @return the hex encoding of this two-byte sequence
   *
   * @see org.apache.commons.codec.binary.Hex
   */
  public String toString() {
    return new String( Hex.encodeHex( this.getBytes() ) );
  }

  public boolean equals( Object o ) {
    if ( !( o instanceof TwoByteSequence ) ) { return false; }
    TwoByteSequence tbs = (TwoByteSequence) o;
    return ( this.byte0 == tbs.byte0 && this.byte1 == tbs.byte1 );
  }

  public int hashCode() {
    return byte0 & byte1;
  }

}

