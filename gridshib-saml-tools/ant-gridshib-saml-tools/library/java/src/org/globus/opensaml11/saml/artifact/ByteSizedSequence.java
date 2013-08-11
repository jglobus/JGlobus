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

/**
 * <p>A <code>ByteSizedSequence</code> is an arbitrary sequence of bytes.
 * The implementation determines the size of the sequence.</p>
 *
 * @author Tom Scavo
 */
public interface ByteSizedSequence {

  /**
   * Get the size of this sequence of bytes.
   *
   * @return the size of the sequence
   */
  public int size();

  /**
   * Get the actual bytes of this sequence of bytes.
   *
   * @return the actual sequence of bytes
   */
  public byte[] getBytes();

  /**
   * Get a string representation of this sequence of bytes.
   * This method overrides the corresponding method of the
   * superclass.
   *
   * @return a string representation of this sequence of bytes
   */
  public String toString();

  /**
   * Equate two sequences of bytes.
   *
   * @return true if and only if this sequence of bytes is
   *         equivalent to the given object
   */
  public boolean equals( Object o );

  /**
   * Compute the hashcode of this sequences of bytes.
   *
   * @return the hashcode
   */
  public int hashCode();

}
