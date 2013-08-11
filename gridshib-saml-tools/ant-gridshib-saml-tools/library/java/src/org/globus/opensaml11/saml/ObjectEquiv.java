/*
 * Copyright 2005-2009 University of Illinois
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

package org.globus.opensaml11.saml;

/**
 * An object equivalence class
 *
 * @author     Tom Scavo
 */
public abstract class ObjectEquiv implements Cloneable {

    /**
     * Compares this object with the given object. Two objects are
     * equal if and only if
     * <ol>
     *   <li>they belong to the same type equivalence set,
     *       <strong>and</strong></li>
     *   <li>they have the same "deep structure"</li>
     * </ol>
     * The method determines if these conditions are true by calling
     * #isTypeEquiv and #localEquals on this object, respectively.
     * <p>
     * This method is invariant with respect to class, and is
     * therefore inherited by all subclasses.
     * <p>
     * See the paper
     * <a href="http://www.cs.uwec.edu/~phillips/papers/JavaEquals.pdf">Implementing
     * Object Equivalence in Java Using the Template Method Design Pattern</a>
     * for more detail about the technique employed here.
     *
     * @param obj the object with which to compare.
     * @return true if and only if the objects are type equivalent
     *         and equal by "deep comparison".
     */
    public final boolean equals(Object obj) {
        if (this == obj) {return true;}
        //if (obj == null) {return false;}
        if (!(obj instanceof ObjectEquiv)) {return false;}
        if (isTypeEquiv(obj)) {
            return localEquals(obj);
        }
        return false;
    }

    /**
     * Compares this object with the given object. Two objects are
     * type equivalent if and only if they belong to the same type
     * equivalence set.
     *
     * @param obj the object with which to compare.
     * @return true if and only if the objects are type equivalent.
     */
    private final boolean isTypeEquiv(Object obj) {
        // type checking occurs in the calling method:
        ObjectEquiv obj2 = (ObjectEquiv) obj;
        return this.getTypeEquiv().equals(obj2.getTypeEquiv());
    }

    /**
     * Compares this object with the given object by doing a
     * "deep comparison" on the two objects. The #equals method
     * (which calls this method) ensures that the two objects are
     * type compatible, therefore the given object may be safely
     * cast to the type of this object for any given implementation
     * of the method.
     * <p>
     * This implementation always returns true. This permits blind
     * chaining of a hierarchy of <code>localEquals</code> methods.
     * <p>
     * Subclasses typically override this method. (If the immediate
     * subclass does not override this trivial implementation, then
     * all instances of the subclass are equal by definition.)
     * If a subclass does in fact override this method, it should
     * also override the #getTypeEquiv method. If a subclass does
     * not override this method, instances of the subclass are assumed
     * to have the same "deep structure" as instances of the parent
     * class, that is, the two instances are the same type and
     * therefore belong to the same type equivalence set.
     *
     * @param obj the object with which to compare.
     * @return true if and only if the objects are equal by
     *         "deep comparison".
     */
    protected boolean localEquals(Object obj) {
        return true;
    }

    /**
     * Gets the (non-null) type of this object. More precisely, gets
     * the type of the type equivalence set to which the object belongs.
     * <p>
     * Immediate subclasses must implement this method. Other subclasses
     * typically override this method. If a subclass does in fact
     * override this method, it should also override the #localEquals
     * method. If a subclass does not override this method, instances of
     * the subclass are assumed to be the same type as instances of the
     * parent class, that is, the two classes belong to the same type
     * equivalence set.
     * <p>
     * Note that an implementation of this method typically does not
     * return this.getClass(). If it did, a subclass might choose to
     * inherit the method hoping to become type equivalent with its
     * parent class, which would fail.
     * <p>
     * On the other hand, if an implementation were to return
     * this.getClass() and declare that implementation final, each
     * subclass would be forced into a unique type equivalence set,
     * that is, no two subclasses would be type equivalent.
     *
     * @return the (non-null) type of this object.
     */
    protected abstract Class getTypeEquiv();

}

