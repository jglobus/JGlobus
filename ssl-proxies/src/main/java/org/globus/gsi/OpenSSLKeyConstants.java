/*
 * Copyright 1999-2010 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS,WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

package org.globus.gsi;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Jan 21, 2010
 * Time: 10:32:19 AM
 * To change this template use File | Settings | File Templates.
 */
public final class OpenSSLKeyConstants {
    public static final int DES_EDE3_CBC_KEY_LENGTH = 24;
    public static final int DES_EDE3_CBC_IV_LENGTH = 8;
    public static final int AES_128_CBC_KEY_LENGTH = 16;
    public static final int AES_128_CBC_IV_LENGTH = 16;
    public static final int AES_192_CBC_KEY_LENGTH = 24;
    public static final int AES_192_CBC_IV_LENGTH = 16;
    public static final int AES_256_CBC_KEY_LENGTH = 32;
    public static final int AES_256_CBC_IV_LENGTH = 16;
    public static final int DES_CBC_KEY_LENGTH = 8;
    public static final int DES_CBC_IV_LENGTH = 8;

    private OpenSSLKeyConstants() {
        //should not be instantiated;
    }

}
