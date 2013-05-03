/*
 * Copyright 2013 NORDUnet A/S
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
package org.globus.gsi.util;

import org.bouncycastle.asn1.DERBitString;

public enum KeyUsage
{
    DIGITAL_SIGNATURE(0),
    NON_REPUDIATION(1),
    KEY_ENCIPHERMENT(2),
    DATA_ENCIPHERMENT(3),
    KEY_AGREEMENT(4),
    KEY_CERTSIGN(5),
    CRL_SIGN(6),
    ENCIPHER_ONLY(7),
    DECIPHER_ONLY(8);

    private int bit;

    private KeyUsage(int bit) {
        this.bit = bit;
    }

    public boolean isSet(DERBitString bits) {
        byte[] bytes = bits.getBytes();
        int length = (bytes.length * 8) - bits.getPadBits();
        return (bit < length && ((bytes[bit / 8] & (0x80 >>> (bit % 8))) != 0));
    }
}
