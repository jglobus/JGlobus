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
package org.globus.gsi.util;

import java.io.IOException;
import java.io.OutputStream;

// JGLOBUS-95 : how much of this can be borrwed directly form BC?

/**
 * Fill Me
 */
public final class PEMUtil {

    public static final String LINE_SEP;
    static final byte[] LINE_SEP_BYTES;

    static final int LINE_LENGTH = 64;

    private static final char[] HEX = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            'A', 'B', 'C', 'D', 'E', 'F'};

    static {
        LINE_SEP = System.getProperty("line.separator");
        LINE_SEP_BYTES = LINE_SEP.getBytes();
    }

    private PEMUtil() {
        //This should not be instantiated
    }


    public static void writeBase64(
            OutputStream out,
            String header,
            byte[] base64Data,
            String footer)
            throws IOException {

        int length = LINE_LENGTH;
        int offset = 0;

        if (header != null) {
            out.write(header.getBytes());
            out.write(LINE_SEP_BYTES);
        }

        int size = base64Data.length;
        while (offset < size) {
            if (LINE_LENGTH > (size - offset)) {
                length = size - offset;
            }
            out.write(base64Data, offset, length);
            out.write(LINE_SEP_BYTES);
            offset = offset + LINE_LENGTH;
        }

        if (footer != null) {
            out.write(footer.getBytes());
            out.write(LINE_SEP_BYTES);
        }
    }

    /**
     * Return a hexadecimal representation of a byte array
     *
     * @param b a byte array
     * @return String containing the hexadecimal representation
     */
    public static String toHex(byte[] b) {
        char[] buf = new char[b.length * 2];
        int j = 0;
        int k;

        for (byte aB : b) {
            k = aB;
            buf[j++] = HEX[(k >>> 4) & 0x0F];
            buf[j++] = HEX[k & 0x0F];
        }
        return new String(buf);
    }


}
