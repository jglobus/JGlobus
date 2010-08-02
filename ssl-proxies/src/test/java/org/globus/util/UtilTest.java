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
package org.globus.util;

import junit.framework.TestCase;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.globus.util.Util;

public class UtilTest extends TestCase {

    private Log logger = LogFactory.getLog(UtilTest.class);

    private static final String uStr1 = "(exe = mis)";
    private static final String qStr1 = "\"(exe = mis)\"";

    private static final String uStr2 = "(exe = \"mis\")";
    private static final String qStr2 = "\"(exe = \\\"mis\\\")\"";

    private static final String uStr3 = "(exe = \"mis\"\\test)";
    private static final String qStr3 = "\"(exe = \\\"mis\\\"\\\\test)\"";

    public void testQuote1() {
        String tStr1 = Util.quote(uStr1);
        logger.debug(uStr1 + " : " + tStr1);
        assertEquals("t1", qStr1, tStr1);

        String tStr2 = Util.quote(uStr2);
        logger.debug(uStr2 + " : " + tStr2);
        assertEquals("t2", qStr2, tStr2);

        String tStr3 = Util.quote(uStr3);
        logger.debug(uStr3 + " : " + tStr3);
        assertEquals("t3", qStr3, tStr3);
    }

    public void testUnQuote1() {
        try {
            String tStr0 = Util.unquote(uStr1);
            logger.debug(uStr1 + " : " + tStr0);
            assertEquals("t0", uStr1, tStr0);
        } catch (Exception e) {
            fail("Unquote failed.");
        }

        try {
            String tStr1 = Util.unquote(qStr1);
            logger.debug(qStr1 + " : " + tStr1);
            assertEquals("t1", uStr1, tStr1);
        } catch (Exception e) {
            fail("Unquote failed.");
        }

        try {
            String tStr2 = Util.unquote(qStr2);
            logger.debug(qStr2 + " : " + tStr2);
            assertEquals("t2", uStr2, tStr2);
        } catch (Exception e) {
            fail("Unquote failed.");
        }

        try {
            String tStr3 = Util.unquote(qStr3);
            logger.debug(qStr3 + " : " + tStr3);
            assertEquals("t3", uStr3, tStr3);
        } catch (Exception e) {
            fail("Unquote failed.");
        }
    }
}
