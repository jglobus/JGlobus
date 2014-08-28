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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.globus.gsi.SigningPolicyException;

import java.io.StringReader;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.globus.gsi.SigningPolicy;
import org.globus.gsi.SigningPolicyParser;
import org.globus.gsi.testutils.FileSetupUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class TestSigningPolicyFileParser {

    FileSetupUtil successFile;
    FileSetupUtil singleAllowedDn;
    FileSetupUtil[] tabTestFiles;

    @Before
    public void setup() throws Exception {

        this.successFile =
                new FileSetupUtil(
                        "certificateUtilTest/samplePolicy.signing_policy");

        this.singleAllowedDn =
                new FileSetupUtil("certificateUtilTest/5aba75cb.signing_policy");

        this.tabTestFiles = new FileSetupUtil[3];
        this.tabTestFiles[0] =
                new FileSetupUtil("certificateUtilTest/afe55e66.signing_policy");
        this.tabTestFiles[1] =
                new FileSetupUtil("certificateUtilTest/cf4ba8c8.signing_policy");
        this.tabTestFiles[2] =
                new FileSetupUtil("certificateUtilTest/49f18420.signing_policy");
    }

    @Test
    public void testPatternMatching() throws Exception {

        // test getPattern method
        // no wildcards or question marks
        String patternStr = "CN=abcdefgh";
        String patternR = (SigningPolicyParser.getPattern(patternStr))
                .pattern();
        assertTrue("CN=abcdefgh".equals(patternR));

        // first character wildcard and question marks
        String pattern1Str = "CN=*def?gh?";
        Pattern pattern1 = SigningPolicyParser.getPattern(pattern1Str);
        String pattern1R = pattern1.pattern();
        assertTrue(("CN=" + SigningPolicyParser.WILDCARD_PATTERN + "def" +
                SigningPolicyParser.SINGLE_PATTERN + "gh" +
                SigningPolicyParser.SINGLE_PATTERN).equals(pattern1R));

        // only wild cards
        String pattern2Str = "/CN=abc*def*gh";
        Pattern pattern2 = SigningPolicyParser.getPattern(pattern2Str);
        String pattern2R = pattern2.pattern();
        assertTrue(
                ("/CN=abc" + SigningPolicyParser.WILDCARD_PATTERN + "def" +
                        SigningPolicyParser.WILDCARD_PATTERN + "gh").equals(
                        pattern2R));

        // test isValidDN methods
        // Add patern2, wildcards in middle
        Vector<Pattern> allowed = new Vector();
        allowed.add(pattern2);
        X500Principal fooPrincipal = new X500Principal("CN=foo");
        SigningPolicy policy = new SigningPolicy(fooPrincipal, allowed);

        X500Principal subject21 = new X500Principal("CN=abc12DEF34defdef56gh");
        assertTrue(policy.isValidSubject(subject21));

        X500Principal subject22 =
                new X500Principal("CN=123abc12def34defdef56gh");
        assertFalse(policy.isValidSubject(subject22));

        X500Principal subject23 =
                new X500Principal("CN=abc12def34defdef56gh123");
        assertFalse(policy.isValidSubject(subject23));

        // wildcard as first and last character
        String pattern3Str = "*abc*def*gh*";
        Pattern pattern3 = SigningPolicyParser.getPattern(pattern3Str);
        allowed.clear();
        allowed.add(pattern3);
        policy = new SigningPolicy(fooPrincipal, allowed);

        X500Principal subject31 = new X500Principal("CN=ABC12def34defdef56gh");
        assertTrue(policy.isValidSubject(subject31));

        X500Principal subject32 =
                new X500Principal("CN=123abc12def34defdef56gh555");
        assertTrue(policy.isValidSubject(subject32));

        // use of space and slashes, from old signing policy file
        String pattern4Str = "/C=US/O=Globus/*";
        Pattern pattern4 = SigningPolicyParser.getPattern(pattern4Str);
        allowed.clear();
        allowed.add(pattern4);

        policy = new SigningPolicy(fooPrincipal, allowed);

        X500Principal subject41 =
                new X500Principal(
                        "CN=Globus Certification Authority, O=Globus, C=US");
        assertTrue(policy.isValidSubject(subject41));

        // wildcard as first character, question mark
        String pattern5Str = "/*C=US/O=Globus/CN=foo-?/CN=*";
        Pattern pattern5 = SigningPolicyParser.getPattern(pattern5Str);
        allowed.clear();
        allowed.add(pattern5);
        policy = new SigningPolicy(fooPrincipal, allowed);

        X500Principal subject51 =
                new X500Principal(
                        "CN=Globus Certification Authority, O=Globus, O=US");
        assertFalse(policy.isValidSubject(subject51));
        X500Principal subject52 =
                new X500Principal(
                        "CN=test space,CN=a12b,CN=foo-1,O=Globus,C=US,C=SOME");
        assertTrue(policy.isValidSubject(subject52));
        X500Principal subject53 =
                new X500Principal("CN=,CN=foo-k,O=Globus,C=US");
        assertTrue(policy.isValidSubject(subject53));
        X500Principal subject54 =
                new X500Principal("CN= , CN=foo-1, O=Globus, C=US");
        assertTrue(policy.isValidSubject(subject54));

        X500Principal subject55 =
                new X500Principal("C=US,O=Globus,CN=foo-123,CN=");
        assertFalse(policy.isValidSubject(subject55));

        // multiple question mark with punctuation
        String pattern6Str = "/C=US/O=global/CN=*/CN=user-??";
        Pattern pattern6 = SigningPolicyParser.getPattern(pattern6Str);
        allowed.clear();
        allowed.add(pattern6);
        policy = new SigningPolicy(fooPrincipal, allowed);

        X500Principal subject61 =
                new X500Principal("CN=user-12,CN=foo,O=Globus,C=US");
        assertFalse(policy.isValidSubject(subject61));
        X500Principal subject62 =
                new X500Principal("CN=user-12,CN=foo,O=Global,C=US");
        assertTrue(policy.isValidSubject(subject62));
        X500Principal subject63 =
                new X500Principal("CN=user-12,CN=bar 1,CN=foo ,O=global,C=US");
        assertTrue(policy.isValidSubject(subject63));

        // add multiple patterns and test validity if atleast one matches
        String pattern7Str = "/C=US/O=Globus/CN=*/CN=user-??";
        Pattern pattern7 = SigningPolicyParser.getPattern(pattern7Str);
        allowed.add(pattern7);
        policy = new SigningPolicy(fooPrincipal, allowed);

        X500Principal subject71 =
                new X500Principal("CN=user-12, CN=bar 1, CN=foo , O=Globus,C=US");
        assertTrue(policy.isValidSubject(subject71));
        assertTrue(policy.isValidSubject(subject63));
    }

    // JGLOBUS-103
    @Test
    public void testFileSuccess() throws Exception {

        this.successFile.copyFileToTemp();

        SigningPolicyParser parser = new SigningPolicyParser();
        Map<X500Principal, SigningPolicy> map =
                parser.parse(this.successFile.getAbsoluteFilename());

        assertTrue(map != null);

        SigningPolicy policy =
                map.get(new X500Principal(
                        "CN=Globus Certification Authority,O=Globus,C=US"));

        assertTrue(policy != null);
        List<Pattern> allowedDN = policy.getAllowedDNs();
        assertTrue(allowedDN != null);
        assertTrue(allowedDN.size() == 2);

        List<String> patterns = new Vector(2);
        patterns.add((allowedDN.get(0)).pattern());
        patterns.add((allowedDN.get(1)).pattern());

        // given the getPattern method is already tested, assuming it
        // works here.
        Pattern p1 = SigningPolicyParser.getPattern("/C=us/O=Globus/*");
        assertTrue(patterns.contains(p1.pattern()));
        p1 = SigningPolicyParser.getPattern("/C=US/O=Globus/*");
        assertTrue(patterns.contains(p1.pattern()));
        p1 = SigningPolicyParser
                .getPattern("/C=us/O=National Computational Science Alliance/*");
        assertFalse(patterns.contains(p1.pattern()));

        policy = map.get(new X500Principal(
                "CN=Globus Certification Authority,O=National Computational Science Alliance,C=US"));
        assertTrue(policy != null);
        allowedDN = policy.getAllowedDNs();
        assertTrue(allowedDN != null);
        assertTrue(allowedDN.size() == 1);
        patterns.clear();
        patterns.add(((Pattern) allowedDN.get(0)).pattern());
        p1 = SigningPolicyParser
                .getPattern("/C=us/O=National Computational Science Alliance/*");
        assertTrue(patterns.contains(p1.pattern()));

        // test file with single allows DN without double quotes
        this.singleAllowedDn.copyFileToTemp();
        map.clear();
        map = parser.parse(this.singleAllowedDn.getAbsoluteFilename());

        policy = map.get(new X500Principal(
                "OU=Certification Authority,O=National Computational Science Alliance,C=US"));

        assertTrue(policy != null);
        allowedDN.clear();
        allowedDN = policy.getAllowedDNs();
        assertTrue(allowedDN != null);
        assertTrue(allowedDN.size() == 1);

        patterns = new Vector(1);
        patterns.add(((Pattern) allowedDN.get(0)).pattern());

        p1 = SigningPolicyParser
                .getPattern("/C=US/O=National Computational Science Alliance/*");
        assertTrue(patterns.contains(p1.pattern()));
    }

    @Test
    public void testFilesWithTab() throws Exception {

        this.tabTestFiles[0].copyFileToTemp();
        SigningPolicyParser parser = new SigningPolicyParser();

        Map<X500Principal, SigningPolicy> map =
                parser.parse(this.tabTestFiles[0].getAbsoluteFilename());

        SigningPolicy policy =
                map.get(new X500Principal("CN=CyGridCA,O=HPCL,O=CyGrid,C=CY"));
        assertTrue(policy != null);
        List<Pattern> allowedDN = policy.getAllowedDNs();
        assertTrue(allowedDN != null);
        assertTrue(allowedDN.size() == 1);

        allowedDN.clear();
        map.clear();
        this.tabTestFiles[1].copyFileToTemp();
        map = parser.parse(this.tabTestFiles[1].getAbsoluteFilename());
        policy = map.get(new X500Principal("CN=CNRS,O=CNRS,C=FR"));
        assertTrue(policy != null);
        allowedDN = policy.getAllowedDNs();
        assertTrue(allowedDN != null);
        assertTrue(allowedDN.size() == 2);

        Vector patterns = new Vector(2);
        patterns.add(((Pattern) allowedDN.get(0)).pattern());
        patterns.add(((Pattern) allowedDN.get(1)).pattern());

        // given the getPattern method is already tested, assuming it
        // works here.
        Pattern p1 = SigningPolicyParser
                .getPattern("/C=FR/O=CNRS/CN=CNRS-Projets");
        assertTrue(patterns.contains(p1.pattern()));
        p1 = SigningPolicyParser.getPattern("/C=FR/O=CNRS/CN=CNRS");
        assertTrue(patterns.contains(p1.pattern()));


        allowedDN.clear();
        map.clear();
        this.tabTestFiles[2].copyFileToTemp();
        map = parser.parse(this.tabTestFiles[2].getAbsoluteFilename());

        policy = map.get(
                new X500Principal("CN=INFN Certification Authority,O=INFN,C=IT"));
        assertTrue(policy != null);
        allowedDN = policy.getAllowedDNs();
        assertTrue(allowedDN != null);
        assertTrue(allowedDN.size() == 2);

        patterns.clear();
        patterns.add(((Pattern) allowedDN.get(0)).pattern());
        patterns.add(((Pattern) allowedDN.get(1)).pattern());

        // given the getPattern method is already tested, assuming it
        // works here.
        p1 = SigningPolicyParser.getPattern("/C=it/O=INFN/*");
        assertTrue(patterns.contains(p1.pattern()));
        p1 = SigningPolicyParser.getPattern("/C=IT/O=INFN/*");
        assertTrue(patterns.contains(p1.pattern()));
    }

    @Test(expected = SigningPolicyException.class)
    public void testFileFailure() throws Exception {
        SigningPolicyParser parser = new SigningPolicyParser();
        parser.parse("Foo");
    }

    @Test
    public void testParsingFailure() throws Exception {

        SigningPolicyParser parser = new SigningPolicyParser();

        // not x509
        String error1 =
                "access_id_CA      notX509         '/C=US/O=Globus/CN=Globus " +
                        "Certification Authority'\n pos_rights        globus        CA:sign\n" +
                        " cond_subjects     globus       '\"/C=us/O=Globus/*\"  \"/C=US/O=Globus/*\"'";


        Map<X500Principal, SigningPolicy> map = null;
        boolean worked = false;
        try {
            map = parser.parse(new StringReader(error1));
        } catch (IllegalArgumentException e) {
            worked = true;
        }
        assertTrue(worked);

        // not globus
        error1 =
                "access_id_CA      X509         '/C=US/O=Globus/CN=Globus " +
                        "Certification Authority'\n pos_rights        notglobus        " +
                        "CA:sign\n cond_subjects     globus       '\"/C=us/O=Globus/*\"  " +
                        "\"/C=US/O=Globus/*\"'";
        map = parser.parse(new StringReader(error1));


        // order of rights matter, atleast one positive right implies
        // allowed DN
        error1 =
                "access_id_CA      X509         '/C=US/O=Globus/CN=Globus Certification " +
                        "Authority'\n pos_rights        globus        CA:sign\n cond_subjects" +
                        "     globus       '\"/C=us/O=Globus/*\"  \"/C=US/O=Globus/*\"' \n " +
                        "neg_rights        notglobus        some:right";
        map = parser.parse(new StringReader(error1));
        SigningPolicy policy = map.get(new X500Principal(
                "CN=Globus Certification Authority,O=Globus,C=US"));
        assertTrue(policy != null);
        List<Pattern> allowedDN = policy.getAllowedDNs();
        assertTrue(allowedDN != null);
        assertTrue(allowedDN.size() == 2);

        // incorrect start
        error1 =
                "X509         '/C=US/O=Globus/CN=Globus Certification Authority'\n" +
                        " pos_rights        notglobus        CA:sign\n cond_subjects     " +
                        "globus       \'\"/C=us/O=Globus/*\"  \"/C=US/O=Globus/*\"\'";
        boolean exception = false;
        try {
            map = parser.parse(new StringReader(error1));
        } catch (SigningPolicyException exp) {
            exception = true;
        }
        assertTrue(exception);

        // erroneous quote
        error1 =
                "access_id_CA X509         '/C=US/O=Globus/CN=Globus Certification " +
                        "Authority\n pos_rights        notglobus        CA:sign\n " +
                        "cond_subjects     globus       \'\"/C=us/O=Globus/*\"  " +
                        "\"/C=US/O=Globus/*\"\'";
        exception = false;
        try {
            map = parser.parse(new StringReader(error1));
        } catch (SigningPolicyException exp) {
            if ((exp.getMessage().indexOf("invalid")) != -1) {
                exception = true;
            }
        }
        assertTrue(exception);

        // neg rights rather than restrictions
        error1 =
                "access_id_CA      X509         '/C=US/O=Globus/CN=Globus " +
                        "Certification Authority'\n pos_rights        globus        " +
                        "CA:sign\n  neg_rights        notglobus        some:right";
        exception = false;
        try {
            map = parser.parse(new StringReader(error1));
        } catch (SigningPolicyException exp) {
            // if ((exp.getMessage().indexOf("File format is incorrect") != -1) &&
            //     (exp.getMessage().
            //         indexOf("neg_rights cannot be used here") != -1)) {
            exception = true;
            // }
        }
        assertTrue(exception);

        // first pos_rights is all that matters
        error1 =
                "access_id_CA X509         '/C=US/O=Globus/CN=Globus Certification " +
                        "Authority'\n pos_rights        globus        CA:sign\n " +
                        "cond_subjects     globus       '\"/C=us/O=Globus/*\"  " +
                        "\"/C=US/O=Globus/*\"' \n cond_subjects     globus       " +
                        "'\"/C=us/O=Globus/*\"'";
        map = parser.parse(new StringReader(error1));
        policy = map.get(new X500Principal(
                "CN=Globus Certification Authority,O=Globus,C=US"));
        assertTrue(policy != null);
        allowedDN = policy.getAllowedDNs();
        assertTrue(allowedDN != null);
        assertTrue(allowedDN.size() == 2);
    }

    @After
    public void cleanUp() throws Exception {

        this.singleAllowedDn.deleteFile();
        this.successFile.deleteFile();
        this.tabTestFiles[0].deleteFile();
        this.tabTestFiles[1].deleteFile();
        this.tabTestFiles[2].deleteFile();

    }
}
