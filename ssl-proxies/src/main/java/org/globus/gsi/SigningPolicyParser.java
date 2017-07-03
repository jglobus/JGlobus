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

import org.globus.gsi.util.CertificateUtil;

import org.apache.commons.logging.LogFactory;

import org.apache.commons.logging.Log;


import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.Vector;


import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;


/**
 * Signing policy BCNF grammar as implemented here: (based on C implementation)
 * <p>
 * eacl ::= {eacl_entry}<br>
 * eacl_entry ::= {access_identity} pos_rights {restriction}
 * {pos_rights {restriction}} | {access_identity} neg_rights<br>
 * access_identity ::= access_identity_type def_authority value<br>
 * access_identity_type ::= "access_id_HOST" | "access_id_USER" |
 * "access_id_GROUP" | "access_id_CA" | "access_id_APPLICATION" |
 * "access_id_ANYBODY"<br>
 * pos_rights ::= "pos_rights" def_authority value
 * {"pos_rights" def_authority value}<br>
 * neg_rights ::= "neg_rights" def_authority value
 * {"neg_rights" def_authority value}<br>
 * restriction ::= condition_type def_authority value<br>
 * condition_type ::= alphanumeric_string<br>
 * def_authority ::= alphanumeric_string<br>
 * value ::= alphanumeric_string
 * <p>
 * This class take a signing policy file as input and parses it to extract the
 * policy that is enforced. Only the following policy is enforced: access_id_CA
 * with defining authority as X509 with CA DN as value. Any positive rights
 * following it with globus as defining authority and value CA:sign. Lastly,
 * restriction "cond_subjects" with globus as defining authority and the DNs the
 * CA is authorized to sign. restrictions are assumed to start with cond_. Order
 * of rights matter, so the first occurance of CA:Sign with allowedDNs is used
 * and rest of the policy is ignored.
 * <p>
 * For a given signing policy file, only policy with the particular CA's DN is
 * parsed.
 * <p>
 * subject names may include the following wildcard characters: *    Matches
 * zero or any number of characters. ?    Matches any single character.
 * <p>
 * All subject names should be in Globus format, with slashes and should NOT be
 * revered.
 * <p>
 * The allowed DN patterns are returned as a vector of java.util.regexp.Pattern.
 * The BCNF grammar that uses wildcard (*) and single character (?) are replaced
 * with the regexp grammar needed by the Pattern class.
 */
// COMMENT: BCB: moved over from crux-security-core: different parse-function name, stricter check for parameters
public class SigningPolicyParser {

    public static final String ACCESS_ID_PREFIX = "access_id_";
    public static final String ACCESS_ID_CA = "access_id_CA";

    public static final String DEF_AUTH_X509 = "X509";
    public static final String DEF_AUTH_GLOBUS = "globus";

    public static final String POS_RIGHTS = "pos_rights";
    public static final String NEG_RIGHTS = "neg_rights";

    public static final String CONDITION_PREFIX = "cond_";
    public static final String CONDITION_SUBJECT = "cond_subjects";

    public static final String VALUE_CA_SIGN = "CA:sign";

    public static final String SINGLE_CHAR = "?";
    public static final String WILDCARD = "*";

    public static final String SINGLE_PATTERN = "[\\p{Print}\\p{Blank}]";
    public static final String WILDCARD_PATTERN = SINGLE_PATTERN + "*";
    private static final int MIN_TOKENS_PER_LINE = 3;

    static final String[] ALLOWED_LINE_START = new String[]{ACCESS_ID_PREFIX, POS_RIGHTS, NEG_RIGHTS, CONDITION_PREFIX};

    private Log logger = LogFactory.getLog(SigningPolicyParser.class.getName());

    /**
     * Parses the file to extract signing policy defined for CA with the
     * specified DN. If the policy file does not exist, a SigningPolicy object
     * with only CA DN is created. If policy path exists, but no relevant policy
     * exisit, SigningPolicy object with CA DN and file path is created.
     *
     * @param fileName Name of the signing policy file
     * @return SigningPolicy object that contains the information. If no policy
     *         is found, SigningPolicy object with only the CA DN is returned.
     * @throws org.globus.gsi.SigningPolicyException
     *                               Any errors with parsing the signing policy file.
     * @throws FileNotFoundException If the signing policy file does not exist.
     */
    public Map<X500Principal, SigningPolicy> parse(String fileName)
            throws FileNotFoundException, SigningPolicyException {

        if ((fileName == null) || (fileName.trim().isEmpty())) {
            throw new IllegalArgumentException();
        }

        logger.debug("Signing policy file name " + fileName);

        FileReader fileReader = null;

        try {
            fileReader = new FileReader(fileName);
            return parse(fileReader);
        } catch (Exception e) {
            throw new SigningPolicyException(e);
        } finally {
            if (fileReader != null) {
                try {
                    fileReader.close();
                } catch (Exception exp) {
                    logger.debug("Error closing file reader", exp);
                }
            }
        }


    }

    /**
     * Parses input stream to extract signing policy defined for CA with the
     * specified DN.
     *
     * @param reader Reader to any input stream to get the signing policy
     *               information.
     * @return signing policy map defined by the signing policy file
     * @throws org.globus.gsi.SigningPolicyException
     *          Any errors with parsing the signing policy.
     */
    public Map<X500Principal, SigningPolicy> parse(Reader reader)
            throws SigningPolicyException {

        Map<X500Principal, SigningPolicy> policies = new HashMap<X500Principal, SigningPolicy>();

        BufferedReader bufferedReader = new BufferedReader(reader);
        try {
            String line;

            while ((line = bufferedReader.readLine()) != null) {

                line = line.trim();

                // read line until some line that needs to be parsed.
                if (!isValidLine(line)) {
                    continue;
                }

                logger.debug("Line to parse: " + line);

                String caDN = null;
                if (line.startsWith(ACCESS_ID_PREFIX)) {

                    logger.debug("Check if it is CA and get the DN " + line);
                    caDN = getCaDN(line, caDN);
                    boolean usefulEntry = true;
                    Boolean posNegRights = null;
                    // check for neg or pos rights with restrictions
                    checkRights(policies, bufferedReader, caDN, usefulEntry, posNegRights);
                }
                // JGLOBUS-94
            }
        } catch (IOException exp) {
            throw new SigningPolicyException("", exp);
        } finally {
            cleanupReaders(reader, bufferedReader);
        }
        return policies;
    }

    private void checkRights(Map<X500Principal, SigningPolicy> policies, BufferedReader bufferedReader, String caDN,
                             boolean usefulEntry, Boolean posNegRights) throws IOException, SigningPolicyException {
        boolean tmpUsefulEntry = usefulEntry;
        Boolean tmpPosNegRights = posNegRights;
        String line = bufferedReader.readLine();
        while (line != null) {

            if (!isValidLine(line)) {
                line = bufferedReader.readLine();
                continue;
            }

            line = line.trim();
            logger.debug("Line is " + line);

            if (line.startsWith(POS_RIGHTS)) {
                validatePositiveRights(tmpPosNegRights);
                if (tmpUsefulEntry) {
                    tmpUsefulEntry = isUsefulEntry(line);
                }
                tmpPosNegRights = Boolean.TRUE;
            } else if (line.startsWith(NEG_RIGHTS)) {
                tmpPosNegRights = handleNegativeRights(tmpPosNegRights);

            } else if (line.startsWith(CONDITION_PREFIX)) {
                if (handleConditionalLine(policies, line, caDN, tmpUsefulEntry, tmpPosNegRights)) {
                    break;
                }
            } else {
                String err = "invalidLine";
                // no valid start with
                // String err = i18n.getMessage("invalidLine", line);
                throw new SigningPolicyException(err + line);
            }
            line = bufferedReader.readLine();
        }
    }

    private boolean handleConditionalLine(Map<X500Principal, SigningPolicy> policies, String line, String caDN, boolean usefulEntry, Boolean posNegRights) throws SigningPolicyException {
        if (!Boolean.TRUE.equals(posNegRights)) {
            String err = "invalidRestrictions";
            //   i18n.getMessage("invalidRestrictions", line);
            throw new SigningPolicyException(err);
        }

        if (usefulEntry && line.startsWith(CONDITION_SUBJECT)) {
            logger.debug("Read in subject condition.");
            int startIndex = CONDITION_SUBJECT.length();
            int endIndex = line.length();
            Vector<Pattern> allowedDNs = getAllowedDNs(line.substring(startIndex, endIndex));
            // Some IGTF CA signing policies include all the various versions of having the emailAddress
            // in the DN.  The "E=" variant causes an exception to be thrown in modern JVMs.
            // Hence, we ignore invalid DNs.  Luckily, the signing policies contain all variants so
            // it is safe to ignore.
            try {
                X500Principal caPrincipal = CertificateUtil.toPrincipal(caDN);
                SigningPolicy policy = new SigningPolicy(caPrincipal, allowedDNs);
                policies.put(caPrincipal, policy);
            } catch (java.lang.IllegalArgumentException e) {
                if (caDN == null) {
                    throw e;
                }
                String [] components = caDN.split("/");
                boolean hasE = false;
                for (int i=0; i<components.length; i++) {
                    String attribute = components[i].split("=")[0];
                    if (attribute.equals("E")) {
                        hasE = true;
                        break;
                    }
                }
                if (hasE) {
                    logger.warn("Invalid DN (" + caDN + ") in the CA policy");
                    logger.debug("Invalid DN in the CA policy", e);
                    return true;
                } else {
                    throw e;
                }
            }
            return true;
        }
        return false;
    }

    private String getCaDN(String line, String caDN) throws SigningPolicyException {
        String outCaDN = caDN;
        if (line.startsWith(ACCESS_ID_CA)) {
            outCaDN = getCA(line.substring(ACCESS_ID_CA.length(),
                    line.length()));
            logger.debug("CA DN is " + outCaDN);
        }
        return outCaDN;
    }

    private void validatePositiveRights(Boolean posNegRights) throws SigningPolicyException {
        if (Boolean.FALSE.equals(posNegRights)) {
            String err = "invalidPosRights";
            //  i18n.getMessage("invalidPosRights", line);
            throw new SigningPolicyException(err);
        }
    }

    private boolean isUsefulEntry(String line) throws SigningPolicyException {
        boolean usefulEntry;
        logger.debug("Parse pos_rights here");
        int startIndex = POS_RIGHTS.length();
        int endIndex = line.length();
        // if it is not CASignRight, then
        // usefulentry will be false. Otherwise
        // other restrictions will be useful.
        usefulEntry = isCASignRight(line.substring(startIndex, endIndex));
        return usefulEntry;
    }

    private Boolean handleNegativeRights(Boolean posNegRights) throws SigningPolicyException {
        if (Boolean.TRUE.equals(posNegRights)) {
            String err = "invalidNegRights";
            //  i18n.getMessage("invalidNegRights", line);
            throw new SigningPolicyException(err);
        }
        logger.debug("Ignore neg_rights");
        return Boolean.FALSE;
    }

    private void cleanupReaders(Reader reader, BufferedReader bufferedReader) {
        if (bufferedReader != null) {
            try {
                bufferedReader.close();
            } catch (Exception exp) {
                //Nothing we can do
                logger.debug("Unable to close bufferedReader", exp);
            }
        }
        if (reader != null) {
            try {
                reader.close();
            } catch (Exception e) {
                //Nothing we can do
                logger.debug("Unable to close reader", e);
            }
        }
    }

    private boolean isValidLine(String line)
            throws SigningPolicyException {

        String trimmedLine = line.trim();

        // if line is empty or comment character, skip it.
        if (trimmedLine.isEmpty() || trimmedLine.startsWith("#")) {
            return false;
        }

        // Validate that there are atleast three tokens on the line
        StringTokenizer tokenizer = new StringTokenizer(trimmedLine);
        if (tokenizer.countTokens() < MIN_TOKENS_PER_LINE) {
            // String err = i18n.getMessage("invalidTokens", line);
            String err = "invalidTokens";
            throw new SigningPolicyException(err + " on line \"" + trimmedLine + "\"");
        }

        for (String allowedLineStart : ALLOWED_LINE_START) {
            if (trimmedLine.startsWith(allowedLineStart)) {
                return true;
            }
        }
        throw new SigningPolicyException("Line starts incorrectly");

    }

    private Vector<Pattern> getAllowedDNs(String line)
            throws SigningPolicyException {

        String trimmedLine = line.trim();

        int index = findIndex(trimmedLine);

        if (index == -1) {
            String err = "invalid tokens";
            //  i18n.getMessage("invalidTokens", line);
            throw new SigningPolicyException(err);
        }

        String defAuth = trimmedLine.substring(0, index);

        if (DEF_AUTH_GLOBUS.equals(defAuth)) {

            String value = trimmedLine.substring(index + 1, trimmedLine.length());
            value = value.trim();

            int startIndex = 0;
            int endIndex = value.length();
            if (value.charAt(startIndex) == '\'') {
                startIndex++;
                int endOfDNIndex = value.indexOf('\'', startIndex);
                if (endOfDNIndex == -1) {
                    String err = "invlaid subjects";
                    //i18n.getMessage("invalidSubjects",
                    //                       lineForErr);
                    throw new SigningPolicyException(err);
                }
                endIndex = endOfDNIndex;
            }

            value = value.substring(startIndex, endIndex);
            value = value.trim();

            if (value.isEmpty()) {
                String err = "empty subjects";
                //i18n.getMessage("emptySubjects", lineForErr);
                throw new SigningPolicyException(err);
            }

            Vector<Pattern> vector = new Vector<Pattern>();

            startIndex = 0;
            endIndex = value.length();
            if (value.indexOf("\"") == -1) {
                vector.add(getPattern(value));
            } else {
                while (startIndex < endIndex) {

                    int quot1 = value.indexOf("\"", startIndex);
                    int quot2 = value.indexOf("\"", quot1 + 1);
                    if (quot2 == -1) {
                        String err = "unmatched quotes";
                        //i18n.getMessage("unmatchedQuotes",
                        //                      lineForErr);
                        throw new SigningPolicyException(err);
                    }
                    String token = value.substring(quot1 + 1, quot2);
                    vector.add(getPattern(token));
                    startIndex = quot2 + 1;
                }
            }

            return vector;
        }
        return null;
    }

    private boolean isCASignRight(String line)
            throws SigningPolicyException {

        String trimmedLine = line.trim();

        int index = findIndex(trimmedLine);

        if (index == -1) {
            String err = "invalid tokens";
            //    i18n.getMessage("invalidTokens", line);
            throw new SigningPolicyException(err);
        }

        String defAuth = trimmedLine.substring(0, index);
        if (DEF_AUTH_GLOBUS.equals(defAuth)) {
            trimmedLine = trimmedLine.substring(index + 1, trimmedLine.length());
            trimmedLine = trimmedLine.trim();
            // check if it is CA:Sign
            String value = trimmedLine.substring(0, trimmedLine.length());
            if (VALUE_CA_SIGN.equals(value)) {
                return true;
            }
        }

        return false;
    }

    private String getCA(String inputLine)
            throws SigningPolicyException {

        String line = inputLine.trim();

        int index = findIndex(line);

        if (index == -1) {
            String err = "invalid tokens";
            //  i18n.getMessage("invalidTokens", line);
            throw new SigningPolicyException(err);
        }

        String defAuth = line.substring(0, index);

        if (DEF_AUTH_X509.equals(defAuth)) {

            line = line.substring(index + 1, line.length());
            line = line.trim();

//            String dnString = line.substring(0, line.length());

            String caDN;
            // find CA DN
            int caDNLocation = 0;
            if (line.charAt(caDNLocation) == '\'') {
                caDNLocation++;
                int endofDNIndex = line.indexOf('\'', caDNLocation + 1);
                if (endofDNIndex == -1) {
                    //  String err = i18n.getMessage("invalidCaDN", inputLine);
                    String err = "invalid ca dn";
                    throw new SigningPolicyException(err);
                }
                caDN = line.substring(caDNLocation, endofDNIndex);
            } else {
                caDN = line.substring(caDNLocation, line.length() - 1);
            }
            caDN = caDN.trim();
            return caDN;
        }
        return null;
    }

    /**
     * Method that takes a pattern string as described in the signing policy
     * file with * for zero or many characters and ? for single character, and
     * converts it into java.util.regexp.Pattern object. This requires replacing
     * the wildcard characters with equivalent expression in regexp grammar.
     *
     * @param patternStr Pattern string as described in the signing policy file
     *                   with for zero or many characters and ? for single
     *                   character
     * @return Pattern object with the expression equivalent to patternStr.
     */
    public static Pattern getPattern(String patternStr) {

        if (patternStr == null) {
            throw new IllegalArgumentException();
        }

        int startIndex = 0;
        int endIndex = patternStr.length();
        StringBuffer buffer = new StringBuffer("");
        while (startIndex < endIndex) {
            int star = patternStr.indexOf(WILDCARD, startIndex);
            if (star == -1) {
                star = endIndex;
                String preStr = patternStr.substring(startIndex, star);
                buffer = buffer.append(preStr);
            } else {
                String preStr = patternStr.substring(startIndex, star);
                buffer = buffer.append(preStr).append(WILDCARD_PATTERN);
            }
            startIndex = star + 1;
        }

        String tmpPatternStr = buffer.toString();

        startIndex = 0;
        endIndex = tmpPatternStr.length();
        buffer = new StringBuffer("");
        while (startIndex < endIndex) {
            int qMark = tmpPatternStr.indexOf(SINGLE_CHAR, startIndex);
            if (qMark == -1) {
                qMark = endIndex;
                String preStr = tmpPatternStr.substring(startIndex, qMark);
                buffer = buffer.append(preStr);
            } else {
                String preStr = tmpPatternStr.substring(startIndex, qMark);
                buffer = buffer.append(preStr).append(SINGLE_PATTERN);
            }
            startIndex = qMark + 1;
        }
        tmpPatternStr = buffer.toString();

        LogFactory.getLog(SigningPolicyParser.class.getCanonicalName()).debug("String with replaced pattern is " + tmpPatternStr);

        return Pattern.compile(tmpPatternStr, Pattern.CASE_INSENSITIVE);
    }

    // find first space or tab as separator.

    private int findIndex(String line) {

        int index = -1;

        if (line == null) {
            return index;
        }

        String trimmedLine = line.trim();
        int spaceIndex = trimmedLine.indexOf(" ");
        int tabIndex = trimmedLine.indexOf("\t");

        if (spaceIndex != -1) {
            if (tabIndex != -1) {
                if (spaceIndex < tabIndex) {
                    index = spaceIndex;
                } else {
                    index = tabIndex;
                }
            } else {
                index = spaceIndex;
            }
        } else {
            index = tabIndex;
        }
        return index;
    }
}
