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

import java.util.List;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.security.auth.x500.X500Principal;
import org.globus.gsi.SigningPolicyParser;

/**
 * Represents a signing policy associated with a particular CA. The signing policy defines a list of distinguished
 * names which are allowed to sign certificates for a particular Certificate Authority subject distinguished name.
 *
 * @version ${version}
 * @since 1.0
 */
// COMMENT: BCB: new method signatures
public class SigningPolicy {

    private X500Principal caSubject;
    private List<Pattern> allowedDNs;

    /**
     * Create a signing policy for the supplied subject which allows the supplied list of DNs to sign certificates.
     *
     * @param caSubjectDN The DN for the subject to which this policy applies.
     * @param allowedDNs  The list of DNs which can sign certs for this subject.
     */
    public SigningPolicy(X500Principal caSubjectDN, String[] allowedDNs) {

        if ((caSubjectDN == null) || (allowedDNs == null)) {
            throw new IllegalArgumentException();
        }

        this.caSubject = caSubjectDN;
        int numberOfDNs = allowedDNs.length;
        this.allowedDNs = new Vector<Pattern>(numberOfDNs);
        for (String anAllowedDNs : allowedDNs) {
            this.allowedDNs.add(SigningPolicyParser.getPattern(anAllowedDNs));

        }
    }

    /**
     * Create a signing policy for the supplied subject which allows subjects whose DNs match one of the supplied
     * patterns to sign certificates.
     *
     * @param caSubjectDN The DN for the subject to which this policy applies.
     * @param allowedDNs  A list of patterns to which to compare signing entity DNs.
     */
    // COMMENT: allowedDNs != null is new, and causes the test to fail
    public SigningPolicy(X500Principal caSubjectDN, List<Pattern> allowedDNs) {

        if ((caSubjectDN == null) || (allowedDNs == null)) {
            throw new IllegalArgumentException();
        }

        this.caSubject = caSubjectDN;
        this.allowedDNs = allowedDNs;
    }

    /**
     * Get CA subject DN for which this signing policy is defined.
     *
     * @return returns the CA subject
     */
    public X500Principal getCASubjectDN() {
        return this.caSubject;
    }

    /**
     * Ascertains if the subjectDN is valid against this policy.
     *
     * @param subject Subject DN to be validated
     * @return true if the DN is valid under this policy and false if it is not
     */
    public boolean isValidSubject(X500Principal subject) {

        if (subject == null) {
            throw new IllegalArgumentException();
        }

        String subjectDN = CertificateUtil.toGlobusID(subject);

        if ((this.allowedDNs == null) || (this.allowedDNs.size() < 1)) {
            return false;
        }

        int size = this.allowedDNs.size();
        for (int i = 0; i < size; i++) {
            Pattern pattern = allowedDNs.get(i);
            Matcher matcher = pattern.matcher(subjectDN);
            boolean valid = matcher.matches();
            if (valid) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return the patterns which identify the valid signing entities.  If this signing policy has been created with a
     * set of DNs then the patterns will simply match the DNs.
     *
     * @return The patterns matching allowed signing entities.
     */
    public List<Pattern> getAllowedDNs() {
        return this.allowedDNs;
    }

    /**
     * Method to determine if a signing policy is available for a
     * given DN.
     *
     * @return If the patterns vector is not null and has atleast one
     * element, true is returned. Else the method returns false.
     */
    public boolean isPolicyAvailable() {

        if ((this.allowedDNs == null) ||
            (this.allowedDNs.size() < 1)) {
            return false;
        }
        return true;
    }

}
