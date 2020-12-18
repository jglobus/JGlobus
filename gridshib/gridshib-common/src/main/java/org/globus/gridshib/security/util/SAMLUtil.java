/*
 * Copyright 2007-2009 University of Illinois
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.globus.gridshib.security.util;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.mapper.GridShibEntityMapper;
import org.globus.gridshib.security.SAMLSecurityContext;
import org.globus.gridshib.security.x509.SAMLX509Extension;
import org.globus.gridshib.security.util.CertUtil;

import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLSubjectAssertion;

public class SAMLUtil {

    private static Log logger =
        LogFactory.getLog(SAMLUtil.class.getName());

    /**
     * Gets <em>all</em> the SAML assertions from the
     * given certificate chain, up to and including the
     * first non-impersonation proxy.
     *
     * @param certs an X.509 certificate chain
     * @return an array of SAML subject assertions (or
     *         null if the given certificate chain does not
     *         contain any embedded SAML assertions)
     *
     * @exception java.io.IOException
     *            If unable to decode a certificate extension
     * @exception org.globus.opensaml11.saml.SAMLException
     *            If unable to parse a SAML assertion
     * @exception java.security.cert.CertificateException
     *            If unable to determine if a certificate is
     *            an impersonation proxy
     */
    public static SAMLSubjectAssertion[] getSAMLAssertions(
            X509Certificate[] certs) throws IOException, SAMLException,
                                            CertificateException {

        if (certs == null) {
            String msg = "Null cert chain";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }
        logger.debug("certs = " + certs.toString());

        SAMLSubjectAssertion assertion = null;
        List assertions = new ArrayList();

        // the SAML certificate extension search algorithm:
        for (int i = 0; i < certs.length; i++) {
            logger.debug("Processing certificate " + i + ": " +
                         certs[i].toString());
            assertion = SAMLX509Extension.getSAMLAssertion(certs[i]);
            if (assertion == null) {
                logger.debug("No SAML extension found in this certificate");
            } else {
                logger.debug("SAML extension found in this certificate");
                assertions.add(assertion);
            }
            if (!CertUtil.isImpersonationProxy(certs[i])) {
                logger.debug("All certificates processed");
                break;
            }
        }

        Object[] o = assertions.toArray(new SAMLSubjectAssertion[0]);
        return (SAMLSubjectAssertion[])o;
    }

    /**
     * First obtain the certificate chain of the authenticated
     * user from the existing security context, and then traverse
     * the certificate chain and search for bound SAML assertions.
     * Add the parsed SAML assertions to the user's security context.
     *
     * @param subject the authenticated subject
     *
     * @exception java.io.IOException
     *            If unable to decode a certificate extension
     * @exception org.globus.opensaml11.saml.SAMLException
     *            If unable to parse a SAML assertion
     * @exception java.security.cert.CertificateException
     *            If unable to determine if a certificate is
     *            an impersonation proxy
     */
    public static void consumeSAMLAssertions(Subject subject)
                                      throws IOException,
                                             SAMLException,
                                             CertificateException {

        if (subject == null) {
            String msg = "Null subject";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }
        logger.debug("subject = " + subject.toString());

        X509Certificate[] certs =
            CertUtil.getCertificateChain(subject);
        if (certs == null) {
            logger.warn("Unable to obtain certificate chain");
            logger.info("Attribute collection aborted");
            return;
        }
        logger.debug("Found " + certs.length + " certificates in the chain");

        traverseCertChain(subject, certs);
    }

    /**
     * Traverse the given certificate chain of the authenticated
     * user, looking for bound SAML assertions.  Add the parsed
     * SAML assertions to the user's security context.
     *
     * @param subject the authenticated subject
     * @param certs the X.509 certificate chain previously presented
     *              by the subject as an authentication token
     *
     * @exception java.io.IOException
     *            If unable to decode a certificate extension
     * @exception org.globus.opensaml11.saml.SAMLException
     *            If unable to parse a SAML assertion
     * @exception java.security.cert.CertificateException
     *            If unable to determine if a certificate is
     *            an impersonation proxy
     */
    private static void traverseCertChain(Subject subject,
                                          X509Certificate[] certs)
                                   throws IOException,
                                          SAMLException,
                                          CertificateException {

        if (subject == null) {
            String msg = "Null subject";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }
        logger.debug("subject = " + subject.toString());

        if (certs == null) {
            String msg = "Null certificate chain";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }
        logger.debug("Found " + certs.length + " certificates in the chain");

        // the SAML certificate extension search algorithm:
        for (int i = 0; i < certs.length; i++) {
            logger.debug("Processing certificate: " + certs[i].toString());
            if (SAMLX509Extension.hasSAMLExtension(certs[i])) {
                logger.debug("SAML extension found in this certificate");
                consumeSAMLExtension(subject, certs[i]);
            } else {
                logger.debug("No SAML extension found in this certificate");
            }
            if (!CertUtil.isImpersonationProxy(certs[i])) {
                logger.debug("All certificates processed");
                break;
            }
        }
    }

    /**
     * Consumes the SAML certificate extension by extracting the
     * assertion from the certificate and processing it.  If the
     * assertion is a self-issued assertion, and the certificate
     * is an impersonation proxy, the SAML issuer is taken as
     * the EEC subject; otherwise, the SAML issuer is simply the
     * assertion issuer.
     * <p>
     * The algorithm distinguishes between two types of
     * assertions: signed assertions and unsigned assertions.
     * A signed assertion (called a <em>third-party
     * assertion</em>) is accepted if and only if the signature
     * can be verified.  This requires a trusted certificate
     * from SAML metadata.
     * <p>
     * A special type of unsigned assertion is the case
     * where the issuer of the assertion and the issuer
     * of the certificate are one and the same entity.
     * This is called a <em>self-issued assertion</em>.
     * To determine if an assertion is self-issued, we
     * search for the value of attribute
     * <code>Assertion/@Issuer</code> in metadata and map
     * this issuer to an X.509 issuer.
     * If the latter matches the issuer of the presented
     * certificate, the assertion is a self-issued assertion.
     * <p>
     * In the case of a self-issued assertion, since the
     * assertion issuer and the certificate issuer are one
     * and the same entity, the
     * signature on the certificate covers the assertion.
     * Assuming the signature on the certificate has
     * already been verified, the assertion issuer is
     * therefore postively identified.
     * <p>
     * An unsigned assertion that is not self-issued is
     * not processed.
     * <p>
     * As a practical matter, regardless of the type of
     * entity mapping used, we can always compare the issuer
     * DN of the presented certificate to the mapped DN in
     * metadata.  If SAML metadata is used, and the
     * metadata contains a trusted certificate, we can
     * instead compare X500Principal objects and thereby avoid
     * DN string comparisons.  Thus we strongly recommend
     * that complete certificates (as opposed to DNs or
     * bare keys) be included in SAML metadata.
     *
     * @param subject the authenticated subject
     * @param cert a certificate from the certificate chain
     *             presented by the subject
     *
     * @exception java.io.IOException
     *            If unable to decode a certificate extension
     * @exception org.globus.opensaml11.saml.SAMLException
     *            If unable to parse a SAML assertion
     * @exception java.security.cert.CertificateException
     *            If unable to determine if a certificate is
     *            an impersonation proxy
     */
    private static void consumeSAMLExtension(Subject subject,
                                             X509Certificate cert)
                                      throws IOException,
                                             SAMLException,
                                             CertificateException {

        assert (subject != null);
        assert (cert != null);

        // get a SAML subject assertion:
        SAMLSubjectAssertion assertion =
            SAMLX509Extension.getSAMLAssertion(cert);
        if (assertion == null) {
            logger.warn("Unable to obtain SAML assertion");
            logger.info("Skipping this certificate extension");
            return;
        }
        logger.debug("Processing assertion: " + assertion.toString());

        // the SAML issuer is the assertion issuer:
        String issuer = assertion.getIssuer();

        if (assertion.isSigned()) {
            logger.debug("Processing signed assertion...");
            X509Certificate signingCert =
                GridShibEntityMapper.getX509Certificate(issuer);
            if (signingCert == null) {
                logger.error("Unable to locate a signing certificate " +
                             "for assertion issuer " + issuer);
                logger.info("Skipping this certificate extension");
                return;
            } else {
                logger.debug("Using signing certificate: " +
                             signingCert.toString());
            }
            try {
                assertion.verify(signingCert);
            } catch (SAMLException e) {
                logger.error("Unable to verify assertion signature");
                logger.debug(e);
                logger.info("Skipping this certificate extension");
                return;
            }
            if (isAssertionValid(assertion)) {
                logger.debug("Signed assertion is valid");
            } else {
                logger.error("Signed assertion is not valid");
                logger.info("Skipping this certificate extension");
                return;
            }
        } else {
            X500Principal certIssuer = null;
            if (CertUtil.isImpersonationProxy(cert)) {
                X509Certificate eec = CertUtil.getEEC(subject);
                // TODO: handle possible null EEC
                certIssuer = eec.getSubjectX500Principal();
            } else {
                certIssuer = cert.getIssuerX500Principal();
            }
            logger.debug("Certificate issuer: " + certIssuer.toString());
            if (isSelfIssuedAssertion(issuer, certIssuer)) {
                logger.debug("Processing self-issued assertion");
            } else {
                logger.error("Unable to identify assertion issuer " + issuer);
                logger.info("Skipping this certificate extension");
                return;
            }
        }

        SAMLSecurityContext secCtx =
           SAMLSecurityContext.getSAMLSecurityContext(subject);
        assert (secCtx != null);
        secCtx.parseSAMLAssertion(assertion);
    }

    // TODO: Implement validity check for third-party assertions
    private static boolean isAssertionValid(SAMLSubjectAssertion assertion) {
        return false;
    }

    /**
     * Checks whether the issuer of the assertion is the same as
     * the issuer of the certificate that contains the assertion,
     * that is, if the assertion is <em>self-issued</em>.
     * <p>
     * The following three tests are performed (in order):
     * <ol>
     *   <li>The assertion issuer is mapped to a certificate
     *   and the issuer of this mapped certificate is compared
     *   to the given <code>certIssuer</code> instance</li>
     *   <li>The assertion issuer is mapped to a DN and this
     *   mapped DN is compared to the DN of the given
     *   <code>certIssuer</code> instance</li>
     *   <li>The assertion issuer is compared directly to the
     *   DN of the given <code>certIssuer</code> instance</li>
     * </ol>
     * Note that test&nbsp;1 does <em>not</em> involve a DN
     * string comparison, which is preferred.  It is therefore
     * strongly recommended that complete certificates be
     * included in metadata.
     */
    private static boolean isSelfIssuedAssertion(String issuer,
                                                 X500Principal certIssuer) {

        assert (issuer != null && certIssuer != null);

        X509Certificate mappedCert =
            GridShibEntityMapper.getX509Certificate(issuer);
        if (mappedCert == null) {
            logger.debug("Unable to find a signing certificate " +
                         "for assertion issuer " + issuer);
        } else {
            logger.debug("Found a signing certificate " +
                         "for assertion issuer " + issuer);
            X500Principal mappedCertSubject =
                mappedCert.getSubjectX500Principal();
            logger.debug("Mapped certificate subject: " +
                         mappedCertSubject.toString());
            if (mappedCertSubject.equals(certIssuer)) {
                logger.debug("Mapped certificate subject equals " +
                             "certificate issuer");
                return true;
            }
            logger.warn("Mapped cert subject does not match " +
                        "certificate issuer " + certIssuer.toString());
        }

        String certIssuerStr = certIssuer.getName(X500Principal.RFC2253);

        Set trustedDNs = GridShibEntityMapper.getDNs(issuer);
        if (trustedDNs == null) {
            logger.debug("Unable to find a set of trusted DNs " +
                         "for assertion issuer " + issuer);
        } else {
            logger.debug("Found a set of trusted DNs " +
                         "for assertion issuer " + issuer);
            logger.debug("Mapped distinguished names: " +
                         trustedDNs.toString());
            if (trustedDNs.contains(certIssuerStr)) {
                logger.debug("Certificate issuer DN is a trusted DN");
                return true;
            }
            logger.warn("Mapped distinguished names do not contain " +
                        "the certificate issuer DN " + certIssuerStr);
        }

        if (issuer.equals(certIssuerStr)) {
            logger.debug("Certificate issuer DN matches assertion issuer");
            return true;
        }

        logger.warn("Assertion issuer does not match " +
                    "certificate issuer DN: " + certIssuerStr);
        return false;
    }
}
