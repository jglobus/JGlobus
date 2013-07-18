/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 * Copyright 2006-2009 University of Illinois
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

package org.globus.gridshib.client.saml.query;

import org.globus.opensaml11.saml.SAMLAssertion;
import org.globus.opensaml11.saml.SAMLAttribute;
import org.globus.opensaml11.saml.SAMLAttributeQuery;
import org.globus.opensaml11.saml.SAMLAttributeStatement;
import org.globus.opensaml11.saml.SAMLBinding;
import org.globus.opensaml11.saml.SAMLBindingFactory;
import org.globus.opensaml11.saml.SAMLConfig;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLNameIdentifier;
import org.globus.opensaml11.saml.SAMLRequest;
import org.globus.opensaml11.saml.SAMLResponse;
import org.globus.opensaml11.saml.SAMLSOAPBinding;
import org.globus.opensaml11.saml.SAMLStatement;
import org.globus.opensaml11.saml.SAMLSubject;
import org.globus.opensaml11.saml.SAMLSubjectStatement;

import javax.net.ssl.SSLHandshakeException;
import java.io.PrintStream;
import java.util.Iterator;

public class AttributeQuery {

    private static final String X509_FORMAT =
        SAMLNameIdentifier.FORMAT_X509;

    private static final String EMAIL_FORMAT =
        SAMLNameIdentifier.FORMAT_EMAIL;

    private static final String SHIB_FORMAT =
        "urn:mace:shibboleth:1.0:nameIdentifier";

    // defaults, getters and setters available
    private String format = EMAIL_FORMAT;
    private String keystore;
    private String keystore_pwd;
    private String key_pwd;
    private String truststore;
    private String identity;
    private String IdPproviderId;
    private String SPproviderId;
    private String AAUrl;

    // no getters and setters
    private SAMLConfig config = SAMLConfig.instance();
    private SAMLRequest request = null;

    public AttributeQuery() {
    }

    /**
     * @param identity  Value of the SAML NameIdentifier in the SAML subject
     *                  of the attribute query, this is the entity that the
     *                  call is querying about.
     *
     * @param SPproviderId  The Resource attribute of the AttributeQuery
     *                      element. Along with the SSL credential used to
     *                      establish the connection to the AA, this identifies
     *                      the entity making the attribute query.
     *
     * @param IdPproviderId  NameQualifier of the SAML NameIdentifier in the
     *                       SAML subject of the attribute query.
     *
     * @param AAUrl  URL of the attribute authority.
     *
     * @param nameFormat  NameIdentifier format
     *
     * @param keystore  Path to the Java keystore containing the client cert
     *                  to use for the attribute query, OpenSAML 1.1 requires
     *                  this keystore to be a file.
     *
     * @param keystore_pwd  Password to the Java keystore
     *
     * @param key_pwd  Password to the key in the Java keystore
     *
     * @param truststore  Path to the Java keystore containing cert of self
     *                    signed transport cert of AA or of the CA that signed
     *                    it.  OpenSAML 1.1 requires this keystore to be a file.
     *
     * @throws SAMLException
     */
    public AttributeQuery(String identity,
                          String IdPproviderId,
                          String SPproviderId,
                          String AAUrl,
                          String nameFormat,
                          String key_pwd,
                          String keystore,
                          String keystore_pwd,
                          String truststore) throws SAMLException {

        this.identity = identity;
        this.IdPproviderId = IdPproviderId;
        this.SPproviderId = SPproviderId;
        this.format = nameFormat;
        this.initRequest();

        this.AAUrl = AAUrl;

        this.setKey_pwd(key_pwd);
        this.setKeystore(keystore);
        this.setKeystore_pwd(keystore_pwd);
        this.setTruststore(truststore);
    }

    /**
     * convenience method, sets NameIdentifier format to
     * "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
     */
    public void useX509NameFormat() throws SAMLException {
        this.format = X509_FORMAT;
        this.initRequest();
    }

    /**
     * convenience method, sets NameIdentifier format to
     * "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
     */
    public void useEmailNameFormat() throws SAMLException {
        this.format = EMAIL_FORMAT;
        this.initRequest();
    }

    /**
     * convenience method, sets NameIdentifier format to
     * "urn:mace:shibboleth:1.0:nameIdentifier"
     */
    public void useShibNameFormat() throws SAMLException {
        this.format = SHIB_FORMAT;
        this.initRequest();
    }

    /**
     * Make the query.
     *
     * @throws Exception
     * @throws SAMLException
     */
    public SAMLResponse run() throws Exception {
        return runSAML();
    }

    // SAML client requires JKS *files* for client and trusted certs
    private SAMLResponse runSAML() throws Exception {
        try {
            SAMLBinding binding =
                    SAMLBindingFactory.getInstance(SAMLSOAPBinding.SOAP);

            return binding.send(this.AAUrl, this.request);
        }
        catch (SAMLException ex) {
            throw ex;
        }
    }

    /**
     * Parses multiple statements in multiple assertions
     * in a single response.
     *
     * @param resp the response to be parsed
     * @param out prints output to this stream
     * @param debug prints debug output to this stream
     */
    public static void parseResponse(SAMLResponse response,
                                     PrintStream out,
                                     PrintStream debug) {
        if (response == null) {
            out.println("Response is null");
            return;
        }

        if (debug != null) {
            debug.println("\n--------------- SAML ---------------");
            debug.println(response.toString());
            debug.println("------------------------------------\n");
        }

        Iterator assertions = response.getAssertions();
        if ((assertions == null) || (!assertions.hasNext())) {
            out.println("No assertions");
            return;
        }

        // process assertions:
        while (assertions.hasNext()) {
            SAMLAssertion assertion = (SAMLAssertion)assertions.next();
            if (debug != null) {
                debug.println("\n--------------- SAML ASSERTION ---------------");
                debug.println(assertion.toString());
                debug.println("----------------------------------------------\n");
            }
            out.println("\nReceived an assertion issued by: " + assertion.getIssuer());
            Iterator statements = assertion.getStatements();
            if ((statements == null) || (!statements.hasNext())) {
                out.println("There are no statements in the assertion");
                continue;
            }
            // process statements:
            while (statements.hasNext()) {
                SAMLStatement statement = (SAMLStatement) statements.next();
                if (!(statement instanceof SAMLAttributeStatement)) {
                    out.println("Skipping non-attribute statement");
                    continue;
                }
                out.println("\nAttribute statement:");
                SAMLSubject subject = ((SAMLSubjectStatement) statement).getSubject();
                out.println("  Subject: " +
                    subject.getNameIdentifier().getName());
                Iterator attributes = ((SAMLAttributeStatement) statement).getAttributes();
                if ((attributes == null) || (!attributes.hasNext())) {
                    out.println("There are no attributes");
                    continue;
                }
                // process attributes:
                int count = 0;
                while (attributes.hasNext()) {
                    SAMLAttribute attribute = (SAMLAttribute)attributes.next();
                    if (debug != null) {
                        debug.println("\n--------------- SAML ATTRIBUTE" +
                                " ---------------");
                        debug.println("--------------------------------" +
                                "--------------\n");
                        debug.println(attribute.toString());
                    }
                    count += 1;
                    out.println("\n  Attribute #" + count + ":");
                    out.println("     Name:      " + attribute.getName());
                    out.println("     Namespace: " + attribute.getNamespace());
                    Iterator values = attribute.getValues();
                    if ((values == null) || (!values.hasNext())) {
                        out.println("There are no attribute values");
                        continue;
                    }
                    // process attribute values:
                    while (values.hasNext()) {
                        out.println("     Value    : " + values.next());
                    }
                }
            }
        }
    }

    public static void parseQueryError(Exception e,
                                       PrintStream out,
                                       PrintStream debug) {
        if (e == null) {
            out.println("Error from the query is null");
            return;
        }

        if (e instanceof SAMLException) {
            parseSAMLerror((SAMLException)e, out, debug);
        } else {
            parseError(e, out, debug);
        }

    }

    private static void parseSAMLerror(SAMLException e,
                                       PrintStream out,
                                       PrintStream debug) {
        out.println("\n** SAML problem:");
        out.println(e.getMessage());

        if (e.getMessage().matches(".*General error processing request.*")) {
            out.println("\n** Solution:\nThis error means that the SSL " +
                    "handshake worked (that is good), but you need to " +
                    "consult the IdP log to know what went wrong." +
                    "\nIn idp.xml, try setting the" +
                    " <TransactionLog> and <ErrorLog> 'level' attributes" +
                    " to 'DEBUG'");
        }

        if (e.getMessage().matches(".*supplied Subject was unrecognized.*")) {
            out.println("\n** Solution:\nIf you are running a gridshib query," +
                    " this means the DN is not in the mapping file.");
        }

        if (e.getMessage().matches(".*Invalid credentials for request.*")) {
            out.println("\n** Solution:\nThis error means that the SSL " +
                    "handshake worked (that is good), but that the AA " +
                    "processing has determined that the credentials used " +
                    "are not valid.");
            out.println("This is typically because the " +
                    "credentials presented do not " +
                    "match what the AA's credential configuration is for " +
                    "the SP providerId you're using.");
            out.println("\nYou need to either:" +
                    "\n1) adjust the AA's metadata configuration " +
                    "and add this credential to the SP providerId's keys " +
                    "section.");
            out.println("2) present a different credential");
            out.println("3) or use a different SP providerId");
        }

        Throwable cause = e.getCause();
        if (cause instanceof SSLHandshakeException) {

            if (e.getMessage().matches(".*bad_certificate.*")) {
                out.println("\n** Solution:\n");
                out.println("This error means that you are making the " +
                            "query using client credentials that are not " +
                            "trusted by the Attribute Authority's SSL " +
                            "engine (typically provided by Apache httpd). " +
                            "An authenticated request is not even getting " +
                            "to the AA servlet in the Tomcat container " +
                            "(you will notice a lack of activity in the " +
                            "AA's DEBUG output), so you need to either " +
                            "change the SSL engine's configuration or " +
                            "present a different certificate.");
            } else {
                out.println("\n** Solution:\n");
                out.println("The exact nature of the error is unknown. " +
                            "It probably means that our end of the SSL " +
                            "handshake is not completing because we do " +
                            "not trust the Attribute Authority's SSL " +
                            "certificate, so you need adjust your trust " +
                            "configuration. If you have an IdP metadata " +
                            "file, check to make sure the metadata " +
                            "contains the AA's certificate. " +
                            "Otherwise, if you have the certificate " +
                            "and it is self-signed, or if you have the " +
                            "certificate of the CA that signed the AA's " +
                            "SSL certificate, try the pem_truststore " +
                            "option to this program.");
            }
        }

    }

    private static void parseError(Exception e,
                                   PrintStream out,
                                   PrintStream debug) {
        out.println("\n** Problem:");
        out.println(e.getMessage());
    }

    /**
     * This is called every time a new value needed for the SAML request is set,
     * whether via a setter method or at object instantiation time.
     *
     * This re-instantiates the SAML request object and therefore re-validates
     * the request.  This is not done in the run() method so that the run()
     * method only runs the query (this is helpful if the requests are being
     * queued, for example).
     *
     */
    private void initRequest() throws SAMLException {
        SAMLNameIdentifier nameid =
            SAMLNameIdentifier.getInstance(this.format);
        nameid.setName(this.identity);
        nameid.setNameQualifier(this.IdPproviderId);

        SAMLSubject subject = new SAMLSubject(nameid, null, null, null);

        SAMLAttributeQuery query = new SAMLAttributeQuery(
                subject,
                this.SPproviderId,
                null
            );

        this.request = new SAMLRequest(query);
    }

    /* getters and setters */

    public String getAAUrl() {
        return AAUrl;
    }

    public void setAAUrl(String AAUrl) {
        this.AAUrl = AAUrl;
    }

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) throws SAMLException {
        this.format = format;
        this.initRequest();
    }

    public String getIdentity() {
        return identity;
    }

    public void setIdentity(String identity) throws SAMLException {
        this.identity = identity;
        this.initRequest();
    }

    public String getIdPproviderId() {
        return IdPproviderId;
    }

    public void setIdPproviderId(String idPproviderId) throws SAMLException {
        IdPproviderId = idPproviderId;
        this.initRequest();
    }

    public String getKey_pwd() {
        return key_pwd;
    }

    public void setKey_pwd(String key_pwd) {
        if (key_pwd == null) {
            return;
        }
        this.key_pwd = key_pwd;
        this.config.setProperty(
                "org.globus.opensaml11.saml.ssl.key-pwd", this.key_pwd);
    }

    public String getKeystore() {
        return keystore;
    }

    public void setKeystore(String keystore) {
        if (keystore == null) {
            return;
        }
        this.keystore = keystore;
        this.config.setProperty(
                "org.globus.opensaml11.saml.ssl.keystore", this.keystore);
    }

    public String getKeystore_pwd() {
        return keystore_pwd;
    }

    public void setKeystore_pwd(String keystore_pwd) {
        if (keystore_pwd == null) {
            return;
        }
        this.keystore_pwd = keystore_pwd;
        this.config.setProperty(
                "org.globus.opensaml11.saml.ssl.keystore-pwd", this.keystore_pwd);
    }

    public String getSPproviderId() {
        return SPproviderId;
    }

    public void setSPproviderId(String SPproviderId) throws SAMLException {
        this.SPproviderId = SPproviderId;
        this.initRequest();
    }

    public String getTruststore() {
        return truststore;
    }

    public void setTruststore(String truststore) {
        if (truststore == null) {
            return;
        }
        this.truststore = truststore;
        this.config.setProperty(
                "org.globus.opensaml11.saml.ssl.truststore", this.truststore);
    }


}
