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

import org.globus.opensaml11.saml.SAMLException;

import java.util.Properties;

public abstract class ShibClient extends BaseClient {

    /**
     * A default AA endpoint location.
     * Agrees with the location set in example-metadata.xml
     * and the default IdP config file (idp.xml).
     */
    protected static final String DEFAULT_AAURL =
                             "https://idp.example.org:8443/shibboleth-idp/AA";

    /**
     * A default IdP providerId.
     * Agrees with the providerId set in example-metadata.xml
     * and the default IdP config file (idp.xml).
     */
    protected static final String DEFAULT_IDP_PROVIDERID =
                             "https://idp.example.org/shibboleth";

    /**
     * A default SP providerId.
     * Agrees with the providerId set in example-metadata.xml
     * and the default SP config file.
     */
    protected static final String DEFAULT_SP_PROVIDERID =
                             "https://sp.example.org/shibboleth";

    protected static final String DEFAULT_ALIAS = "globus";
    protected static final String DEFAULT_PASSWORD = "globus";
    protected static final String DEFAULT_KEYSTORE_FILE = "shib_client.jks";
    protected static final String DEFAULT_TRUSTSTORE_FILE = "shib_server.jks";

    // not in BaseClient
    protected String querySubject;

    protected static Properties defaults() {
        Properties defaultOptions = new Properties();

        defaultOptions.put(AA_URL.getOpt(), DEFAULT_AAURL);
        defaultOptions.put(IDP_PROVIDERID.getOpt(), DEFAULT_IDP_PROVIDERID);
        defaultOptions.put(SP_PROVIDERID.getOpt(), DEFAULT_SP_PROVIDERID);
        defaultOptions.put(NEW_TRUSTSTORE.getOpt(), DEFAULT_TRUSTSTORE_FILE);
        defaultOptions.put(NEW_KEYSTORE.getOpt(), DEFAULT_KEYSTORE_FILE);
        defaultOptions.put(NEW_KEYSTORE_PWD.getOpt(), DEFAULT_PASSWORD);
        defaultOptions.put(NEW_KEY_ALIAS.getOpt(), DEFAULT_ALIAS);

        return defaultOptions;
    }

    protected abstract AttributeQuery constructQuery() throws SAMLException;

    protected static void shibQuery(ShibClient client) {

        try {
            AttributeQuery query = client.constructQuery();

            // inner try/catch to make sure query != null
            try {
                System.out.println("\n** Sending query");
                if (client.debugMode) {
                    AttributeQuery.parseResponse(
                            query.run(),
                            System.out,
                            System.err);
                } else {
                    AttributeQuery.parseResponse(
                            query.run(),
                            System.out,
                            null);
                }

            } catch (Exception e) {

                if (client.debugMode) {
                    AttributeQuery.parseQueryError(
                            e,
                            System.err,
                            System.err);
                } else {
                    AttributeQuery.parseQueryError(
                            e,
                            System.err,
                            null);
                }

                if (client.debugMode) {
                    System.err.println(
                            "\n\n--------------- STACKTRACE ---------------");
                    e.printStackTrace();
                    System.err.println(
                            "------------------------------------------\n");
                }

                client.cleanup();
                System.exit(APPLICATION_ERROR);
            }

        } catch (SAMLException e) {
            System.err.println("Error constructing query: " + e.getMessage());
            if (client.debugMode) {
                System.err.println(
                        "\n\n--------------- STACKTRACE ---------------");
                e.printStackTrace();
                System.err.println(
                        "------------------------------------------\n");
            }

            client.cleanup();
            System.exit(APPLICATION_ERROR);
        }

        client.cleanup();
    }




}
