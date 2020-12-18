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
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;

import java.util.Properties;

public class GridShibClient extends ShibClient {

    protected static final String GRIDSHIB_DEFAULT_SP_PROVIDERID
            = "https://globus.org/gridshibtest";

    protected static final String GRIDSHIB_DEFAULT_IDENTITY
            = "CN=GridShib,OU=NCSA,O=UIUC";

    protected static final String GRIDSHIB_DEFAULT_KEYSTORE_FILE
            = "gridshib_client.jks";

    protected static final String GRIDSHIB_DEFAULT_TRUSTSTORE_FILE
            = "gridshib_server.jks";

    protected static final Option X509 =
        OptionBuilder.withArgName( "DN" )
        .hasArg()
        .withDescription("X509 distinguished name")
        .withLongOpt("dn")
        .create();

    protected GridShibClient() {
        this.options.addOption(X509);
    }

    protected void displayLongUsage() {
        System.out.println("A long help message");
    }
    // for shibQuery
    protected AttributeQuery constructQuery() throws SAMLException {
        AttributeQuery query = new AttributeQuery(
                this.querySubject,
                this.idpProviderid,
                this.spProviderid,
                this.aaurl,
                null,
                this.jksKeyPw,
                this.jksPath,
                this.jksPw,
                this.jksTruststore
        );
        query.useX509NameFormat();
        return query;
    }

    public static void main(String[] args) {

        GridShibClient client = new GridShibClient();
        client.setCustomUsage("[--" + X509.getLongOpt() + " DN]");

        Properties defaults = defaults();
        // override
        defaults.put(SP_PROVIDERID.getOpt(), GRIDSHIB_DEFAULT_SP_PROVIDERID);
        // set default identity to a DN in the mapping file
        // distributed with GridShib IdP plugin
        defaults.put(X509.getLongOpt(), GRIDSHIB_DEFAULT_IDENTITY);

        CommandLine line;
        try {
            line = client.parse(args, defaults);
            if (line.hasOption(X509.getLongOpt())) {
                String value = line.getOptionValue(X509.getLongOpt());
                if (value == null) {
                    throw new ParseException("X509 DN flag (--" +
                        X509.getLongOpt() + ") " +
                            "supplied, but argument is empty");
                } else {
                    client.querySubject = value;
                }
            }
        } catch(ParseException e) {
            System.err.println("Parsing Error: " + e.getMessage());
            if (client.debugMode) {
                System.err.println(
                        "\n\n--------------- STACKTRACE ---------------");
                e.printStackTrace();
                System.err.println(
                        "------------------------------------------\n");
            }

            // possibly leaving tmpfiles w/o removing them
            // don't know what threw error, best to not remove
            System.exit(COMMAND_LINE_ERROR);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            if (client.debugMode) {
                System.err.println(
                        "\n\n--------------- STACKTRACE ---------------");
                e.printStackTrace();
                System.err.println(
                        "------------------------------------------\n");
            }

            // possibly leaving tmpfiles w/o removing them
            // don't know what threw error, best to not remove
            System.exit(COMMAND_LINE_ERROR);
        }

        shibQuery(client);
    }

}
