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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.ParseException;
import org.globus.opensaml11.saml.SAMLException;

import java.util.Properties;

public class ShibTestClient extends ShibClient {

    protected static final Option PRINCIPAL =
        OptionBuilder.withArgName( "principal" )
        .hasArg()
        .withDescription("principal name")
        .withLongOpt("principal")
        .create("f");

    protected ShibTestClient() {
        this.options.addOption(PRINCIPAL);
    }

    protected void displayLongUsage() {
        System.out.println("A long help message");
    }

    /**
     * A default NameIdentifier (with format emailAddress)
     * used to construct the attribute query.
     */
    protected static final String DEFAULT_IDENTITY =
        "bogus@example.org";

    /**
     * Construct an attribute query based on the emailAddress format.
     *
     * @return the constructed attribute query
     * @throws SAMLException if unable to construct the query
     * @see ShibClient#shibQuery(ShibClient)
     */
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
        query.useEmailNameFormat();
        return query;
    }

    public static void main(String[] args) {

        ShibTestClient client = new ShibTestClient();
        client.setCustomUsage("[-" + PRINCIPAL.getOpt() + " name]");

        Properties defaults = defaults();
        defaults.put(PRINCIPAL.getOpt(), DEFAULT_IDENTITY);

        CommandLine line;
        try {
            line = client.parse(args, defaults);
            if (line.hasOption(PRINCIPAL.getOpt())) {
                String value = line.getOptionValue(PRINCIPAL.getOpt());
                if (value == null) {
                    throw new ParseException("Principal flag (-" +
                        PRINCIPAL.getOpt() + ") " +
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
