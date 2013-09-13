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
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.PosixParser;

import java.security.cert.X509Certificate;
import java.util.Properties;
import java.util.Iterator;
import java.util.Map;
import java.io.File;

/**
 * Allows programs to inherit this cmdline functionality.
 *
 * Based on org.globus.wsrf.client.BaseClient
 */
public abstract class BaseClient {

    public static final int COMMAND_LINE_ERROR = 1;
    public static final int APPLICATION_ERROR = 2;

    protected boolean debugMode;
    protected String customUsage;
    protected String helpFooter;
    protected String helpHeader;
    protected Options options = new Options();

    protected String jksTruststore;
    protected boolean removeJKStrustStore = false;


    protected String pemPath;
    protected String pemKey;

    protected String jksPath;
    protected String jksPw;
    protected String jksKeyPw;
    protected boolean removeJKS = false;

    protected String aaurl;
    protected String idpProviderid;
    protected String spProviderid;

    public static final Option HELP =
        OptionBuilder.withDescription("Displays help")
        .withLongOpt("help")
        .create("h");

    private static final Option LONG_HELP =
        OptionBuilder
        .withDescription("Displays a long help message")
        .withLongOpt("lh")
        .create();

    public static final Option DEBUG =
        OptionBuilder.withDescription("Enables debug mode")
        .withLongOpt("debug")
        .create("d");

    public static final Option TRUSTSTORE =
        OptionBuilder.withArgName( "path" )
        .hasArg()
        .withDescription("Path to an existing Java keystore (JKS) containing " +
            "the server's SSL certificate if is self-signed or if not, the " +
            "certificate of the CA that signed it")
        .withLongOpt("truststore")
        .create("t");

    public static final Option PEM_TRUSTSTORE =
        OptionBuilder.withArgName( "path" )
        .hasArg()
        .withDescription("Path to a PEM file of " +
            "the server's SSL certificate if is self-signed or if not, the " +
            "certificate of the CA that signed it")
        .withLongOpt("pem_truststore")
        .create("r");

    public static final Option NEW_TRUSTSTORE =
        OptionBuilder.withArgName( "path" )
        .hasArg()
        .withDescription("Overrides default path to the ephemeral JKS" +
            " created to use for SSL server certificate verification process." +
            " Note: for password/alias, this uses the same settings as client" +
            " cert store (alias override is irrelevant when using metadata" +
            " option for the server trust information)")
        .withLongOpt("new_truststore")
        .create("x");

    public static final Option METADATA =
        OptionBuilder.withArgName( "path" )
        .hasArg()
        .withDescription("If this option is selected, the 'truststore' and " +
            "'pem_truststore' settings are ignored.  This metadata file " +
            "will be consulted for the AA SSL certificates to trust, adding " +
            "all <X509Certificate> in the <AttributeAuthorityDescriptor> " +
            "element of the given IdP providerId")
        .withLongOpt("metadata")
        .create("m");

    public static final Option KEYSTORE =
        OptionBuilder.withArgName( "path" )
        .hasArg()
        .withDescription("Path to an existing Java keystore (JKS) with " +
            "the SSL client certificate to use")
        .withLongOpt("jks")
        .create("j");

    public static final Option KEYSTORE_PWD =
        OptionBuilder.withArgName( "password" )
        .hasArg()
        .withDescription("Password for an existing JKS with the SSL " +
            "client certificate to use")
        .withLongOpt("jks_pass")
        .create("k");

    public static final Option KEY_PWD =
        OptionBuilder.withArgName( "password" )
        .hasArg()
        .withDescription("Password for the key in an existing JKS")
        .withLongOpt("jks_key_pass")
        .create("l");

    public static final Option NEW_KEYSTORE =
        OptionBuilder.withArgName( "path" )
        .hasArg()
        .withDescription("Overrides default path to the ephemeral JKS" +
            " created to use for SSL client certificate")
        .withLongOpt("new_jks")
        .create("w");

    public static final Option NEW_KEYSTORE_PWD =
        OptionBuilder.withArgName( "password" )
        .hasArg()
        .withDescription("Overrides default password for both of the " +
            "ephemeral JKS created to use for SSL certificates")
        .withLongOpt("new_jks_pass")
        .create("y");

    public static final Option NEW_KEY_ALIAS =
        OptionBuilder.withArgName( "string" )
        .hasArg()
        .withDescription("Overrides default alias for the key in both of the " +
            "ephemeral JKS created to use for SSL certificates")
        .withLongOpt("new_jks_alias")
        .create("z");

    public static final Option KEEP_NEW_KEYSTORE =
        OptionBuilder
        .withDescription("If this option is present, the normally " +
            "ephemeral client JKS file is not deleted after the query")
        .withLongOpt("keep_keystore")
        .create("u");

    public static final Option KEEP_NEW_TRUSTSTORE =
        OptionBuilder
        .withDescription("If this option is present, the normally " +
            "ephemeral server JKS truststore is not deleted after the query")
        .withLongOpt("keep_truststore")
        .create("v");

    public static final Option PEM =
        OptionBuilder.withArgName( "path" )
        .hasArg()
        .withDescription("Path to a PEM certificate to use for client " +
            "authentication")
        .withLongOpt("pem")
        .create("p");

    public static final Option PEM_KEY =
        OptionBuilder.withArgName( "path" )
        .hasArg()
        .withDescription("Path to the key for the PEM certificate")
        .withLongOpt("pk")
        .create("q");

    public static final Option AA_URL =
        OptionBuilder.withArgName( "URL" )
        .hasArg()
        .withDescription("URL of the AA to query")
        .withLongOpt("aaurl")
        .create("a");

    public static final Option IDP_PROVIDERID =
        OptionBuilder.withArgName( "URI" )
        .hasArg()
        .withDescription("The IdP providerId -- NameQualifier of the " +
            "SAML NameIdentifier in the SAML subject of the attribute " +
            "query.  This is used to qualify the subject of the attribute " +
            "query, presumably to ensure uniqueness.")
        .withLongOpt("idp_providerid")
        .create("i");

    public static final Option SP_PROVIDERID =
        OptionBuilder.withArgName( "URI" )
        .hasArg()
        .withDescription("The SP providerId -- The Resource attribute of " +
            "the AttributeQuery element has this value. Along with the SSL " +
            "credential used to establish the connection to the AA, this " +
            "identifies the entity making the attribute query.")
        .withLongOpt("sp_providerid")
        .create("s");

    protected BaseClient() {
        addOptions();
    }

    protected void addOptions() {
        options.addOption(HELP);
        options.addOption(LONG_HELP);
        options.addOption(DEBUG);

        options.addOption(TRUSTSTORE);
        options.addOption(PEM_TRUSTSTORE);
        options.addOption(NEW_TRUSTSTORE);
        options.addOption(METADATA);
        options.addOption(KEYSTORE);
        options.addOption(KEYSTORE_PWD);
        options.addOption(KEY_PWD);
        options.addOption(NEW_KEYSTORE);
        options.addOption(NEW_KEYSTORE_PWD);
        options.addOption(NEW_KEY_ALIAS);
        options.addOption(KEEP_NEW_KEYSTORE);
        options.addOption(KEEP_NEW_TRUSTSTORE);
        options.addOption(PEM);
        options.addOption(PEM_KEY);

        options.addOption(AA_URL);
        options.addOption(IDP_PROVIDERID);
        options.addOption(SP_PROVIDERID);
    }

    /**
     * For extending clients to add extra usage information.
     * @param customUsage
     */
    public void setCustomUsage(String customUsage) {
        this.customUsage = customUsage;
    }

    public void setHelpFooter(String msg) {
        this.helpFooter = msg;
    }

    public void setHelpHeader(String msg) {
        this.helpHeader = msg;
    }

    public void addOption(Option option)
    {
        this.options.addOption(option);
    }

    public void displayUsage() {
        StringBuffer buf = new StringBuffer("Invoke application: " +
                "java " + getClass().getName());

        buf.append("\n\nSet client cert:");

        buf.append("\n    Either PEM:      [-" + PEM.getOpt() + " <path> -"
                + PEM_KEY.getOpt() + " <path>]");

        buf.append("\n    Or JKS:          [-" + KEYSTORE.getOpt() + " <path> -" +
                KEYSTORE_PWD.getOpt() + " <pass> -" +
                KEY_PWD.getOpt() + " <pass>]");

        buf.append("\n\nSet trusted server cert(s):");

        buf.append("\n    Either PEM:      [-" + PEM_TRUSTSTORE.getOpt() +
                " <path>]");

        buf.append("\n    Or JKS:          [-" + TRUSTSTORE.getOpt() + " <path>]");

        buf.append("\n    Or metadata:     [-" + METADATA.getOpt() + " <path>]");

        buf.append("\n\nSet query subject:   ");

        String usage = buf.toString();
        usage = (this.customUsage == null) ? usage : usage + this.customUsage;

        String header = (this.helpHeader == null) ?
                        "\nOptions:" : this.helpHeader;
        HelpFormatter formatter = new HelpFormatter();

        // passing usage to printHelp makes it look bad
        System.out.println(usage + "\n");

        // cli package is bugged, cannot set this to whitespace
        formatter.setSyntaxPrefix("________");
        formatter.printHelp(" ", header, options, null, false);

        // some more custom output:
        System.out.println("\nNote: options " +
                KEEP_NEW_KEYSTORE.getOpt() + "," +
                KEEP_NEW_TRUSTSTORE.getOpt() + "," +
                NEW_KEYSTORE.getOpt() + "," +
                NEW_TRUSTSTORE.getOpt() + "," +
                NEW_KEYSTORE_PWD.getOpt() + "," +
                NEW_KEY_ALIAS.getOpt() +
                " are usually not needed\n");

        if (this.helpFooter != null) {
            System.out.println(this.helpFooter);
        }
    }

    protected abstract void displayLongUsage();

    /**
     * Allow the implementing class of BaseClient to support end of program
     * maintenance like removing ephemeral keystores.
     *
     * (This assumes all trust information is translated into keystores,
     *  needs to be revisited if that assumption changes)
     *
     */
    protected void cleanup() {
        if (this.debugMode) {
            System.err.println("\n\nCleanup:");
        }
        File file;
        if (this.removeJKS) {
            file = new File(this.jksPath);
            if (file.delete()) {
                if (this.debugMode) {
                    System.err.println("Removed tmp file: "
                            + file.getAbsolutePath());
                }
            } else {
                System.err.println("Cannot remove tmp file: "
                        + file.getAbsolutePath());
            }
        }
        if (this.removeJKStrustStore) {
            file = new File(this.jksTruststore);
            if (file.delete()) {
                if (this.debugMode) {
                    System.err.println("Removed tmp file: "
                            + file.getAbsolutePath());
                }
            } else {
                System.err.println("Cannot remove tmp file: "
                        + file.getAbsolutePath());
            }
        }

    }

    protected CommandLine parse(String [] args) throws Exception {
        return parse(args, null);
    }

    protected CommandLine parse(String [] args, Properties defaultOptions)
        throws Exception {

        CommandLineParser parser = new PosixParser();
        CommandLine line = parser.parse(this.options, args, defaultOptions);

        if (defaultOptions != null) {
            Iterator iter = defaultOptions.entrySet().iterator();
            while(iter.hasNext()) {
                Map.Entry entry = (Map.Entry)iter.next();
                Option opt = this.options.getOption((String)entry.getKey());
                if (opt != null) {
                    String desc = opt.getDescription();
                    desc += " (Default '" + entry.getValue() + "')";
                    opt.setDescription(desc);
                }
            }
        }

        if (args.length == 0) {
            System.out.println("For help message, use -" + HELP.getOpt());
            System.out.println("For a long help message, use --"
                    + LONG_HELP.getLongOpt());
            System.exit(0);
        }

        if (line.hasOption(HELP.getOpt())) {
            displayUsage();
            System.exit(0);
        }

        if (line.hasOption(LONG_HELP.getLongOpt())) {
            displayLongUsage();
            System.exit(0);
        }

        this.debugMode = line.hasOption("d");

        setIDs(line);

        setCerts(line);

        return line;
    }

    private void setIDs(CommandLine line) throws ParseException {
        if (line.hasOption(AA_URL.getOpt())) {
            this.aaurl = line.getOptionValue(AA_URL.getOpt());
            if (this.aaurl == null) {
                throw new ParseException("AAUrl (" +
                        AA_URL.getOpt() + ") " +
                        "setting is empty");
            }
        }

        if (line.hasOption(IDP_PROVIDERID.getOpt())) {
            this.idpProviderid = line.getOptionValue(IDP_PROVIDERID.getOpt());
            if (this.idpProviderid == null) {
                throw new ParseException("IdP providerId (" +
                        IDP_PROVIDERID.getOpt() + ") " +
                        "setting is empty");
            }
        }

        if (line.hasOption(SP_PROVIDERID.getOpt())) {
            this.spProviderid = line.getOptionValue(SP_PROVIDERID.getOpt());
            if (this.spProviderid == null) {
                throw new ParseException("SP providerId (" +
                        SP_PROVIDERID.getOpt() + ") " +
                        "setting is empty");
            }
        }

    }

    /**
     * Makes sure the client chooses either JKS or PEM, but not a combination,
     * and makes sure that each option has all the info it needs.
     *
     * If PEM is picked, a JKS is generated for OpenSAML.
     */
    private void setCerts(CommandLine line) throws Exception {

        // a little bad, since it expects each client impl of BaseClient
        // to register defaults for these three, even if that client impl
        // never uses ephemeral keystores... leave in for now
        if (!(line.hasOption(NEW_KEYSTORE.getOpt())
                && line.hasOption(NEW_KEYSTORE_PWD.getOpt())
                && line.hasOption(NEW_KEY_ALIAS.getOpt()))) {
            throw new ParseException("Not all configurations for ephemeral " +
                    "key store are present.");
        }

        String keystoreName = line.getOptionValue(NEW_KEYSTORE.getOpt());
        String keystorePass = line.getOptionValue(NEW_KEYSTORE_PWD.getOpt());
        String keystoreAlias = line.getOptionValue(NEW_KEY_ALIAS.getOpt());

        if ((keystoreName == null)
                || (keystorePass == null)
                || (keystoreAlias == null)) {
            throw new ParseException("Not all configurations for ephemeral " +
                    "key stores are present.");
        }

        if (line.hasOption(METADATA.getOpt())) {
            System.out.println("\n** Using metadata for server certificates " +
                    "to trust");
            String md = line.getOptionValue(METADATA.getOpt());
            if (md == null) {
                throw new ParseException("Metadata flag (" +
                        METADATA.getOpt() + ") " +
                        "supplied, but argument is empty");
            }
            if (this.debugMode) {
                System.err.println("Metadata path: " + md);
            }

            if (this.idpProviderid == null) {
                throw new Exception("No IdP providerId to lookup certificates" +
                        "in the metadata");
            }

            X509Certificate[] certs =
                    CertUtils.findAAcerts(md, this.idpProviderid);


            String newjks = line.getOptionValue(NEW_TRUSTSTORE.getOpt());
            if (newjks == null) {
                throw new ParseException("New truststore flag (" +
                        NEW_TRUSTSTORE.getOpt() + ") " +
                            "supplied, but argument is empty");
            }
            initEphemeralTrustJKS(newjks, keystorePass, certs);
            checkTruststoreRemove(line, newjks);

        } else if (line.hasOption(TRUSTSTORE.getOpt())) {
            System.out.println("\n** Using existing JKS for certificates " +
                    "to trust");
            this.jksTruststore = line.getOptionValue(TRUSTSTORE.getOpt());
            if (this.jksTruststore == null) {
                throw new ParseException("Truststore flag (" +
                        TRUSTSTORE.getOpt() + ") " +
                            "supplied, but argument is empty");
            }
            if (this.debugMode) {
                System.err.println("Truststore path: " + this.jksPath);
            }
            this.removeJKStrustStore = false;
        } else if (line.hasOption(PEM_TRUSTSTORE.getOpt())) {
            System.out.println("\n** Using PEM file as trusted certificate");
            String pem = line.getOptionValue(PEM_TRUSTSTORE.getOpt());
            if (pem == null) {
                throw new ParseException("PEM truststore flag (" +
                        PEM_TRUSTSTORE.getOpt() + ") " +
                            "supplied, but argument is empty");
            }

            if (this.debugMode) {
                System.err.println("Trusted PEM path: " + pem);
            }

            String newjks = line.getOptionValue(NEW_TRUSTSTORE.getOpt());
            if (newjks == null) {
                throw new ParseException("New truststore flag (" +
                        NEW_TRUSTSTORE.getOpt() + ") " +
                            "supplied, but argument is empty");
            }

            initEphemeralTrustJKS(newjks, keystorePass, keystoreAlias, pem);
            checkTruststoreRemove(line, newjks);
        }

        // not worth specifying exact conflict
        String conflict = "This program only makes queries over " +
                "a trusted channel (SSL).  To make a query, you must choose " +
                "either '-" + KEYSTORE.getOpt() +
                "' or '-" + PEM.getOpt() +
                "'.  Choosing '-" + KEYSTORE.getOpt() +
                "' requires '-" + KEYSTORE_PWD.getOpt() +
                "' and '-" + KEY_PWD.getOpt() +
                "'.  Choosing '-" + PEM.getOpt() +
                "' requires '-" + PEM_KEY.getOpt() +
                "'.  Use '-" + HELP.getOpt() +
                "' to see the help message or '--"
                + LONG_HELP.getLongOpt() + "' for a longer explanation.";

        if (line.hasOption(KEYSTORE.getOpt())
                && line.hasOption(PEM.getOpt())) {

            throw new ParseException(conflict);
        }

        // JKS
        if (line.hasOption(KEYSTORE.getOpt())
                && line.hasOption(KEYSTORE_PWD.getOpt())
                && line.hasOption(KEY_PWD.getOpt())) {

            System.out.println("\n** Using existing JKS for certificate " +
                    "to present to server for SSL connection");

            this.jksPath = line.getOptionValue(KEYSTORE.getOpt());
            if (this.jksPath == null) {
                throw new ParseException("JKS path flag (" +
                        KEYSTORE.getOpt() + ") " +
                            "supplied, but argument is empty");
            }

            this.jksPw = line.getOptionValue(KEYSTORE_PWD.getOpt());
            if (this.jksPw == null) {
                throw new ParseException("JKS password flag (" +
                        KEYSTORE_PWD.getOpt() + ") " +
                            "supplied, but argument is empty");
            }

            this.jksKeyPw = line.getOptionValue(KEY_PWD.getOpt());
            if (this.jksKeyPw == null) {
                throw new ParseException("JKS key password flag (" +
                        KEY_PWD.getOpt() + ") " +
                            "supplied, but argument is empty");
            }

            this.pemKey = null;
            this.pemPath = null;
            this.removeJKS = false;

            if (this.debugMode) {
                System.err.println("JKS path: " + this.jksPath);
                System.err.println("JKS pass: " + this.jksPw);
                System.err.println("JKS keypass: " + this.jksKeyPw);
                System.err.println("PEM paths set to null.");
                System.err.println("Remove-JKS flag set to false");
            }

            return;
        }

        // PEM
        if (line.hasOption(PEM.getOpt()) && line.hasOption(PEM_KEY.getOpt())) {

            System.out.println("\n** Using existing PEM certificate " +
                    "to present to server for SSL connection");
            this.pemPath = line.getOptionValue(PEM.getOpt());
            if (this.pemPath == null) {
                throw new ParseException("PEM certificate path flag (" +
                        PEM.getOpt() + ") " +
                            "supplied, but argument is empty");
            }

            this.pemKey = line.getOptionValue(PEM_KEY.getOpt());
            if (this.pemKey == null) {
                throw new ParseException("PEM key path flag (" +
                        PEM_KEY.getOpt() + ") " +
                            "supplied, but argument is empty");
            }

            if (this.debugMode) {
                System.err.println("PEM path: " + this.pemPath);
                System.err.println("PEM key : " + this.pemKey);
            }

            initEphemeralClientJKS(keystoreName, keystorePass, keystorePass,
                             this.pemPath, this.pemKey);

            checkKeystoreRemove(line, keystoreName);

        } else {
            throw new ParseException(conflict);
        }

    }

    private void initEphemeralTrustJKS(String certstoreName,
                                       String certstorePass,
                                       String certstoreAlias,
                                       String pem) throws Exception {
        if (this.debugMode) {
            System.err.println("Ephemeral certstore: " + certstoreName);
            System.err.println("Ephemeral certstore pass: " + certstorePass);
            System.err.println("Ephemeral certstore alias: " +
                                                           certstoreAlias);
        }

        CertUtils.createCertStore(
                pem,
                certstoreAlias,
                certstoreName,
                certstorePass,
                this.debugMode);

        this.jksTruststore = certstoreName;
    }

    private void initEphemeralTrustJKS(String certstoreName,
                                       String certstorePass,
                                       X509Certificate[] certs) throws Exception {
        if (this.debugMode) {
            System.err.println("Ephemeral certstore: " + certstoreName);
            System.err.println("Ephemeral certstore pass: " + certstorePass);
        }

        // give each one an alias
        String[] aliases = new String[certs.length];
        for (int i = 0; i < certs.length; i++) {
            aliases[i] = "cert-" + i;
        }

        CertUtils.createCertStore(
                certs,
                aliases,
                certstoreName,
                certstorePass,
                this.debugMode);

        this.jksTruststore = certstoreName;
    }

    /**
     *
     * @param keystoreName
     * @param keystorePass
     * @param keystoreAlias
     * @param pemPath
     * @param pemKey
     */
    private void initEphemeralClientJKS(String keystoreName,
                                  String keystorePass,
                                  String keystoreAlias,
                                  String pemPath,
                                  String pemKey) throws Exception {

        if (this.debugMode) {
            System.err.println("Ephemeral keystore: " + keystoreName);
            System.err.println("Ephemeral keystore pass: " + keystorePass);
            System.err.println("Ephemeral keystore alias: " +
                                                           keystoreAlias);
        }

        CertUtils.createKeyStore(
                pemPath,
                pemKey,
                keystoreAlias,
                keystorePass,
                keystoreName,
                this.debugMode);

        this.jksPath = keystoreName;
        this.jksPw = keystorePass;
        this.jksKeyPw = keystorePass;
    }

    private void checkKeystoreRemove(CommandLine line,
                             String keystoreName) {

        if (line.hasOption(KEEP_NEW_KEYSTORE.getOpt())) {
            this.removeJKS = false;
        } else {
            this.removeJKS = true;
        }

        if (this.debugMode) {
            File file = new File(keystoreName);
            if (this.removeJKS) {
                System.err.println("This program will remove ephemeral " +
                        "JKS file: " + file.getAbsolutePath() + "\n");
            } else {
                System.err.println("This program will not remove " +
                        "ephemeral JKS file: " + file.getAbsolutePath() + "\n");
            }
        }
    }

    private void checkTruststoreRemove(CommandLine line,
                             String keystoreName) {

        if (line.hasOption(KEEP_NEW_TRUSTSTORE.getOpt())) {
            this.removeJKStrustStore = false;
        } else {
            this.removeJKStrustStore = true;
        }

        if (this.debugMode) {
            File file = new File(keystoreName);
            if (this.removeJKStrustStore) {
                System.err.println("This program will remove ephemeral " +
                        "JKS file: " + file.getAbsolutePath() + "\n");
            } else {
                System.err.println("This program will not remove " +
                        "ephemeral JKS file: " + file.getAbsolutePath() + "\n");
            }
        }
    }

}
