/*
 * Copyright 1999-2007 University of Chicago
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

package org.globus.gridshib.tool.x509;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.common.cli.ApplicationRuntimeException;
import org.globus.gridshib.saml.SAMLToolsCLI;
import org.globus.gridshib.security.util.GSIUtil;
import org.globus.gridshib.security.x509.NonCriticalX509Extension;
import org.globus.gridshib.security.x509.X509Extension;

import org.globus.gsi.X509Credential;
import org.globus.gsi.CredentialException;

/**
 * This is the X.509 Binding Tool.  It binds arbitrary
 * content to an arbitrary non-critical certificate
 * extension of an X.509 proxy certificate.
 * In particular, the Binding Tool will bind a SAML
 * assertion to a proxy certificate.
 *
 * @since 0.3.0
 */
public class X509BindingTool extends X509ToolCLI
                          implements SAMLToolsCLI {

    private static Log logger =
        LogFactory.getLog(X509BindingTool.class.getName());

    private static X509BindingTool cli;

    /**
     * @since 0.5.0
     */
    public X509BindingTool(String[] args) {

        super(args);
    }

    public static void main(String[] args) {

        X509BindingTool cli = new X509BindingTool(args);

        try {
            cli.run();
        } catch (ApplicationRuntimeException e) {
            String msg = " (exit code " + cli.getExitCode() + ")";
            logger.error(e.getMessage() + msg, e);
            if (!cli.wantQuiet()) { System.err.println(e.getMessage()); }
        }

        System.exit(cli.getExitCode());
    }

    /**
     * @since 0.5.0
     */
    public void run() throws ApplicationRuntimeException {

        logger.info("Begin execution of X509BindingTool");

        // get (required) input to bind:
        BufferedInputStream in = null;
        if (this.getInputPath() == null) {
            logger.debug("Processing infile as stdin");
            in = new BufferedInputStream(System.in);
        } else {
            logger.debug("Processing infile " + this.getInputPath());
            File infile = new File(this.getInputPath());
            try {
                in = new BufferedInputStream(new FileInputStream(infile));
            } catch (FileNotFoundException e) {
                this.setExitCode(APPLICATION_ERROR);
                String msg = "Unable to locate input file";
                throw new ApplicationRuntimeException(msg, e);
            } catch (SecurityException e) {
                this.setExitCode(APPLICATION_ERROR);
                String msg = "Unable to read from file";
                throw new ApplicationRuntimeException(msg, e);
            }
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            int c;
            while ((c = in.read()) != -1) {
                out.write(c);
            }
        } catch (IOException e) {
            this.setExitCode(APPLICATION_ERROR);
            String msg = "Unable to read bytes from input stream";
            throw new ApplicationRuntimeException(msg, e);
        } finally {
            if (in != null) {
                try { in.close(); } catch (IOException e) { }
            }
        }
        byte[] bytes = out.toByteArray();

        // if input is SAML, properly encode it:
        if (this.indicatesSAML()) {
            logger.debug("Processing SAML assertion");
            try {
                String s = new String(bytes);
                bytes = X509Extension.encodeDERUTF8String(s);
                logger.debug("Unencoded SAML assertion: " + s);
            } catch (IOException e) {
                this.setExitCode(APPLICATION_ERROR);
                String msg = "Unable to encode bytes";
                throw new ApplicationRuntimeException(msg, e);
            }
        } else {
            logger.debug("Processing DER-encoded ASN.1 structure");
        }

        // get the OID:
        String oid = this.getOID();
        if (oid == null) {
            this.setExitCode(APPLICATION_ERROR);
            String msg = "OID is null";
            throw new ApplicationRuntimeException(msg);
        }

        X509Credential cred = null;
        if (this.getIssuingCredential() != null) {
            // use credential on the command line:
            cred = this.getIssuingCredential();
        } else {
            // use configured credential:
            cred = this.getConfig().getCredential();
        }
        logger.debug("Issuing credential: " + cred.toString());

        NonCriticalX509Extension ext =
            new NonCriticalX509Extension(oid, bytes);

        // bind extension to X.509 proxy certificate:
        X509Credential proxy = null;
        try {
            int lifetime = this.getX509Lifetime();
            if (lifetime == 0) {
                proxy = GSIUtil.createCredential(cred, ext);
            } else {
                proxy = GSIUtil.createCredential(cred, ext, lifetime);
            }
        } catch (CredentialException e) {
            this.setExitCode(APPLICATION_ERROR);
            String msg = "Unable to bind extension to proxy cert";
            throw new ApplicationRuntimeException(msg, e);
        }

        // output X.509 proxy credential::
        try {
            if (this.getOutputPath() == null) {
                //proxy.save(System.out);
                GSIUtil.printCredential(proxy);
            } else {
                GSIUtil.writeCredentialToFile(proxy, this.getOutputPath());
            }
        } catch (Exception e) {
            this.setExitCode(APPLICATION_ERROR);
            String msg = "Unable to output proxy credential";
            throw new ApplicationRuntimeException(msg, e);
        }

        this.setExitCode(SUCCESS_CODE);

        logger.info("End execution of X509BindingTool");
    }
}
