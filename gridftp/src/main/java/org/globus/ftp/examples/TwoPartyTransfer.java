package org.globus.ftp.examples;

import java.io.File;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
//import org.birncommunity.sample.proxy.LocalCredentialHelper;
import org.globus.ftp.GridFTPClient;
import org.globus.ftp.Session;
import org.globus.gsi.gssapi.auth.IdentityAuthorization;

public class TwoPartyTransfer {

    private static Log log = LogFactory.getLog(TwoPartyTransfer.class);
    private String host;
    private int port;
    private String source;
    private String dest;
    private String direction;

    public static void main(String[] args) throws Exception {
/*
        if (args.length != 5 || args[0].equals("-h") || args[0].equals("--help")) {
            log.error("Usage: java " + TwoPartyTransfer.class.getName() +
                " <host> <port> <direction> <sourceFile> <base destFile>");
            log.error("host: GridFTP server hostname");
            log.error("port: GridFTP server port");
            log.error("direction: \"download\" || \"upload\"");
            log.error("sourceFile: source file");
            log.error("destFile: destination file");
            log.error("");
            log.error("A user proxy certificate needs to be in place in /tmp");
            log.error("");
            log.error("Example: java " + TwoPartyTransfer.class.getName() +
                " chi-vm-4.isi.edu 2811 download /tmp/testfile /tmp/testfile");
            log.error("This will transfer chi-vm-4.isi.edu/tmp/testfile into /tmp/testfile");
            System.exit(1);
        }
*/
        String host = "localhost";//args[0];
        int port = 50500;//new Integer(args[1]).intValue();
        String direction = "download";//args[2];
        String source = "~/test/test1";///test/args[3];
        String dest = "/tmp/testx";//args[4];

        new TwoPartyTransfer(host, port, source, dest, direction).doTransfer();
    }

    public TwoPartyTransfer(String host, int port, String source, String dest, String direction) {

        if (!direction.equals("download") && !direction.equals("upload")) {
            throw new IllegalArgumentException("Invalid direction: \"download\" || \"upload\"");
        }
        this.host = host;
        this.port = port;
        this.source = source;
        this.dest = dest;
        this.direction = direction;
    }

    public void doTransfer() throws Exception {

        GridFTPClient client = null;
        try {
            client = new GridFTPClient(host, port);

            // Change the authorization from the output of identity from grid-proxy-init
            client.setAuthorization(new IdentityAuthorization("/O=Grid/OU=GlobusTest/OU=simpleCA-ubuntu/CN=Vijay Anand"));

            client.authenticate(new LocalCredentialHelper().getDefaultCredential());
            client.setType(Session.TYPE_IMAGE);
            client.setPassive();
            client.setLocalActive();
            if (direction.equals("download")) {
                client.get(source, new File(dest));
            } else {
                client.put(new File(source), dest, false);
            }
        } finally {
            try {
                if (client != null) {
                    client.close(true);
                }
            } catch (Exception e) {
                log.error("Can't close connection.",e);
            }
        }
    }
}
