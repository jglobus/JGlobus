package org.globus.ftp.test;

import org.globus.ftp.GridFTPClient;
import org.globus.ftp.Session;
import org.globus.gsi.gssapi.auth.IdentityAuthorization;
import org.globus.util.ConfigUtil;
import org.gridforum.jgss.ExtendedGSSCredential;
import org.gridforum.jgss.ExtendedGSSManager;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class SimpleTarTransfer {

    public static void main(String[] args) throws Exception {
        String tarAlias = "tar";
        String host = "localhost";//args[0];
        int port = 60000;//new Integer(args[1]).intValue();
        String sourceParentDir = "/tmp";// args[2];
        String sourceDir = "tartest";//args[3];
        String destFile = "/tmp/target.tar";

        GSSCredential cred = getDefaultCredential();
        String tarCommand = createDownloadTarSiteCommand(sourceParentDir, sourceDir, tarAlias);
        GridFTPClient client = createClient(host, port, cred, tarCommand);
        downloadTarToFile(client, sourceDir, destFile);
    }

    static GridFTPClient createClient(String host, int port, GSSCredential cred, String tarCommand) throws Exception {
        GridFTPClient client = null;
        client = new GridFTPClient(host, port);
        client.setAuthorization(new IdentityAuthorization("/O=Grid/OU=GlobusTest/OU=simpleCA-ubuntu/CN=Vijay Anand"));
        client.authenticate(cred);
        client.setType(Session.TYPE_IMAGE);
        try {
            client.site(tarCommand);
        } catch (Exception e) {
            throw new Exception("popen driver not supported", e);
        }
        client.setPassive();
        client.setLocalActive();
        return client;
    }

    static String createDownloadTarSiteCommand(String sourceParentDir, String sourceDir, String tarAlias) {
        StringBuffer sb = new StringBuffer();
        sb.append("SETDISKSTACK popen:argv=#");
        sb.append(tarAlias);
        sb.append("#cf#-#-C#");
        sb.append(sourceParentDir);
        sb.append("#");
        sb.append(sourceDir);
        return sb.toString();
    }

    static void downloadTarToFile(GridFTPClient client, String sourceDir, String destFile) throws Exception {
        try {
            client.get(sourceDir, new File(destFile));
        } finally {
            if (client != null) {
                client.close(true);
            }
        }
    }

    static GSSCredential getDefaultCredential() throws IOException, GSSException {
        File proxyFile = new File(ConfigUtil.discoverProxyLocation());
        byte[] proxyBytes = new byte[(int) proxyFile.length()];
        FileInputStream in = new FileInputStream(proxyFile);
        try {
            in.read(proxyBytes);
        } finally {
            in.close();
        }
        ExtendedGSSManager manager = (ExtendedGSSManager) ExtendedGSSManager.getInstance();
        return manager.createCredential(proxyBytes, ExtendedGSSCredential.IMPEXP_OPAQUE,
            GSSCredential.DEFAULT_LIFETIME, null, GSSCredential.INITIATE_AND_ACCEPT);
    }

}
