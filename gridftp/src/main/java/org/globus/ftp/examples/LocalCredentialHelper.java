package org.globus.ftp.examples;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.globus.util.ConfigUtil;
import org.gridforum.jgss.ExtendedGSSCredential;
import org.gridforum.jgss.ExtendedGSSManager;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class LocalCredentialHelper {

    private Log log = LogFactory.getLog(LocalCredentialHelper.class);

    public GSSCredential getDefaultCredential() throws IOException, GSSException {

        System.out.println("Proxy Location "+ ConfigUtil.discoverProxyLocation());
    	return this.getCredential(new File(ConfigUtil.discoverProxyLocation()));
    }

    public GSSCredential getCredential(File proxyFile) throws IOException, GSSException {

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
