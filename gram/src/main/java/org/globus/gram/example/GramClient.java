package org.globus.gram.example;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
//import org.globus.ftp.examples.LocalCredentialHelper;
import org.globus.gram.GramJob;
import org.globus.gram.GramJobListener;
import org.globus.gsi.gssapi.auth.IdentityAuthorization;
import org.globus.util.ConfigUtil;
import org.gridforum.jgss.ExtendedGSSCredential;
import org.gridforum.jgss.ExtendedGSSManager;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;

public class GramClient {

	public static void main(String argv[]) {

		String port = "ubuntu:50000:";
		String DN ="/O=Grid/OU=GlobusTest/OU=simpleCA-ubuntu/CN=Vijay Anand";
		try {
            GramJob j = new GramJob("&(executable=/bin/ls)");
            j.request(port  + DN );
            j.addListener(new GramJobListener() {
                public void statusChanged(GramJob job) {
                    System.out.println(job.getStatusAsString());
                }
            });
            //j.request(port  + DN +"/jobmanager-fork");
            System.out.println("Submitted");
            Thread.sleep(10000);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class LocalCredentialHelper {

    private Log log = LogFactory.getLog(LocalCredentialHelper.class);

    public GSSCredential getDefaultCredential() throws IOException, GSSException {

        System.out.println("Proxy Location "+ ConfigUtil.discoverProxyLocation());
    	return this.getCredential(new File(ConfigUtil.discoverProxyLocation()));
    }

    public GSSCredential getCredential(File proxyFile) throws IOException, GSSException {

        byte[] proxyBytes = new byte[(int) proxyFile.length()];
        FileInputStream in = new FileInputStream(proxyFile);
        in.read(proxyBytes);
        in.close();
        ExtendedGSSManager manager = (ExtendedGSSManager) ExtendedGSSManager.getInstance();
        return manager.createCredential(proxyBytes, ExtendedGSSCredential.IMPEXP_OPAQUE,
                GSSCredential.DEFAULT_LIFETIME, null, GSSCredential.INITIATE_AND_ACCEPT);
    }
}
