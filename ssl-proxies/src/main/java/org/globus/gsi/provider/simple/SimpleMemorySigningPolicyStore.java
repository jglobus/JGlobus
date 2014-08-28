package org.globus.gsi.provider.simple;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x509.X509Name;
import org.globus.gsi.SigningPolicy;
import org.globus.gsi.bc.X509NameHelper;
import org.globus.gsi.provider.SigningPolicyStore;
import org.globus.gsi.provider.SigningPolicyStoreException;


/**
 * @deprecated
 */
public class SimpleMemorySigningPolicyStore implements SigningPolicyStore {
    private static Log logger = LogFactory.getLog(SimpleMemorySigningPolicyStore.class);


    private Map<String, SigningPolicy> store;

    public SimpleMemorySigningPolicyStore(SigningPolicy[] policies) {
        store = new ConcurrentHashMap<String,SigningPolicy>();
        int numPolicies = 0;
        if (policies != null) {
        	numPolicies = policies.length;
            for (SigningPolicy policy : policies) {
                if (policy != null) {
                	X509Name name = new X509Name(false, policy.getCASubjectDN().getName(X500Principal.RFC2253));
                    store.put(X509NameHelper.toString(name), policy);
                    logger.debug("Adding to policy store: " + X509NameHelper.toString(name));
                }
            }
        }
        logger.debug("Loaded " +  store.size() + " policies of " + numPolicies);
    }

    public SigningPolicy getSigningPolicy(X500Principal caPrincipal) throws SigningPolicyStoreException {
    	SigningPolicy policy = store.get(caPrincipal.getName(X500Principal.RFC2253));
    	if (policy == null) {
    		X509Name name = new X509Name(false, caPrincipal.getName(X500Principal.RFC2253));
    		logger.debug("Getting from policy store: " + X509NameHelper.toString(name));
            policy = store.get(X509NameHelper.toString(name));
    	}
    	return policy;
    }

}
