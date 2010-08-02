package org.globus.gsi.provider.simple;

import org.globus.gsi.provider.simple.SimpleMemorySigningPolicyStore;

import org.springframework.core.io.ClassPathResource;
import java.io.InputStreamReader;
import org.globus.gsi.SigningPolicy;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import org.globus.gsi.SigningPolicyParser;
import org.junit.Test;
import static org.junit.Assert.*;

public class SimpleMemorySigningPolicyStoreTest {

    @Test
    public void  testGetSigningPolicy() throws Exception {
        SigningPolicyParser parser = new SigningPolicyParser();
        Map<X500Principal, SigningPolicy> policies;
        policies = parser.parse(new InputStreamReader(new ClassPathResource("org/globus/gsi/test/49f18420.signing_policy").getInputStream()));
        assertNotNull(policies);
        assertFalse(policies.isEmpty());
        SimpleMemorySigningPolicyStore store =  new SimpleMemorySigningPolicyStore(policies.values().toArray(new SigningPolicy[1]));
        for (X500Principal p : policies.keySet()) {
            assertNotNull(store.getSigningPolicy(p));
        }
    }

}
