import org.globus.gsi.jsse.SSLConfigurator
import org.globus.gsi.provider.GlobusProvider
import org.globus.gsi.stores.ResourceSigningPolicyStoreParameters
import org.globus.gsi.stores.ResourceSigningPolicyStore
import org.apache.http.conn.ssl.SSLSocketFactory
import org.apache.http.impl.client.DefaultHttpClient
import org.apache.http.conn.scheme.Scheme
import org.apache.http.client.methods.HttpGet

trait Client {
  val valid = "classpath:/mykeystore.properties"
  val invalid = "classpath:/invalidkeystore.properties"
  
  def validCert = client(5082, valid)
  def invalidCert = client(5082, invalid)
  
  def client(port:int, keystore:String) = {
    val config = getConfig(keystore)
    val fac = new SSLSocketFactory(config.getSSLContext())
    fac.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
    val httpclient = new DefaultHttpClient();
    val scheme = new Scheme("https", fac, port);
    httpclient.getConnectionManager().getSchemeRegistry().register(scheme);
    val httpget = new HttpGet("https://localhost/");
    httpclient.execute(httpget);	
  }
	
  def getConfig(credStoreLocation:String) = {
    val config = new SSLConfigurator();
		config.setCrlLocationPattern(null);
		config.setCrlStoreType(GlobusProvider.CERTSTORE_TYPE);

		config.setCredentialStoreLocation(credStoreLocation);
		config.setCredentialStorePassword("password");
		config.setCredentialStoreType(GlobusProvider.KEYSTORE_TYPE);

		config.setTrustAnchorStoreLocation("classpath:/mytruststore.properties");
		config.setTrustAnchorStorePassword("password");
		config.setTrustAnchorStoreType(GlobusProvider.KEYSTORE_TYPE);
  
		val policyParams = new ResourceSigningPolicyStoreParameters(
				"classpath:/globus_ca.signing_policy");
		val policyStore = new ResourceSigningPolicyStore(policyParams);
  
		config.setPolicyStore(policyStore);
		config
  }
    
}
