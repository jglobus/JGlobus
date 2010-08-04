import collection.mutable.Map
import java.util.{ArrayList, Arrays, List => JList, Map => JMap, HashMap => JHashMap}
import org.junit.Assert.{assertEquals, fail}
import cuke4duke.scala.{Dsl, EN}
import cuke4duke.Table
import org.apache.catalina.Context;
import org.apache.catalina.Engine;
import org.apache.catalina.Host;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.startup.Embedded;
import org.apache.catalina.valves.ValveBase;
import org.apache.coyote.InputBuffer;
import org.apache.coyote.http11.InternalInputBuffer;
import org.globus.gsi.tomcat.GlobusSSLImplementation;
import org.globus.gsi.tomcat.GlobusSSLInputStream;
import org.globus.gsi.tomcat.GlobusSSLSocketFactory;
import org.globus.gsi.testutils.FileSetupUtil;
import org.globus.gsi.provider.GlobusProvider;
import org.globus.gsi.jss.GlobusTLSContext;
import org.globus.gsi.tomcat._

class Tomcat extends Dsl with EN with Client{
  
  val embedded = new Embedded()
  val validKey = new FileSetupUtil("mykeystore.properties")
  val validCert = new FileSetupUtil("mytruststore.properties")
	    
  Given("Tomcat is configured with ssl proxy support enabled"){
	  val engine = embedded.createEngine();
	  engine.setName("Catalina");
	  engine.setDefaultHost("localhost")
	  val host = embedded.createHost("localhost", ".");
	  engine.addChild(host);
	  val context = embedded.createContext("", "");
	  host.addChild(context);
	  embedded.addEngine(engine);
	  val connector = embedded.createConnector("localhost", 5082, false);
	  connector.setScheme("https");
	  connector.setAttribute("sslImplementation", classOf[GlobusSSLImplementation]);
	  connector.setAttribute("socketFactory", classOf[GlobusSSLSocketFactory].getCanonicalName());
	  validKey.copyFileToTemp();
	  connector.setAttribute("keystoreFile", validKey.getTempFile().getAbsolutePath());
	  connector.setAttribute("keystoreType", GlobusProvider.KEYSTORE_TYPE);
	  connector.setAttribute("keystorePassword", "password");
	  validCert.copyFileToTemp();
	  connector.setAttribute("truststoreFile", validCert.getTempFile().getAbsolutePath());
	  connector.setAttribute("truststoreType", GlobusProvider.KEYSTORE_TYPE);
	  connector.setAttribute("truststorePassword", "password");
	  connector.setAttribute("signingPolicyLocation", "classpath:/globus_ca.signing_policy");
	  connector.setAttribute("crlLocation", "");
	  connector.setAttribute("clientAuth", "true");
	  embedded.addConnector(connector);
  }
  
  Given("Tomcat is running with a valid certificate"){
	  embedded.start()
  }
  
  When("A client presents a valid certificate"){
	  validCert
  } 
  
  Then("The client can successfully connect to the server"){
    
  }
  
  Then("The server shuts down"){
    embedded.stop();
	validKey.deleteFile();
	validCert.deleteFile();
  }
  
}
