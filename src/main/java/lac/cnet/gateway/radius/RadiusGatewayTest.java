package lac.cnet.gateway.radius;

import java.io.IOException;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import lac.cnet.gateway.components.Gateway;
import lac.cnet.radius.CheckAuthentication;
import lac.cnet.sddl.udi.core.UniversalDDSLayerFactory;
import lac.cnet.sddl.udi.core.UniversalDDSLayerFactory.SupportedDDSVendors;

public class RadiusGatewayTest {

	// For checking periodically Radius Authorization.
	String server = "192.168.56.101";
	String user = "";
	String pass = "";
	

	/**
	* Starts the program
	* 
	* @param args
	*/
	public static void main(String[] args) {					
	    Logger.getLogger("").setLevel(Level.OFF);
	    
	    if (args.length != 6) {
	      System.out.println("Call syntax: $GatewayTest <gateway-public-ip> <gateway-RUDP-port> <dds-vendor> <RadiusServer-ip> "
	      		+ "<user> <password>" );
	      System.exit(-1);
	    }
	    
	    new RadiusGatewayTest(args);	    
	  }

	  public RadiusGatewayTest(String[] args) {	  		  
		  this.server = args[3];
		  this.user = args[4];
		  this.pass = args[5];
		  String nasID = "gateway-1";
		  
		  CheckAuthentication auth = new CheckAuthentication(this.server, this.user, this.pass, nasID);
		  
		  if (!auth.Authorize()) {
		  	System.exit(-1);
		  }

		  System.out.println("Working Directory = " + System.getProperty("user.dir") + " - " + args.length);
		    		    		   
		  UUID id = UUID.randomUUID();
		    
		  String strDDSVendor = args[2];
		  SupportedDDSVendors ddsVendor = UniversalDDSLayerFactory.convertStrToSupportedDDSVendor(strDDSVendor);
		    
		  try {
		      new Gateway(Integer.parseInt(args[1]), args[0], id, false,ddsVendor);
		      System.out.println("Gateway started...");
		      System.out.println("Gateway MR-UDP IP: " + args[0] + ":" + args[1] + "\n");
		      
		      if (auth.CheckTokenStatus(id,  this.user,  nasID, 0, "")) {
		    	  System.out.println("> CheckToken OK\n");
		      } else {
		    	  System.out.println("> CheckToken failed\n");
		      }
		      
		      if (auth.CheckTokenStatus(id, this.user, "gateway-2", 0, "")) {
		    	  System.out.println(">> CheckToken OK\n");
		      } else {
		    	  System.out.println(">> CheckToken failed\n");
		      }		      
		  }
		  catch (IOException e) {
		      e.printStackTrace();
		  }
	  }		  	  	  
}



