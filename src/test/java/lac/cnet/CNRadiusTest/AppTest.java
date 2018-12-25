package lac.cnet.CNRadiusTest;

import java.util.UUID;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import lac.cnet.radius.CheckAuthentication;

/**
 * Unit test for simple App.
 */
public class AppTest 
    extends TestCase
{
	// For checking periodically Radius Authorization.
	String server = "192.168.56.101";
	String user = "user";
	String pass = "upass";
	String nasId = "gw-1";
	String gatewayIP = "localhost";
	int gatewayPort = 5510;
	String secret = "secretpass";

    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public AppTest( String testName )
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( AppTest.class );
    }

    /**
     * Rigourous Test :-)
     */
    public void testApp()
    {
		  CheckAuthentication auth = new CheckAuthentication(server, user, pass, nasId);
		  
		  testAuth(auth, true);
		  testCheck(auth, nasId, true);
		  testCheck(auth, "other", false);
		 
		  
		  auth.setNasId("mn-1");
		  testAuth(auth, true);
		  testCheck(auth, "mn-1", true);
		  testCheck(auth, "other", false);

		  auth.setSecret("wrongPass");
		  testAuth(auth, false);
		   
		  auth.setSecret(this.secret);
		  auth.setUser("noUser");
		  testAuth(auth, false);
		  
		  auth.setUser(this.user);
		  auth.setPassword("wrongPass");
		  testAuth(auth, false);
		  
		  auth.setPassword(this.pass);
		  testAuth(auth, true);
		  
    	assertTrue( true );
    }
    
    
    public void  testAuth(CheckAuthentication auth, boolean isAuth) {
		 if (!auth.Authorize()) {
			  if(isAuth) {
			  	assertTrue(false);
			  }
			  else {
				  assertTrue(true);
			  }			  
		 } else {
			 if(nasId.toLowerCase().contains("mn")) {
				 String[] list = auth.getPOAList();
					  
				 if(list == null) assertTrue(false);
					  	  		  
				 for(int i = 0; i < list.length; i = i + 2) {
					 System.out.println("POA[" + i + "]" + list[i] + ":" + list[i+1]);
				 }
				  
				gatewayIP = list[0];
				gatewayPort = Integer.parseInt(list[1]);
			 } 
		 }
    }
    
    public void testCheck(CheckAuthentication auth, String nas, boolean isTrue) {
		  UUID id = UUID.randomUUID();

	      if (auth.CheckTokenStatus(id,  user,  nas, 0, "")) {
	    	  if (isTrue)
	    		  assertTrue(true);
	    	  else
	    		  assertTrue(false);
	      } else {
	    	  if (!isTrue)
	    		  assertTrue(true);
	    	  else
	    		  assertTrue(false);
	      }  	
    }
    
    
}
