package lac.cnet.radius;

import java.io.IOException;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;
import java.util.UUID;

import org.tinyradius.packet.AccessRequest;
import org.tinyradius.packet.AccountingRequest;
import org.tinyradius.packet.RadiusPacket;
import org.tinyradius.util.RadiusClient;
import org.tinyradius.util.RadiusException;

public class CheckAuthentication {
	
	private long timeBeforeExpirationForRenew = 30000; 				// Time in milliseconds to renew authorization.
	
	private boolean isRenew = true;									// Flag for behavior on expiration time. Renew or not authorization.
		
	// For checking periodically Radius Authorization.
	Timer timer;
	long delay;
	String[] messageTokens;
	String token = "";
	String server = "192.168.56.101";
	String user = "mobilenode";
	String pass = "123";
	String nasId;	
	Date expirationTime;
	
	private String secret = "!cOnTeXtNeT357?lAc&PuCrIo";
			
	/**
	 * Internal Timer class to control expiration time.
	 * run() is called on expiration time if isRenew is false or 
	 * ExpirationTime - timeBeforeExparationForRenew for calling Authorize() again.
	 * 
	 * @author iyda
	 */
	class task extends TimerTask {
		public task() {
		}
		 
		@Override
		public void run() {
			if(isRenew) {
				System.out.println("	Authorizing again ....");
				if (! Authorize()) {
					System.exit(-1);
				}
			}
		}
	}

	/** 
	 * Constructor for authorization class. Sets up basic parameters of the connection. 
	 * 
	 * @param serv	Authorization server IP address. It uses default port 1812 for access and 1813 for accounting pakets.
	 * @param user  
	 * @param pass
	 * @param id
	 */
	public CheckAuthentication(String serv, String user, String pass, String id) {
		this.timer = new Timer();		// For checking expiration.
		this.server = serv;
		this.user = user;
		this.pass = pass;
		this.nasId = id;
	}	
		
	/**
	 *  Authorization method that uses parameters passed in the constructor call.
	 *  It sends an Access-Request packet with NAS-Identifier attribute that should inform the type of the client:
	 *  gateway, procnode, mobilenode
	 *  followed by "-" and an integer identifying the specific node.
	 *  
	 *  If the type of return packet is ACCESS_ACCEPT it must have the Reply-Message attribute with the fields
	 *  Expiration and Token.
	 *  
	 *  Expiration is the expiration time in milliseconds (since Jan, 1st 1970).
	 *  Token is a unique string created by the AuthServer.
	 * 
	 *  Then, Expiration and Token can be checked any time against AuthServer records to see authenticity of messages/nodes. 
	 * 
	 *  The method starts a Timer that 30s before the expiration time will renew Authorization.
	 *  
	 * @return true if Authorized, false otherwise.
	 */
	public boolean Authorize() {		
		RadiusClient rc = new RadiusClient(server, secret);
		AccessRequest ar = new AccessRequest(user, pass);
		ar.setAuthProtocol(AccessRequest.AUTH_CHAP);
		ar.addAttribute("NAS-Identifier", this.nasId);
		System.out.println(ar);
		try {
			RadiusPacket response = rc.authenticate(ar);
			if(response.getPacketType() != RadiusPacket.ACCESS_ACCEPT) {
				System.out.println("Authentication failed ! Connection not accepted.");
				return false;
			} else {
				String message = response.getAttributeValue("Reply-Message");
				
				if(message == null) {
					System.out.println("Received accept without required attributes. Probably, Auth Server, not configured properly");
					return false;
				}
				
				System.out.println("Response: " + message);				
				messageTokens = message.split(":");
				
				int foundRequiredFields = 0;
				boolean isExpiration = false;
				boolean isToken = false;
				
				// Look for fields into the response message. It must find Expiration and Token fields into Reply-Message attribute.
				// The field structure is field-name:field-value
				for(String attr: messageTokens) {
					if(attr.equals("Expiration")) {
						isExpiration = true;
						foundRequiredFields++;
						continue;
					}
					
					if(isExpiration) {
						isExpiration = false;
						expirationTime = new Date();
						long msecs = expirationTime.getTime();
						System.out.println("Now: " + expirationTime);
						expirationTime.setTime(Long.parseLong(attr));
						System.out.println("Expiration time: " + expirationTime);						
						this.delay = expirationTime.getTime() - msecs;
						
						if (this.isRenew) {
							this.delay -= 30000;					// Sets time for call expiration
						}
						
						timer.schedule(new task(), this.delay);
						continue;
					}
					
					if(attr.equals("Token")) {
						isToken = true;
						foundRequiredFields++;
						continue;
					} 
					
					if(isToken) {
						this.token = attr;
					}
				}
				
				if (foundRequiredFields != 2) {
					System.out.println("Accept received without required fields. Probably AuthServer not configured properly.");
					return (false);
				}
			}
		} catch (IOException e) {
			System.out.println(e.getMessage());
			return false;
		} catch (RadiusException e) {
			System.out.println(e.getMessage());
			return false;
		}
		
		rc.close();
		return true;
	}
	
	/**
	 * This method must be used by MobileNodes after Authorize() return (hopefully, true) in order to
	 * receive list of Point of Attachment (gateway) IP addresses. 
	 * 
	 * @return String[] list with gateway IP addresses.
	 */
	public String[] getPOAList() {
		String[] list = null;
		boolean foundPoA = false;
		
		for (String token: this.messageTokens) {
			if (token.equals("PoA")) {
				foundPoA = true;
				continue;
			}
			
			if(foundPoA) {
				list = token.split(",");
				break;
			}	
		}
		return list;
	}
	
	/** 
	 * Checks token status and expiration time.
	 * If remoteExpiration equals 0 or token equals "", it uses previously received information from Authorized() method.
	 * Send and Account-Request packet with given Expiration and Token. AuthServer checks information and returns Account-Response
	 * with "forced" attribute Reply-Message and a Status field with OK or NOK string.
	 * 
	 * It is said "forced" because originally RADIUS Account-Response packets does not carry any attributes.
	 * 
	 * TODO - migrate used attributes to Vendor-Specific attributes.
	 * 
	 * @param uuid	acct-session-id
	 * @param user	who is making the request
	 * @param nasId who concerns remoteExpiration and remoteToken [it may be the own node, or checking a third party - received message.
	 * @param remote Expiration expiration to be checked. If not specified checking owns expiration.
	 * @param remoteToken token to be checked. If not specified checking owns token.
	 * @return true if authenticated, false otherwise.
	 */ 
	public boolean CheckTokenStatus(UUID uuid, String user, String nasId, long remoteExpiration, String remoteToken) {
		RadiusClient rc = new RadiusClient(this.server, this.secret);

		AccountingRequest acc = new AccountingRequest(this.user, AccountingRequest.ACCT_STATUS_TYPE_START);
		acc.addAttribute("Acct-Session-Id", uuid.toString());
		acc.addAttribute("Calling-Station-Id", nasId);
		
		if(remoteExpiration <= 0) {
			// Called CheckAuthorization without previously calling Authorize.
			if(this.expirationTime != null) {
				acc.addAttribute("Connect-Info", Long.toString(this.expirationTime.getTime()));
			} else {
				System.out.print("CheckAuthorization: not authorizing missing expiration time. Probably, app had not called Authorized()");
				return (false);
			}
		} else {
			acc.addAttribute("Connect-Info", Long.toString(remoteExpiration));
		}
		
		if(remoteToken == "") {
			if(this.token != "") {
				acc.addAttribute("Digest-Response", this.token);
			} else {
				System.out.print("CheckAuthorization: not authorizing missing token field. Probably, app had not called Authorized()");
				return(false);
			}
		} else {
			acc.addAttribute("Digest-Response", remoteToken);
		}

		System.out.println("CheckAuthorization:" + acc + "\n");
		
		// Communicates with Authorization Server via Account-Request radius packet and expects response.
		// Response packet should has Reply-Message attribute with Status field saying OK or NOK.
		RadiusPacket response;
		
		try {
			response = rc.account(acc);			
			System.out.println("\nResponse-ACC:" + response);
			
			String message = response.getAttributeValue("Reply-Message");
			
			if(message != null) {
				messageTokens = message.split(":");
						
				if(messageTokens[1].equals("NOK")) {				
					rc.close();
					return(false);
				}			
			} else {
				System.out.println("CheckAuthorization: response has not required field. Probably AuthServer not configured properly");
				rc.close();
				return(false);
			}
		} catch (IOException e) {			
			e.printStackTrace();
			return(false);
		} catch (RadiusException e) {			
			e.printStackTrace();
			return(false);
		}

		rc.close();
		
		return true;
	}
	
	/**
	 * Sets up radius shared secret of the client.
	 * 
	 * @param sharedSecret	Client's shared secret with Authorization Server.
	 */
	public void setSecret(String sharedSecret) {
		this.secret = sharedSecret;
	}
	
	/**
	 * 
	 * @param value boolean specifying if renews authorization at expiration time or not.
	 */
	public void setIsRenew(boolean value) {
		this.isRenew = value;
	}

	
	public long getTimeBeforeExpirationForRenew() {
		return timeBeforeExpirationForRenew;
	}

	public void setTimeBeforeExpirationForRenew(long timeBeforeExpirationForRenew) {
		this.timeBeforeExpirationForRenew = timeBeforeExpirationForRenew;
	}
	
}
