package be.msec.client;

import be.msec.client.connection.Connection;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;
import java.util.Arrays;
import java.util.Calendar;

import javax.smartcardio.*;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.DateFormatSymbols;
import java.text.SimpleDateFormat;


public class Client {

	private final static byte IDENTITY_CARD_CLA =(byte)0x80;
	private static final byte VALIDATE_PIN_INS = 0x22;
	private static final byte VALIDATE_TIME_INS = 0x25;
	private static final byte UPDATE_LOCAL_TIME_INS = 0x31;
	private static final byte VERIFY_PK_INS = (byte) 0x32;
	private final static byte FILL_TEMPBUFFER = (byte) 0x33;
	private static final byte GEN_NONCE = 0x20;
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private static final short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	private static final short TIME_UPDATE_REQUIRED = 0x6302;
	private static final int  SUCCESS_RESPONS = 36864;
	private final static short CERT_VALIDATION_FAIL = 0x6303;
	private final static short WRONG_CHALLENGE_RESPONSE = 0x6304;
	private final static byte GET_SERIAL_INS= 0x24;
	private final static byte GENERATE_SYM_K_INS = (byte) 0x34;
	private final static byte CHECK_CHALLENGE_RESPONSE = (byte) 0x36;
	private final static byte AUTHENTICATE_TO_SP = (byte) 0x37;
	//INS codes for different SPs
	private final static byte GET_eGov_DATA=(byte)0x05;
//	private final static byte GET_Health_DATA=(byte)0x06;	
//	private final static byte GET_SN_DATA=(byte)0x07;
//	private final static byte GET_def_DATA=(byte)0x08;
	//	timestamp implementation to be discussed
	//private final static byte GET_TS_DATA=(byte)0x09;
	private final static byte REQ_VALIDATION_INS=(byte)0x16;
	private final static byte VALIDATE_CERT_TIME = (byte) 0x35;
	
	//individuals identified by a service-specific pseudonym
	private  byte[] nym_Gov = new byte[]{0x11}; // to have something to test data saving on javacard
	private byte[] nym_Health = new byte[]{0x12}; // to have something to test data saving on javacard
	private byte[] nym_SN = new byte[]{0x13}; // to have something to test data saving on javacard
	private byte[] nym_def = new byte[]{0x14}; // to have something to test data saving on javacard
	
	private byte[] name;
	private byte[] address;
	private byte[] country;
	private byte[] birthdate;
	private byte[] age;
	private byte[] gender;
	private byte[] picture;
	private byte[] bloodType;
	
	//Certificates and Keys
	private final static byte CertC0=(byte)0x20;	//common cert
	private final static byte SKC0=(byte)0x21;
	private final static byte CertCA=(byte)0x22;	//CA
	private final static byte CertG=(byte)0x23;	//cert for gov timestam
	private final static byte SKG=(byte)0x24;
	private final static byte CertSP=(byte)0x25;	//cert in each domain
	private final static byte SKsp=(byte)0x26;
	private final static byte Ku=(byte)0x27;
	private final static byte PKG=(byte)0x28;
	
	/**
	 * @param args
	 */
	
	static TSClient TS = new TSClient();
	static IConnection c;
	boolean simulation = true;		// Choose simulation vs real card here
	
	public Client() throws Exception {
		CommandAPDU a;
		ResponseAPDU r;

		if (simulation) {
			//Simulation:	
			c = new SimulatedConnection();
		} else {
			//Real Card:
			c = new Connection();
			((Connection)c).setTerminal(0); //depending on which cardreader you use
		}
		
		c.connect(); 
		
		try {

			/*
			 * For more info on the use of CommandAPDU and ResponseAPDU:
			 * See http://java.sun.com/javase/6/docs/jre/api/security/smartcardio/spec/index.html
			 */
			
			
			
			if (simulation) {
				//0. create applet (only for simulator!!!)
				//Constructs a CommandAPDU from the four header bytes, command data, and expected response data length. (see link above)
				// 0x7f = 127 in decimal
				a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,new byte[]{(byte) 0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x08, 0x01}, 0x7f);
				r = c.transmit(a);
				System.out.println(r);
				if (r.getSW()!=SUCCESS_RESPONS ) throw new Exception("select installer applet failed");
				
				a = new CommandAPDU(0x80, 0xB8, 0x00, 0x00,new byte[]{0xb, 0x01,0x02,0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09,0x00, 0x00, 0x00}, 0x7f);
				r = c.transmit(a);
				System.out.println(r);
				if (r.getSW()!=SUCCESS_RESPONS ) throw new Exception("Applet creation failed");
				
				//1. Select applet  (not required on a real card, applet is selected by default)
				a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,new byte[]{0x01,0x02,0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09,0x00, 0x00}, 0x7f);
				r = c.transmit(a);
				System.out.println(r);
				if (r.getSW()!=SUCCESS_RESPONS ) throw new Exception("Applet selection failed");
			}
			
//Send PIN
			a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00,new byte[]{0x01,0x02,0x03,0x04});
			r = c.transmit(a);

			System.out.println(r);
			if (r.getSW()==SW_VERIFICATION_FAILED) throw new Exception("PIN INVALID");
			else if(r.getSW()!=SUCCESS_RESPONS ) throw new Exception("Exception on the card: " + r.getSW());
			System.out.println("PIN Verified");
			
			
			
			String timeStamp = new SimpleDateFormat("HH mm dd MM yyyy").format(Calendar.getInstance().getTime());
			String DatePart = timeStamp;
            String[] splittedDate = DatePart.split(" ");
            short hour = Short.parseShort(splittedDate[0]);
            short minute = Short.parseShort(splittedDate[1]);
            short day = Short.parseShort(splittedDate[2]);
            short month = Short.parseShort(splittedDate[3]);
            String milenium = splittedDate[4].substring(0, 2);
            String decenium = splittedDate[4].substring(2, 4);
            short mil = Short.parseShort(milenium);
            short dec = Short.parseShort(decenium);
            
			ByteBuffer Respbuffer = ByteBuffer.allocate(12);
            Respbuffer.putShort(hour);
            Respbuffer.position(2);
            Respbuffer.putShort(minute);
            Respbuffer.position(4);
            Respbuffer.putShort(day);
            Respbuffer.position(6);
            Respbuffer.putShort(month);
            Respbuffer.position(8);
            Respbuffer.putShort(mil);
            Respbuffer.position(10);
            Respbuffer.putShort(dec);
            Respbuffer.position(0);
            byte[] Response = new byte[Respbuffer.remaining()];
            Respbuffer.get(Response);
            
			a = new CommandAPDU(IDENTITY_CARD_CLA, REQ_VALIDATION_INS, 0x00, 0x00, Response);
			r = c.transmit(a); 
			System.out.println(r);
			
			if (r.getSW()==TIME_UPDATE_REQUIRED){
				System.out.println("Time update needed, contacting TSS");
				a = new CommandAPDU(IDENTITY_CARD_CLA, GEN_NONCE, 0x00, 0x00); 
				r = c.transmit(a); 
				System.out.println(r);
				byte[] b =r.getData();
				
			
	            
	            
	            byte[] slice = Arrays.copyOfRange(b, 6, b.length);
	            String nonce =new String(slice, java.nio.charset.StandardCharsets.US_ASCII);// b.toString();
	            
	            byte[] timeResponse = TS.getTime(slice);
	            
				System.out.println(b.toString());
				System.out.println("\nnonce: "+(nonce));
				//String timeResponse = TS.getTime(nonce);
				System.out.println("Recieved Time: " + timeResponse);
				System.out.println(timeResponse);
				a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_TIME_INS, 0x00, 0x00, timeResponse); 
				r = c.transmit(a); 
				System.out.println(r);
				if (r.getSW()==SUCCESS_RESPONS){
					System.out.println("Succesfully updated validated time on ID");
				}
	                
			}} catch (Exception e) {
				// TODO: handle exception
			}
		}
				
			//Send time to card, receive boolean
			//In progress...
			//first step to get signed time from G then pass it along
			//SSLServerThread st = new SSLServerThread();//tried this but...
			
			
                 
            
            
            
			
                
            
			
			//System.out.println("\nsigned Data - HEX: "+toHex(signedTime));
			// checkSW(response);
			
			//the card needs to handle singed time from client

			//byte[] signature = r.getData();
			//get time from Server
 
			//certificate handling
			//the card needs to handle singed time from client
			//byte[] signedData = "SignedTime".getBytes("ASCII");
			//a = new CommandAPDU(IDENTITY_CARD_CLA, REQ_VALIDATION_INS, 0x00, 0x00, signedData); 
			//r = c.transmit(a); 
			//System.out.println("\nsigned Data - HEX: "+toHex(signedData));
			// checkSW(response); 

			//signature = r.getData();
			//System.out.println();
			//System.out.printf("Signature from card: %s\n", toHex(signature));
            
//// get Serial#, example to get data from card	
//			r = c.transmit(a);
//			System.out.println(r);
//			//print response data array
//			byte[] b =r.getData();
//			String s = Arrays.toString(b);
//			System.out.println("Serial#: "+ s);
//
//
////eGov data
//			a = new CommandAPDU(IDENTITY_CARD_CLA, GET_eGov_DATA, 0x00, 0x00);
//			r = c.transmit(a);
//			
//			//print response data array
//			byte[] g =r.getData();
//			for(int i=6; i <g.length; i++){
//			System.out.print(new String(new byte[]{ (byte)r.getData() [i]}, "US-ASCII"));	
//		}
			
	
			//}
		//finally {
			//System.out.println("\n------ end connection ------");
			//c.close();  // close the connection with the card
		//}
	//}
	
//	public static Signature getSig(Signature){
//		Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1,false) ; //OR ALG_RSA_SHA_512_PKCS1
//		signature.initSign(privateKey, Signature.M);
//	}
	
    public static String toHex(byte[] bytes) { 
        StringBuilder buff = new StringBuilder(); 
        for (byte b : bytes) { 
            buff.append(String.format("%02X", b)); 
        } 
        return buff.toString(); 
    }

	public static String handleJSONSPauthenticate(JSONObject req) throws Exception {
		// TODO Auto-generated method stub
		CommandAPDU a;
		ResponseAPDU r;
		String Domain = (String) req.get("domain");
		String Cert = (String) req.get("cert");
		byte [] decoded = Base64.decode(Cert);
		
		//X509Certificate SPCertificate =  (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(decoded));
		
	 
		byte[] slice1 = Arrays.copyOfRange(decoded, 0, 80);
		
		ByteBuffer bb = ByteBuffer.allocate(slice1.length + 2);
		bb.putShort((short)0);
		bb.position(2);
		bb.put(slice1);
		bb.position(0);
		byte[] result1 = bb.array();
		
		byte[] slice2 = Arrays.copyOfRange(decoded, 80, decoded.length);
		ByteBuffer bbe = ByteBuffer.allocate(slice2.length + 2);
		bbe.putShort((short)1);
		bbe.position(2);
		bbe.put(slice2);
		bbe.position(0);
		byte[] result2 = bbe.array();
		
	    a = new CommandAPDU(IDENTITY_CARD_CLA, FILL_TEMPBUFFER, 0x00, 0x00,result1);
	    r = c.transmit(a);
		System.out.println(r);
		
		a = new CommandAPDU(IDENTITY_CARD_CLA, FILL_TEMPBUFFER, 0x00, 0x00,result2);
		r = c.transmit(a);
		
		System.out.println(r);
		a = new CommandAPDU(IDENTITY_CARD_CLA, VERIFY_PK_INS, 0x00, 0x00,0x00);
		//System.out.println(a.getNc());

		r = c.transmit(a);
		
		System.out.println(r);
		
		if (r.getSW() ==  CERT_VALIDATION_FAIL ) {
			//abort
		} else {
			//a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_CERT_TIME, 0x00, 0x00,0x00);
			//r = c.transmit(a);
			
			System.out.println(r);
			
			byte[] AESdatah = r.getData();
			System.out.println(AESdatah.length);    
			byte[] AESdata = Arrays.copyOfRange(AESdatah, 6, 22);
			byte[] challenge = Arrays.copyOfRange(AESdatah, 22, AESdatah.length);
			
			String AesString = Base64.encode(AESdata);
			String challengeString = Base64.encode(challenge);
			
			return AesString+ " " + challengeString;
			//new AES key is in here 
		}
		
		System.out.println(r);
		
		
		
		
		return "hey";} 
	
	static public boolean handleJSONSPauthenticateFinal(JSONObject req, String clientCommand){
		CommandAPDU a;
		ResponseAPDU r;
		
		try {
			byte[] challengeResponse = Base64.decode(clientCommand);
			  
			a = new CommandAPDU(IDENTITY_CARD_CLA, CHECK_CHALLENGE_RESPONSE, 0x00, 0x00,challengeResponse);
			    r = c.transmit(a);
				System.out.println(r);
			
				if (r.getSW()==WRONG_CHALLENGE_RESPONSE) {
					System.out.println("Wrong Challenge Response");
					return false;
				} else {
					System.out.println("Correct Challenge Response, Authenticated");
					return true;
				}
			
			
			
			
			
			
		} catch (Base64DecodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
		
	}
	
	
	
	
	
	
	static public void authenticate(JSONObject req, String clientCommand){
		CommandAPDU a;
		ResponseAPDU r;
		
		try {
			byte[] challenge = Base64.decode(clientCommand);
			  
			a = new CommandAPDU(IDENTITY_CARD_CLA, AUTHENTICATE_TO_SP, 0x00, 0x00,challenge);
			    r = c.transmit(a);
				System.out.println(r);
				
		} catch (Exception e) {
			// TODO: handle exception
		}
	
	
	}
	
	
}
	