package be.msec.smartcard;


//import java.util.Arrays;

//import be.msec.client.RandomData;
//import be.msec.client.bte;

//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import javax.crypto.Cipher;

import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.security.*;
import javacardx.crypto.Cipher;
import javacard.framework.Util;

//// in client not card
//import javacard.security.*;
//import javacardx.crypto.*;  //creating keys for use in symmetric algorithms

public class IdentityCard extends Applet {
//	CLA code in CommandAPDU header
	private final static byte IDENTITY_CARD_CLA =(byte)0x80;
	
//	INS codes
	private static final byte VALIDATE_PIN_INS = 0x22;
	private static final byte GET_SERIAL_INS = 0x24;
	private static final byte GEN_NONCE = 0x20;
	private final static byte PIN_TRY_LIMIT =(byte)0x03;
	private final static byte PIN_SIZE =(byte)0x04;
	private final static byte REQ_VALIDATION_INS=(byte)0x16;
	private final static byte VALIDATE_TIME_INS=(byte)0x25;
	private final static byte UPDATE_LOCAL_TIME_INS=(byte)0x31;
	private final static byte VERIFY_PK_INS = (byte) 0x32;
	private final static byte FILL_TEMPBUFFER = (byte) 0x33;
	private final static byte GENERATE_SYM_K_INS = (byte) 0x34;
	private final static byte VALIDATE_CERT_TIME = (byte) 0x35;
	private final static byte CHECK_CHALLENGE_RESPONSE = (byte) 0x36;
	private final static byte AUTHENTICATE_TO_SP = (byte) 0x37;
//	//INS codes for different SPs
	private final static byte GET_eGov_DATA=(byte)0x05;
	private final static byte GET_Health_DATA=(byte)0x06;	
	private final static byte GET_SN_DATA=(byte)0x07;
	private final static byte GET_def_DATA=(byte)0x08;
	//	TS_DATA: first check lastVal. time and update, diff . e.g. set at 24 hrs 
	private final static byte GET_TS_DATA=(byte)0x09; //timestamp
	private final static byte SET_Data=(byte)0x10;
	private final static byte Set_PIN=(byte)0x15;
	//	private byte reqTime=(byte)0x17;
	
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	private final static short TIME_UPDATE_REQUIRED = 0x6302;
	private final static short CERT_VALIDATION_FAIL = 0x6303;
	private final static short WRONG_CHALLENGE_RESPONSE = 0x6304;
	private static final APDU APDU = null;
	
	private Cipher encryptCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1 , false);
	private Cipher encryptC = Cipher.getInstance(Cipher.ALG_RSA_PKCS1 , false);
	private Signature asymSignature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
	private Signature checkSignature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
	byte[] TSN=new byte[]{-77,42,40,-107,-108,-42,125,12,28,-5,44,-22,14,46,61,-115,-45,-126,38,-64,20,53,55,-69,33,48,119,36,106,12,-45,-71,-106,120,114,91,78,56,42,-15,-40,74,24,-74,-21,-72,-75,-36,-77,-66,122,-37,120,94,3,112,19,-55,6,73,118,127,-13,109};
	byte[] TSE=new byte[]{1,0,1};
	
	private final static byte[] CAE=new byte[]{1,0,1};
	private final static byte[] CAN=new byte[]{-75,-95,45,30,-89,-85,-17,-75,121,-51,127,114,50,47,52,30,119,-62,63,96,-118,-59,-23,-84,-32,62,-65,114,1,61,79,0,-58,-62,-31,-15,67,-38,51,95,58,12,-75,-1,-12,-74,80,60,-56,83,10,-35,62,19,-121,124,34,-48,84,98,-31,-75,-108,-57};
	
	private byte[] challenge;
	

	byte[] tempbuffer = new byte[200];
	short tempbufferSentinel = (short) 0;
	private boolean CertValidated = false;
	private boolean SPAuthenticated = false;
////	instance variables declaration
	private byte[] serial = new byte[]{0x30, 0x35, 0x37, 0x36, 0x39, 0x30, 0x31, 0x05};
	private OwnerPIN pin;
//	//individuals identified by a service-specific pseudonym
//	private byte[] nym_Gov = new byte[]{0x11}; // to have something to test data saving on javacard
//	private byte[] nym_Health = new byte[]{0x12};
//	private byte[] nym_SN = new byte[]{0x13};
//	private byte[] nym_def = new byte[]{0x14};

////	instance variables
//	private byte[] name = new byte[]{0x01,0x02,0x03,0x04};
	private byte[] name = {'i', 'n', 's', 'e', 'r', 't',' ', 'c','h','a','r'};
//	private byte[] address;
//	private byte[] country;
//	private byte[] birthdate;
//	private byte[] age;
//	private byte[] gender;
//	private byte[] picture;
//	private byte[] bloodType;
	
	//personal informationn saved on card
	//input above instance variables into info below
	private byte[] info;
	private short incomingData;
//	private short newPin;

	
//	data for certification and encryption/decryption, time needed for cert verification
	private byte[] lastValidationTime = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //time format
	//private byte[] currentTime = new byte[11];
	private byte[] nonce  = new byte[]{(byte)'H',(byte)'E',(byte)'L',(byte)'L',(byte)'O'};
	//private byte[] verifiedTime = new byte[12];
//	private final static byte CertC0=(byte)0x20;	//common cert
//	private final static byte SKC0=(byte)0x21;
//	private final static byte CertCA=(byte)0x22;	//CA
	private final static byte[] CertG= new byte[]{0x30, 0x48, 0x2, 0x41, 0x0,(byte) 0xb3, 0x2a, 0x28, (byte)0x95,(byte) 0x94, (byte)0xd6, 0x7d, 0xc, 0x1c,(byte) 0xfb, 0x2c, (byte)0xea, 0xe, 0x2e, 0x3d, (byte)0x8d, (byte)0xd3,(byte) 0x82, 0x26, (byte)0xc0, 0x14, 0x35, 0x37,(byte) 0xbb, 0x21, 0x30, 0x77, 0x24, 0x6a, 0xc,(byte) 0xd3, (byte)0xb9, (byte)0x96, 0x78, 0x72, 0x5b, 0x4e, 0x38, 0x2a,(byte) 0xf1,(byte) 0xd8, 0x4a, 0x18, (byte)0xb6, (byte)0xeb, (byte)0xb8, (byte)0xb5, (byte)0xdc, (byte)0xb3, (byte)0xbe, 0x7a, (byte)0xdb, 0x78, 0x5e, 0x3, 0x70, 0x13, (byte)0xc9, 0x6, 0x49, 0x76, 0x7f, (byte)0xf3, 0x6d, 0x2, 0x3, 0x1, 0x0, 0x1};	//cert for gov timestam
//	private final static byte SKG=(byte)0x24;
//	private final static byte CertSP=(byte)0x25;	//cert in each domain
//	private final static byte SKsp=(byte)0x26;
//	private final static byte Ku=(byte)0x27;
	private final static byte privKey=(byte)0x28;
	private final static byte pubKey=(byte)0x29;
	
	private KeyPair kp;
	private AESKey symKey;
//	allocate all memory applet needs during its lifetime

	private IdentityCard() {
		/*
		 * During instantiation of the applet, all objects are created.
		 * In this example, this is the 'pin' object.
		 */
		pin = new OwnerPIN(PIN_TRY_LIMIT,PIN_SIZE);
		pin.update(new byte[]{0x01,0x02,0x03,0x04},(short) 0, PIN_SIZE);
		/*
		 * This method registers the applet with the JCRE on the card.
		 */
		//create placeholder for personal information to be given per service provider
		//4086 from tutorial, might be too long for this javacard but might work in jcwde
//		info = new byte[4086];
		register();
	}

//	//Create object of keys
//    RSAPrivateKey thePrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
//    RSAPublicKey thePublickKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
//    KeyPair theKeyPair = new KeyPair(thePublickKey, thePrivateKey);
	
	/*
	 * This method is called by the JCRE when installing the applet on the card.
	 */
	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
			new IdentityCard();
		}
	
	/*
	 * If no tries are remaining, the applet refuses selection.
	 * The card can, therefore, no longer be used for identification.
	 */
	public boolean select() {
		if (pin.getTriesRemaining()==0)
			return false;
		return true;
	}

	/*
	 * This method is called when the applet is selected and an APDU arrives. Processes incoming APDU
	 */
	public void process(APDU apdu) throws ISOException {
		//A reference to the buffer, where the APDU data is stored, is retrieved.
		byte[] buffer = apdu.getBuffer();
		//needed for looping when sending large arrays
		 short LC = apdu.getIncomingLength();
		
		//If the APDU selects the applet, no further processing is required.
		if(this.selectingApplet()){
			return;
		}
		//Check whether the indicated class of instructions is compatible with this applet.
		if (buffer[ISO7816.OFFSET_CLA] != IDENTITY_CARD_CLA)ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		//A switch statement is used to select a method depending on the instruction
		switch(buffer[ISO7816.OFFSET_INS]){
		case VALIDATE_PIN_INS:
			validatePIN(apdu);
			break;
		case REQ_VALIDATION_INS:
			reqRevalidation(apdu);
			break;
		case GET_SERIAL_INS:
			getSerial(apdu);
			break;
		case GET_eGov_DATA:
			eGov_DATA(apdu);
			break;
		case GET_Health_DATA:
			HealthDATA(apdu);
			break;
		case GET_SN_DATA:
			SNDATA(apdu);
			break;
		case GET_def_DATA:
			defDATA(apdu);
			break;
		//update time if validateTIME returnns true
		case GET_TS_DATA:
			TSDATA(apdu);
			break;
		case GEN_NONCE:
			genNonce(apdu);
			break;
		case VALIDATE_TIME_INS:
			validateSignedTime(apdu);
			break;
		case VERIFY_PK_INS:
			verifyPK(apdu);
			break;
		case FILL_TEMPBUFFER:
			fillTempBuffer(apdu);
			break;
		case VALIDATE_CERT_TIME:
			ValidateCertTime(apdu);
			break;
		case CHECK_CHALLENGE_RESPONSE:
			checkChallangeResp(apdu);
			break;
			case AUTHENTICATE_TO_SP:
				authenticateToSP(apdu);
				break;
			
			
			
//		//hard code
//		case SET_Data:
//			setData(apdu);
//			break;
//		//hard code
//		case Set_PIN:
//			setPin(apdu);
//			break;
		//default: genNonce(apdu);	
		//If no matching instructions are found it is indicated in the status word of the response.
		//This can be done by using this method. As an argument a short is given that indicates
		//the type of warning. There are several predefined warnings in the 'ISO7816' class.
		default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	/*
	 * This method is used to authenticate the owner of the card using a PIN code.
	 */
	private void validatePIN(APDU apdu){
		byte[] buffer = apdu.getBuffer();
		//The input data needs to be of length 'PIN_SIZE'.
		//Note that the byte values in the Lc and Le fields represent values between
		//0 and 255. Therefore, if a short representation is required, the following
		//code needs to be used: short Lc = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
		if(buffer[ISO7816.OFFSET_LC]==PIN_SIZE){
			//This method is used to copy the incoming data in the APDU buffer.
			apdu.setIncomingAndReceive();
			//Note that the incoming APDU data size may be bigger than the APDU buffer 
			//size and may, therefore, need to be read in portions by the applet. 
			//Most recent smart cards, however, have buffers that can contain the maximum
			//data size. This can be found in the smart card specifications.
			//If the buffer is not large enough, the following method can be used:
			//byte[] buffer = apdu.getBuffer();
			//short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
			//Util.arrayCopy(buffer, START, storage, START, (short)5);
			//short readCount = apdu.setIncomingAndReceive();
			//short i = ISO7816.OFFSET_CDATA;
			//while ( bytesLeft > 0){
			//	Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, storage, i, readCount);
			//	bytesLeft -= readCount;
			//	i+=readCount;
			//	readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
			//}
			if (pin.check(buffer, ISO7816.OFFSET_CDATA,PIN_SIZE)==false)
				ISOException.throwIt(SW_VERIFICATION_FAILED);
		}
		//shouldn't indicate that it was not accepted because of size, keep matter unknown
//		else ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		else ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}
	

	//receive signed time from SP through Client; update card time if client time more recent 
		private void genNonce(APDU apdu){
			if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
			else{
				
				byte[] buf = apdu.getBuffer();
			    byte ins = buf[ISO7816.OFFSET_INS];
			    short lc = (short)(buf[ISO7816.OFFSET_LC] & 0x00FF);
			    short outLength;
				//nonce  = new byte[20];
				//RandomData rand = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		        //rand.generateData(nonce, (short)0, (short)nonce.length);
		        //nonce = {'h','e','l','l','o'};
			    RSAPublicKey TSkey =  (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false); 
				TSkey.setModulus(TSN, (short)0,(short) TSN.length);
				TSkey.setExponent(TSE, (short)0,(short) TSE.length);
				
				apdu.setOutgoing();
				
				encryptCipher.init(TSkey, Cipher.MODE_ENCRYPT);
				outLength = encryptCipher.doFinal(nonce, (short) 0, (short)nonce.length, buf, (short)0);
				
				apdu.setOutgoingLength(outLength);
				apdu.sendBytes((short)0,outLength);
				//ISOException.throwIt(nonce);
				
			    }
			}

		private void validateSignedTime(APDU apdu){
			if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
			else{
				
			
				byte[] buffer = apdu.getBuffer();
				short lc = (short)(buffer[ISO7816.OFFSET_LC] & 0x00FF);
				RSAPublicKey TSkey =  (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false); 
				TSkey.setModulus(TSN, (short)0,(short) TSN.length);
				TSkey.setExponent(TSE, (short)0,(short) TSE.length);
				short signatureSize = (short)(TSkey.getSize() >> 3);
				
				
				asymSignature.init(TSkey, Signature.MODE_VERIFY);
				
				byte[] plainMessage = new byte[nonce.length + 12];
				byte[] encryptedM = new byte[signatureSize];
				Util.arrayCopy(nonce, (short)0, plainMessage ,(short)0,(short) nonce.length);
				Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, plainMessage ,(short)nonce.length,(short) 12);
				Util.arrayCopy(buffer,(short)(ISO7816.OFFSET_CDATA + (short)12), encryptedM,(short) 0,signatureSize);
				boolean verified = asymSignature.verify(plainMessage, (short)0,(short) (short) plainMessage.length, encryptedM, (short) 0, signatureSize);
      
				if (verified) {
					Util.arrayCopy(plainMessage, (short)nonce.length, lastValidationTime ,(short)0,(short) 12);
				} else {
					ISOException.throwIt((short)2);
				}
			    }
			}
		
		
		
		private void fillTempBuffer(APDU apdu){
			
			byte[] buffer = apdu.getBuffer();
			short state = Util.makeShort(buffer[ISO7816.OFFSET_CDATA], buffer[ISO7816.OFFSET_CDATA+1]);
			
			if (state == (short)0) {
				tempbufferSentinel = (short)0;
				
			}
			else if (state == (short) 1 ) {
				
			}
			Util.arrayCopy(buffer, (short)(ISO7816.OFFSET_CDATA+2), tempbuffer ,tempbufferSentinel,(short) (apdu.getIncomingLength()-2));
			tempbufferSentinel = (short) (tempbufferSentinel + apdu.getIncomingLength()-2);
		}
		
		
		
		
		private void ValidateCertTime(APDU apdu){
			if (CertValidated) {
				byte[] certTime = new byte[8];
				Util.arrayCopy(tempbuffer, (short) 1, certTime, (short) 0, (short) certTime.length); 
				
				boolean timeValid = false;
				
				short lday = Util.makeShort(certTime[0], certTime[1]);
				short lmonth = Util.makeShort(certTime[2], certTime[3]);
				short lmil = Util.makeShort(certTime[4], certTime[5]);
				short ldec = Util.makeShort(certTime[6], certTime[7]);
				
				
				
				short cday = Util.makeShort(lastValidationTime[4], lastValidationTime[5]);
				short cmonth = Util.makeShort(lastValidationTime[6], lastValidationTime[7]);
				short cmil = Util.makeShort(lastValidationTime[8], lastValidationTime[9]);
				short cdec = Util.makeShort(lastValidationTime[10], lastValidationTime[11]);
				
				if (lmil > cmil) {
					timeValid = true;
				} else if (ldec > cdec) {
					timeValid = true;
				}else if (lmonth > cmonth) {
					timeValid = true;
				} else if (lday > cday) {
					timeValid = true;
				} else {
					timeValid = false;
				}
				
				if (!timeValid) {
					ISOException.throwIt(CERT_VALIDATION_FAIL);
				} else {
					genSymKey(apdu);
				}
				
				
				
			} else {
				//should never happen
				ISOException.throwIt(CERT_VALIDATION_FAIL);
			}
		}
		
		
		private void genSymKey(APDU apdu){
			
			short Elength = Util.makeShort(tempbuffer[11], tempbuffer[12]) ;
			short Nlength = Util.makeShort(tempbuffer[9], tempbuffer[10]) ;
			
			byte[] pkmod = new byte[Nlength];
			byte[] pkexp = new byte[Elength];
			
			Util.arrayCopy(tempbuffer,  (short) 13, pkmod, (short) 0, Nlength);
			Util.arrayCopy(tempbuffer,  (short) (Nlength+13), pkexp, (short) 0, Elength);
			
			RandomData randomData = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
			byte[] rnd = new byte[16];
			randomData.generateData(rnd, (short)0, (short)rnd.length);
			
			symKey = (AESKey) KeyBuilder.buildKey (KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
			symKey.setKey(rnd, (short)0);
//			
//			
			RSAPublicKey SPkey =  (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false); 
			SPkey.setModulus(pkmod, (short)0,(short) pkmod.length);
			SPkey.setExponent(pkexp, (short)0,(short) pkexp.length);
//			
			
			encryptC.init(SPkey, Cipher.MODE_ENCRYPT);
//			
			byte[] rnd1= new byte[8];
			byte[] rnd2= new byte[8];
			
			Util.arrayCopy(rnd, (short) 0, rnd1, (short)0, (short)rnd1.length); 
			Util.arrayCopy(rnd, (short) rnd1.length, rnd2, (short)0, (short)rnd2.length); 
			
			byte[] encryptedkey = new byte[48];
			//short outLength = encryptC.doFinal(rnd1, (short) 0, (short)rnd1.length, encryptedkey, (short)0);
			
			
			
			byte[] encryptedChallenge = new byte[16];
			
			challenge = new byte[16];
			
			
			randomData.generateData(challenge, (short)0, (short)challenge.length);
			
			Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
			aesCipher.init(symKey, Cipher.MODE_ENCRYPT); 
			aesCipher.doFinal(challenge, (short)0, (short) challenge.length, encryptedChallenge, (short)0);
			//apdu.setOutgoingAndSend((short)0, len);
			
			//challange stuff;
			
			byte[] response = new byte[encryptedChallenge.length+rnd.length];
			Util.arrayCopy(tempbuffer,  (short) 13, pkmod, (short) 0, Nlength);
			Util.arrayCopy(rnd, (short)0, response,(short)0, (short)rnd.length);
			Util.arrayCopy(encryptedChallenge, (short)0, response,(short)rnd.length, (short)encryptedChallenge.length);
			
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)response.length);
			apdu.sendBytesLong(response,(short)0,(short)response.length);
			
			try {
				//short outLength = encryptC.doFinal(rnd, (short) 0, (short)rnd.length, buf, (short)0);
				//apdu.setOutgoingLength(outLength);
				//apdu.sendBytes((short)0,outLength);
			} catch (ISOException e) {
				ISOException.throwIt(e.getReason());
			}
			
			
			
			
			
			//apdu.setOutgoing();
			//apdu.setOutgoingLength((short)rnd.length);
			//apdu.sendBytesLong(rnd,(short)0,(short)rnd.length);
			
//			byte[] encryptedSymKey = new byte[48];
//			
//			encryptC.doFinal(rnd, (short)0, (short)rnd.length, encryptedSymKey, (short)0);
//		
//			
//			apdu.setOutgoing();
//			apdu.setOutgoingLength((short)encryptedSymKey.length);
//			apdu.sendBytesLong(encryptedSymKey,(short)0,(short)encryptedSymKey.length);
			
		}
		
		
		private void verifyPK(APDU apdu){
			if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
			else{
				
				RSAPublicKey CAkey =  (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false); 
				CAkey.setModulus(CAN, (short)0,(short) CAN.length);
				CAkey.setExponent(CAE, (short)0,(short) CAE.length);
				short signatureSize = (short)(CAkey.getSize() >> 3);
				
				checkSignature.init(CAkey, Signature.MODE_VERIFY);
				
				
				
				short Elength = Util.makeShort(tempbuffer[11], tempbuffer[12]) ;
				short Nlength = Util.makeShort(tempbuffer[9], tempbuffer[10]) ;
				
				
				byte[] plainMessage = new byte[Elength + Nlength + 13];
				byte[] encryptedM = new byte[signatureSize];
				Util.arrayCopy(tempbuffer, (short)0 , plainMessage ,(short)0, (short) plainMessage.length);
				Util.arrayCopy(tempbuffer,(short)(Elength + Nlength + 13), encryptedM,(short) 0, signatureSize);
				
				
				boolean verified = checkSignature.verify(plainMessage, (short)0,(short) plainMessage.length, encryptedM, (short) 0, signatureSize);
				//boolean verified = checkSignature.verify(tempbuffer, (short)0,(short) 80, tempbuffer, (short) 80, (short)64);
      
				//boolean verified = true; 
				
				if (verified) 
				{	CertValidated = true;
					ValidateCertTime(apdu);
				} 
				else {
					CertValidated = false;
					ISOException.throwIt(CERT_VALIDATION_FAIL);
					//apdu.setOutgoing();
					//apdu.setOutgoingLength((short)144);
					//apdu.sendBytesLong(tempbuffer,(short)0,(short)144);
				//	ISOException.throwIt((short) tempbufferSentinel);
				}
				}
				
			    
			}
		
	
		
		private void checkChallangeResp(APDU apdu){
			byte[] response = new byte[apdu.getIncomingLength()];
			byte[] decryptedResponse = new byte[16];
			byte[] buffer = apdu.getBuffer();
			
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, response, (short)0, (short)response.length);
			
			
			Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
			aesCipher.init(symKey, Cipher.MODE_DECRYPT); 
			aesCipher.doFinal(response, (short)0, (short) response.length, decryptedResponse, (short)0);
			
			
			
			byte last = decryptedResponse[decryptedResponse.length-1];
			byte challengeLast = challenge[challenge.length-1];
			
			byte[] result = new byte[decryptedResponse.length + challenge.length];
			
			//Util.arrayCopy(decryptedResponse, (short)0, result, (short)0, (short)decryptedResponse.length);
			//Util.arrayCopy(challenge, (short)0, result, (short)decryptedResponse.length, (short)challenge.length);
			
			
			
			//ISOException.throwIt((short) result.length);
			//apdu.setOutgoing();
			//apdu.setOutgoingLength((short)result.length);
			//apdu.sendBytesLong(result,(short)0,(short)result.length);
			
			if ((challengeLast+(byte) 1)==last) {
				SPAuthenticated = true;
			} else {
				SPAuthenticated = false;
				ISOException.throwIt((short) WRONG_CHALLENGE_RESPONSE);
			}
			
		}
		
		
		private void authenticateToSP(APDU apdu){
	          KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_512);
	          keyPair.genKeyPair();
	          
			
			byte[] response = new byte[apdu.getIncomingLength()];
			byte[] decryptedResponse = new byte[16];
			byte[] buffer = apdu.getBuffer();
			byte[] publickeyBuffer = new byte[67];
			
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, response, (short)0, (short)response.length);
			
			
			Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
			aesCipher.init(symKey, Cipher.MODE_DECRYPT); 
			aesCipher.doFinal(response, (short)0, (short) response.length, decryptedResponse, (short)0);
			
		
			RSAPublicKey pk = (RSAPublicKey) keyPair.getPublic();
			//RSAPrivateCrtKey sk = (RSAPrivateCrtKey) keyPair.getPrivate();
			
			short msize = pk.getModulus(publickeyBuffer, (short)0);
			short esize = pk.getExponent(publickeyBuffer, (short)64);
			
			
			
			 apdu.setOutgoing();
			 apdu.setOutgoingLength((short)67);
			 apdu.sendBytesLong(publickeyBuffer,(short)0,(short)67);
			
			Signature asymsignature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
			asymsignature.init(keyPair.getPrivate(), Signature.MODE_SIGN);
			asymsignature.sign(decryptedResponse, (short)0, (short)decryptedResponse.length, publickeyBuffer, (short)67);
			
			//Cipher encryptC = Cipher.getInstance(Cipher.ALG_RSA_PKCS1,false);
			//encryptC.init(sk, Cipher.MODE_ENCRYPT);
			
			//short encsize = encryptC.doFinal(decryptedResponse, (short)0, (short)decryptedResponse.length, buffer,(short) (4 + msize+esize));
			
			//short encsize = (short)0;
			
			//short outLength = (short) (4+ msize+esize+encsize);
			//apdu.setOutgoingLength(outLength);
			//apdu.sendBytes((short)0,outLength);
			
			
		}
		
		
	//receive signed time from SP through Client; update card time if client time more recent 
	private boolean reqRevalidation(APDU apdu){
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			
			
			byte[] buffer = apdu.getBuffer();
			
		
			
			byte[] Time = new byte[12];
			
			
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, Time ,(short)0,(short) 12);
			
			
			short lhour = Util.makeShort(Time[0], Time[1]);
			short lmin = Util.makeShort(Time[2], Time[3]);
			short lday = Util.makeShort(Time[4], Time[5]);
			short lmonth = Util.makeShort(Time[6], Time[7]);
			short lmil = Util.makeShort(Time[8], Time[9]);
			short ldec = Util.makeShort(Time[10], Time[11]);
			
			
			short chour = Util.makeShort(lastValidationTime[0], lastValidationTime[1]);
			short cmin = Util.makeShort(lastValidationTime[2], lastValidationTime[3]);
			short cday = Util.makeShort(lastValidationTime[4], lastValidationTime[5]);
			short cmonth = Util.makeShort(lastValidationTime[6], lastValidationTime[7]);
			short cmil = Util.makeShort(lastValidationTime[8], lastValidationTime[9]);
			short cdec = Util.makeShort(lastValidationTime[10], lastValidationTime[11]);
			
			
			short delta = 1;
			boolean updateRequired; 
			
			if (lmil > cmil) {
				updateRequired = true;
			} else if (ldec > cdec) {
				updateRequired = true;
			}else if (lmonth > cmonth) {
				updateRequired = true;
			} else if (lday > cday) {
				updateRequired = true;
			} else if (lhour - delta > chour) {
				updateRequired = true;
			} else {
				updateRequired = false;
			}
			
			if (updateRequired)  {
				ISOException.throwIt(TIME_UPDATE_REQUIRED);
			} 
			return true;}
		ISOException.throwIt(TIME_UPDATE_REQUIRED);
	return false;	
	}
		
// 20 byte challenge
	private byte[] getRand(){
		byte[] buf = new byte[20];
        RandomData rand = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        rand.generateData(buf, (short)0, (short)buf.length);
        return buf;
		}
	
	private void getSerial(APDU apdu){
		//If the pin is not validated, a response APDU with the
		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//This sequence of three methods sends the data contained in
			//'identityFile' with offset '0' and length 'identityFile.length'
			//to the host application.
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)serial.length);
			apdu.sendBytesLong(serial,(short)0,(short)serial.length);
		}
	}
	
//		working in progress for all INS
	private void eGov_DATA(APDU apdu){
		//If the pin is not validated, a response APDU with the
		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//This sequence of three methods sends the data contained in
			//'identityFile' with offset '0' and length 'identityFile.length'
			//to the host application.
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)name.length);
			apdu.sendBytesLong(name,(short)0,(short)name.length);
		}
	}
	
	private void HealthDATA(APDU apdu){
		//If the pin is not validated, a response APDU with the
		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//This sequence of three methods sends the data contained in
			//'identityFile' with offset '0' and length 'identityFile.length'
			//to the host application.
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)name.length);
			apdu.sendBytesLong(name,(short)0,(short)name.length);
		}
	}	
	
	
	private void defDATA(APDU apdu){
		//If the pin is not validated, a response APDU with the
		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//This sequence of three methods sends the data contained in
			//'identityFile' with offset '0' and length 'identityFile.length'
			//to the host application.
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)info.length);
			apdu.sendBytesLong(info,(short)0,(short)info.length);
		}
	}
	
//social network 
	private void SNDATA(APDU apdu){
		//If the pin is not validated, a response APDU with the
		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//This sequence of three methods sends the data contained in
			//'identityFile' with offset '0' and length 'identityFile.length'
			//to the host application.
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)info.length);
			apdu.sendBytesLong(info,(short)0,(short)info.length);
		}
	}

//timeStamp
	private void TSDATA(APDU apdu){
		//If the pin is not validated, a response APDU with the
		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
		}
		}
	
	//generate keys
	public PublicKey getPubKey(){
		short keySize = KeyBuilder.LENGTH_RSA_512;
		KeyPair kp = new KeyPair(KeyPair.ALG_RSA, keySize);
		kp.genKeyPair();
		PrivateKey privKey = kp.getPrivate();
		PublicKey pubKey = kp.getPublic();
		return pubKey;
	}
	
	
	public void genRSAKeys(){
		short keySize = 512;
		kp = new KeyPair(KeyPair.ALG_RSA, keySize);
	}
	
	
//	maybe for later if we have the time
//	//no need for now, hard coded in
//	//gov initially sets data
//	private void setData(APDU apdu){
//	    short dataOffset = apdu.getOffsetCdata();
//	    short bytes_left = (short) buffer[ISO.OFFSET_LC];
//		short readCount = apdu.setIncomingAndReceive();
//		while (bytes_left > 0) {
//		//{process received data in buffer}
//		bytes_left -= readCount;
//		//get more data
//		readCount = apdu.receiveBytes (ISO.OFFSET_CDDATA);
//		}	    
//		//verification via certificate of
//		apdu.setIncomingAndReceive();
//		apdu.receiveBytes(incomingData);
//	}
//
//	
//	//no need for now, it's done by the client
//	//owner of card sets pin
//	private void setPin(APDU apdu){
//		//If the pin is not validated, a response APDU with the
//		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
//		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
//		else{
//			apdu.setIncomingAndReceive();
//			apdu.receiveBytes(newPin);
//			// use: update(byte[] pin, short offset, byte length)
//			// to update pin object
//		}
//	}
	
}
