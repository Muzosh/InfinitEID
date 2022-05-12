package be.msec.client;


import javax.crypto.Cipher;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class TSClient {

	 public byte[] getTime(byte[] nonce) throws Exception {
		 byte[] response = null;   
		 try {
	            PublicKey TSkey = getPubKeyFromKeyStore();
	            System.setProperty("javax.net.ssl.trustStore", "clientKS.jks");
	            System.setProperty("javax.net.ssl.trustStorePassword", "SICKS");
	            String strServerName = "localhost"; 							// SSL Server Name, should be updated if using a different computer 
	            int intSSLport = 4443; // Port where the SSL Server is listening
	            DataOutputStream out = null;
	            DataInputStream in = null;


	            try {
	                // Creating Client Sockets
	                SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
	                SSLSocket sslSocket = (SSLSocket) sslsocketfactory.createSocket(strServerName, intSSLport);

	                // Initializing the streams for Communication with the Server
	                out = new DataOutputStream(sslSocket.getOutputStream());
	                in = new DataInputStream(sslSocket.getInputStream());

	        
	                
	                    //String enc_nonce = encrypt(nonce,TSkey);
	                    //out.println(enc_nonce);
	                    //System.out.println(nonce);
	                	out.writeInt(nonce.length);
	                	out.write(nonce);
	            
	                    int length = in.readInt();                    // read length of incoming message
	                    if(length>0) {
	                    response = new byte[length];
	                    in.readFully(response, 0, response.length); // read the message

	                // Closing the Streams and the Socket
	                out.close();
	                in.close();
	                sslSocket.close();
	                return response;}
	                    
	                    else {
	                    	out.close();
	    	                in.close();
	    	                sslSocket.close();
							throw new Exception("No response from TSS");
						}
	            } catch (Exception exp) {
	                System.out.println(" Exception occurred .... " + exp);
	                exp.printStackTrace();
	            }

	        } catch (Exception exp) {
	            System.out.println(" Exception occurred .... " + exp);
	            exp.printStackTrace();
	        }
			return response;
	    }

	    private static PublicKey getPubKeyFromKeyStore() throws Exception {

	        InputStream ins = new FileInputStream("clientKS.jks");

	        KeyStore keyStore = KeyStore.getInstance("JKS");
	        keyStore.load(ins, "SICKS".toCharArray());   //Keystore password
	        KeyStore.PasswordProtection keyPassword =       //Key password
	                new KeyStore.PasswordProtection("SICKS".toCharArray());



	        java.security.cert.Certificate cert = keyStore.getCertificate("ts cert");
	        PublicKey publicKey = cert.getPublicKey();


	        return publicKey;
	    }


	    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
	        Cipher encryptCipher = Cipher.getInstance("RSA");
	        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

	        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

	        return Base64.getEncoder().encodeToString(cipherText);
	    }

	    private static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
	        Signature publicSignature = Signature.getInstance("SHA256withRSA");
	        publicSignature.initVerify(publicKey);
	        publicSignature.update(plainText.getBytes(UTF_8));

	        byte[] signatureBytes = Base64.getDecoder().decode(signature);

	        return publicSignature.verify(signatureBytes);
	    }
	}
