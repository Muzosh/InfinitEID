/*
 * helper class generates public and private keys, encrypts and decrypts byte arrays using the 
 */

package be.msec.client;

import java.io.*;
import java.security.*;
import javax.crypto.*;

public class SecKeys {
	
	private Cipher rsaenc;
	private Cipher rsadec;
	
	public byte[] encrypted;
	public byte[] decrypted;
	
	public static PublicKey pubkey;
	public static PrivateKey privkey;
	
	public SecKeys(){
		try{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(512);
	
			KeyPair kp = kpg.genKeyPair();
			pubkey = kp.getPublic();
			privkey = kp.getPrivate();
			
			rsaenc  = Cipher.getInstance("RSA");
			rsadec = Cipher.getInstance("RSA");
			
			rsaenc.init(Cipher.ENCRYPT_MODE, pubkey);
			rsadec.init(Cipher.DECRYPT_MODE, privkey);
				
		}catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}
	
	public byte[] encryptData(byte[] edata){
			try {
				return rsaenc.doFinal(edata);
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			}
			return encrypted;
      }

	public byte[] decryptData(byte[] enryptedText){
		try {
			return decrypted = rsadec.doFinal(enryptedText);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return decrypted;
      }
	
/*
 * code to generate RSA keys and work with its encrypted data
 * here is an example
 */
//	public static void main(String[] args){
//		byte[] j = null;
//		try {
//			j = "Hello, World!".getBytes("UTF-8");
//		} catch (UnsupportedEncodingException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		SecKeys p = new SecKeys();
//		byte[]encrypteddata = p.encryptData(j);
//		System.out.println(encrypteddata);
//				
//		byte[]  decrypted= p.decryptData(encrypteddata);
//		System.out.println(new String(decrypted));
//		
//	}
	
}
