package com.company;

import javax.crypto.Cipher;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Created by Nassim on 15/04/2017.
 */
public class TestClient {
    public static void main(String args[]) throws Exception {
        try {
            PublicKey TSkey = getPubKeyFromKeyStore();
            System.setProperty("javax.net.ssl.trustStore", "clientKS.jks");
            System.setProperty("javax.net.ssl.trustStorePassword", "SICKS");
            String strServerName = "localhost"; // SSL Server Name
            int intSSLport = 4443; // Port where the SSL Server is listening
            PrintWriter out = null;
            BufferedReader in = null;


            try {
                // Creating Client Sockets
                SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                SSLSocket sslSocket = (SSLSocket) sslsocketfactory.createSocket(strServerName, intSSLport);

                // Initializing the streams for Communication with the Server
                out = new PrintWriter(sslSocket.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));

                BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
                String userInput;
                String nonce = "nonce";  //TODO: generate something
                String ctime = "";
                while ((userInput = stdIn.readLine()) != null) {
                    String enc_nonce = encrypt(nonce,TSkey);
                    out.println(enc_nonce);
                    String response = in.readLine();
                    //System.out.println(response);
                    String[] parts = response.split(" ");
                    ctime = parts[0]; // date
                    String signature = parts[1]; // signed nonce + date
                    Boolean isCorrect = verify(nonce + ctime, signature, TSkey);
                    System.out.println(ctime);
                    System.out.println("verified: "+ isCorrect);
                }



                // Closing the Streams and the Socket
                out.close();
                in.close();
                stdIn.close();
                sslSocket.close();
            } catch (Exception exp) {
                System.out.println(" Exception occurred .... " + exp);
                exp.printStackTrace();
            }

        } catch (Exception exp) {
            System.out.println(" Exception occurred .... " + exp);
            exp.printStackTrace();
        }
    }

    private static PublicKey getPubKeyFromKeyStore() throws Exception {

        InputStream ins = new FileInputStream("clientKS.jks");

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(ins, "SICKS".toCharArray());   //Keystore password
        KeyStore.PasswordProtection keyPassword =       //Key password
                new KeyStore.PasswordProtection("SICKS".toCharArray());



        java.security.cert.Certificate cert = keyStore.getCertificate("ts cert");
        PublicKey publicKey = cert.getPublicKey();
        RSAPublicKey pk = (RSAPublicKey) publicKey;
        BigInteger Nk = pk.getModulus();
        BigInteger Ek = pk.getPublicExponent();

        byte[] Nkb = Nk.toByteArray();
        byte[] Ekb = Ek.toByteArray();


        System.out.println("");
        System.out.println("");


        for (int i=0; i< Nkb.length; i++){
            System.out.print((short)Nkb[i]);
            System.out.print(",");
        }

        System.out.println("");
        System.out.println("");


        for (int i=0; i< Ekb.length; i++){
            System.out.print((short)Ekb[i]);
            System.out.print(",");
        }
        System.out.println("");
        System.out.println("");

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