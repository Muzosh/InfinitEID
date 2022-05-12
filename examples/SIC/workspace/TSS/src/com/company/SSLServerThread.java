package com.company;

import javax.crypto.Cipher;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.security.*;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Created by Nassim on 15/04/2017.
 */



public class SSLServerThread extends Thread{
    public PrintStream log_loc = System.out;
    protected SSLSocket sslSocket;

    public SSLServerThread(SSLSocket clientSocket) {
        this.sslSocket = clientSocket;
    }

    public void run() {
        try{

            KeyPair TSKey = getKeyPairFromKeyStore();

            // Create Input / Output Streams for communication with the client
            while(true)
            {
                PrintWriter out = new PrintWriter(sslSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(
                                sslSocket.getInputStream()));
                String inputLine, outputLine;

                while ((inputLine = in.readLine()) != null) {
                    String nonce = inputLine;
                    //System.out.println(nonce);
                    String dec_nonce = decrypt(nonce,TSKey.getPrivate());
                    String ctime = get_time();
                    String signature = sign(dec_nonce + ctime, TSKey.getPrivate());
                    out.println(ctime +" "+ signature);
                    //System.out.println(inputLine);
                }

                // Close the streams and the socket
                out.close();
                in.close();
                sslSocket.close();
            }
        } catch (java.net.SocketException se) {
            log_loc.println(get_time_for_log() + " | A client at "+sslSocket.getInetAddress()+" closed the connection");
            try {
                sslSocket.close();
            } catch (IOException e) {
                // ignore
            }
        }
        catch (javax.net.ssl.SSLHandshakeException ssle) {
            log_loc.println(get_time_for_log() + " | A client at "+sslSocket.getInetAddress()+" closed the connection during handshake");
        }

        catch(Exception exp)
        {
            log_loc.println(" Exception occurred .... " +exp);
            exp.printStackTrace();
        }

    }






    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }


    private static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }


    private static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }


    private String get_time(){
        Calendar cal = Calendar.getInstance();
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
//        SimpleDateFormat respdf = new SimpleDateFormat("dd-MM-yyyy"); //original from Nassim
        SimpleDateFormat respdf = new SimpleDateFormat("yyyy-MM-dd"); // changed to ease hierarchy when comparing two Times; Alternatively, D for days in year
        Date ct = cal.getTime();
        System.out.println(respdf.format(ct) + " "+ sdf.format(ct) + " | Request received from: "+ sslSocket.getInetAddress()+ " Responded: " + respdf.format(ct));
        return respdf.format(ct);
    }

    private String get_time_for_log(){
        Calendar cal = Calendar.getInstance();
        SimpleDateFormat respdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date ct = cal.getTime();
        return respdf.format(ct) ;
    }

    private static KeyPair getKeyPairFromKeyStore() throws Exception {

        InputStream ins = new FileInputStream("serverKS.jceks");

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(ins, "SICKS".toCharArray());   //Keystore password
        KeyStore.PasswordProtection keyPassword =       //Key password
                new KeyStore.PasswordProtection("SICKS".toCharArray());

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("ts private", keyPassword);

        java.security.cert.Certificate cert = keyStore.getCertificate("tscert");
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }

}


