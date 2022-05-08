package com.company;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
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

                DataOutputStream out = new DataOutputStream(sslSocket.getOutputStream());
                DataInputStream in = new DataInputStream(sslSocket.getInputStream());
                String inputLine, outputLine;

                int length = in.readInt();                    // read length of incoming message
                if(length>0) {
                    byte[] nonce = new byte[length];
                    in.readFully(nonce, 0, nonce.length); // read the message



                    String signature= null;
                    String timeStamp = new SimpleDateFormat("HH mm dd MM yyyy").format(Calendar.getInstance().getTime());
                    String ctime = timeStamp;
                    try {
                        String dec_nonce = decrypt(nonce,TSKey.getPrivate());
                        byte[] bnonce = dec_nonce.getBytes(StandardCharsets.US_ASCII);
                        String DatePart = ctime;
                        String[] splittedDate = DatePart.split(" ");
                        short hour = Short.parseShort(splittedDate[0]);
                        short minute = Short.parseShort(splittedDate[1]);
                        short day = Short.parseShort(splittedDate[2]);
                        short month = Short.parseShort(splittedDate[3]);
                        String milenium = splittedDate[4].substring(0, 2);
                        String decenium = splittedDate[4].substring(2, 4);
                        short mil = Short.parseShort(milenium);
                        short dec = Short.parseShort(decenium);
                        ByteBuffer buffer = ByteBuffer.allocate(bnonce.length + 12);
                        int nonce_length = bnonce.length;
                        buffer.put(bnonce);
                        buffer.position(nonce_length);
                        buffer.putShort(hour);
                        buffer.position(nonce_length+2);
                        buffer.putShort(minute);
                        buffer.position(nonce_length+4);
                        buffer.putShort(day);
                        buffer.position(nonce_length+6);
                        buffer.putShort(month);
                        buffer.position(nonce_length+8);
                        buffer.putShort(mil);
                        buffer.position(nonce_length+10);
                        buffer.putShort(dec);
                        buffer.position(0);
                        byte[] timeR = new byte[buffer.remaining()];
                        buffer.get(timeR);
                        byte[] bytesignature = signBytes(timeR, TSKey.getPrivate());
                        ByteBuffer Respbuffer = ByteBuffer.allocate(bytesignature.length + 12);
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
                        Respbuffer.position(12);
                        Respbuffer.put(bytesignature);
                        Respbuffer.position(0);

                        byte[] Response = new byte[Respbuffer.remaining()];
                        Respbuffer.get(Response);
                        //out.write();
                        out.writeInt(Response.length);
                        out.write(Response);

                    } catch (BadPaddingException e) {
                        signature = "Bad padding";
                        out.write(0);
                    }
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






    public static String decrypt(byte[] cipherText, PrivateKey privateKey) throws Exception {
        //byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(cipherText), UTF_8);
    }


    private static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }


    private static byte[] signBytes(byte[] plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA1withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText);

        byte[] signature = privateSignature.sign();

        return signature;
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
        SimpleDateFormat respdf = new SimpleDateFormat("dd-MM-yyyy");
        Date ct = cal.getTime();
        System.out.println(respdf.format(ct) + " "+ sdf.format(ct) + " | Request received from: "+ sslSocket.getInetAddress()+ " Responded: " + respdf.format(ct));
        return respdf.format(ct);
    }

    private String get_time_for_log(){
        Calendar cal = Calendar.getInstance();
        SimpleDateFormat respdf = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
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


