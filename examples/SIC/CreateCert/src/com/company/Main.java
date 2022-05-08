package com.company;

import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;

public class Main {

    public static void main(String[] args) {
        try {
            KeyPair kp = getKeyPairFromKeyStore();
            RSAPublicKey pubr = (RSAPublicKey) kp.getPublic();
            BigInteger rexp = pubr.getPublicExponent();
            BigInteger rmod = pubr.getModulus();


            byte[] rmodu = rmod.toByteArray();
            //if (rmodu[0] == 0) {
            //    byte[] tmp = new byte[rmodu.length - 1];
            //    System.arraycopy(rmodu, 1, tmp, 0, tmp.length);
            //    rmodu = tmp;
            //}

            byte[] rexpo = rexp.toByteArray();
            //if (rexpo[0] == 0) {
            //    byte[] tmp = new byte[rexpo.length - 1];
            //    System.arraycopy(rexpo, 1, tmp, 0, tmp.length);
            //    rexpo = tmp;
            //}


            X509Certificate defa = (X509Certificate) getCertFromKeyStore();
            RSAPublicKey dk = (RSAPublicKey) defa.getPublicKey();
            String date = new SimpleDateFormat("dd MM yyyy").format(defa.getNotAfter());
            BigInteger modu = dk.getModulus();
            BigInteger expone = dk.getPublicExponent();

            byte[] bmod = modu.toByteArray();
            if (bmod[0] == 0) {
                byte[] tmp = new byte[bmod.length - 1];
                System.arraycopy(bmod, 1, tmp, 0, tmp.length);
                bmod = tmp;
            }

            byte[] bexpo = expone.toByteArray();
            if (bexpo[0] == 0) {
                byte[] tmp = new byte[bexpo.length - 1];
                System.arraycopy(bexpo, 1, tmp, 0, tmp.length);
                bexpo = tmp;
            }

            System.out.println("");
            System.out.println("expo");
            System.out.println("");
            for (int i=0; i<bexpo.length;i++){
                System.out.print(bexpo[i]);
                System.out.print(",");
            }
            System.out.println("");
            System.out.println("");
            for (int i=0; i<bmod.length;i++){
                System.out.print(bmod[i]);
                System.out.print(",");
            }

            System.out.println("");
            System.out.println("");
            System.out.println("");
            System.out.println("");


            String DatePart = date;
            String[] splittedDate = DatePart.split(" ");
            short day = Short.parseShort(splittedDate[0]);
            short month = Short.parseShort(splittedDate[1]);
            String milenium = splittedDate[2].substring(0, 2);
            String decenium = splittedDate[2].substring(2, 4);
            short mil = Short.parseShort(milenium);
            short dec = Short.parseShort(decenium);

            ByteBuffer buffer = ByteBuffer.allocate(bmod.length + bexpo.length + 1 + 4 + 8);
            buffer.put((byte) 1); //domain
            buffer.position(1);

            buffer.putShort(day); //valid to
            buffer.position(3);
            buffer.putShort(month);
            buffer.position(5);
            buffer.putShort(mil);
            buffer.position(7);
            buffer.putShort(dec);
            buffer.position(9);
            //modulus length
            buffer.putShort((short) bmod.length);
            buffer.position(11);
            //exponent length
            buffer.putShort((short) bexpo.length);
            buffer.position(13);
            //modulus
            buffer.put(bmod);
            buffer.position(13 + bmod.length);
            //exponent
            buffer.put(bexpo);

            buffer.position(0);

            byte[] cert = new byte[buffer.remaining()];
            buffer.get(cert);

            Signature privateSignature = Signature.getInstance("SHA1withRSA");
            privateSignature.initSign(kp.getPrivate());
            privateSignature.update(cert);

            byte[] signature = privateSignature.sign();



            Signature publicSignature = Signature.getInstance("SHA1withRSA");
            publicSignature.initVerify(pubr);
            publicSignature.update(cert);

            //byte[] signatureBytes = Base64.getDecoder().decode(signature);

            System.out.println(publicSignature.verify(signature));

            byte[] signedCert = new byte[signature.length + cert.length];
            System.arraycopy(cert, 0, signedCert, 0, cert.length);
            System.arraycopy(signature, 0, signedCert, cert.length, signature.length);

            String sicert = new String(signedCert, StandardCharsets.US_ASCII);

            for (int i=0; i<signedCert.length;i++){
                System.out.print(signedCert[i]);
                System.out.print(", ");
            }

            System.out.println("");
            System.out.println("signedCert.length");
            System.out.println(signedCert.length);

            System.out.println("");
            System.out.println("cert.length");
            System.out.println(cert.length);

            System.out.println("");
            System.out.println("signature.length");
            System.out.println(signature.length);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static KeyPair getKeyPairFromKeyStore() throws Exception {

        InputStream ins = new FileInputStream("root.jks");

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(ins, "SICKS".toCharArray());   //Keystore password
        KeyStore.PasswordProtection keyPassword =       //Key password
                new KeyStore.PasswordProtection("SICCA".toCharArray());

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("root", keyPassword);

        java.security.cert.Certificate cert = keyStore.getCertificate("root");
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }

    private static Certificate getCertFromKeyStore() throws Exception {


        InputStream ins = new FileInputStream("default.jks");
        //InputStream ins = new FileInputStream("/default.jks");

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(ins, "SICKS".toCharArray());   //Keystore password
        KeyStore.PasswordProtection keyPassword =       //Key password
                new KeyStore.PasswordProtection("SICKS".toCharArray());


        java.security.cert.Certificate cert = keyStore.getCertificate("default1 cert");
        //java.security.cert.Certificate cert = keyStore.getCertificate("default2 cert");

        return cert;
    }

}
