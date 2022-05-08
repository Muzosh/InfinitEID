import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.cert.*;
import java.util.Base64;

/**
 * Created by Nassim on 20/04/2017.
 */
public class MiddlewareComm {
    static int MiddlewarePort =2234;
    private SecretKey symetricKeyFromCard;
    byte[] ivdata = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    IvParameterSpec spec = new IvParameterSpec(ivdata);

    boolean sendCert(String ip, String cert){
        Socket clientSocket = null;
        try {
            clientSocket = new Socket(ip, MiddlewarePort);
            PrintWriter outToServer = new PrintWriter(clientSocket.getOutputStream(), true);
            BufferedReader inFromServer = new BufferedReader(
                    new InputStreamReader(clientSocket.getInputStream()));

            outToServer.println(cert);
            outToServer.flush();

            String Response = null;
            while (Response == null) {
                Response = inFromServer.readLine();
            }



            System.out.println("Middleware Response:" + Response);

            try {
                String enc = getResponse(Response);
                outToServer.println(enc);
            } catch (Exception e) {
                e.printStackTrace();
            }
            Response = null;
            while (Response == null) {
                Response = inFromServer.readLine();
            }
            if (Response.equalsIgnoreCase("authenticated")){
                System.out.println("Athenticated to ID");
                outToServer.println(createChallenge());
            }


        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    String createChallenge() throws Exception{
        SecureRandom random = new SecureRandom();
        byte[] challenge = new byte[16];
        random.nextBytes(challenge);
        Cipher cipherAes = Cipher.getInstance("AES/CBC/NoPadding");
        cipherAes.init(Cipher.ENCRYPT_MODE, symetricKeyFromCard, spec);
        byte[] encryptedBytes = cipherAes.doFinal(challenge);
        String result = com.sun.org.apache.xml.internal.security.utils.Base64.encode(encryptedBytes);
        return result;
    }

    String getResponse(String s) throws Exception{
        String[] res = s.split(" ");
        String AesString = res[0];
        String ChallengeString = res[1];
            byte[] Aesdata = com.sun.org.apache.xml.internal.security.utils.Base64.decode(AesString);
            byte[] Challengedata = com.sun.org.apache.xml.internal.security.utils.Base64.decode(ChallengeString);


            symetricKeyFromCard = new SecretKeySpec(Aesdata, 0, Aesdata.length,"AES");

            Cipher cipherAes = Cipher.getInstance("AES/CBC/NoPadding");
            cipherAes.init(Cipher.DECRYPT_MODE, symetricKeyFromCard, spec);
            byte[] decryptedBytes = cipherAes.doFinal(Challengedata);

            System.out.println("");
            System.out.println("");
            for (int i=0; i < decryptedBytes.length; i++){
                System.out.print(decryptedBytes[i]);
                System.out.print(", ");
            }
        System.out.println("");
        System.out.println("");
            byte last = decryptedBytes[decryptedBytes.length-1];
            decryptedBytes[decryptedBytes.length-1] = (byte) (last + (byte)1);
            cipherAes.init(Cipher.ENCRYPT_MODE, symetricKeyFromCard, spec);
            byte[] encryptedBytes = cipherAes.doFinal(decryptedBytes);
            String result = com.sun.org.apache.xml.internal.security.utils.Base64.encode(encryptedBytes);
            return result;
    }

    String certToString(Certificate c) throws CertificateEncodingException {
        String LINE_SEPERATOR = System.getProperty("line.separator");
        final Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPERATOR.getBytes());
        final byte[] rawCrtText = c.getEncoded();
        final String encodedCertText = new String(encoder.encode(rawCrtText));
        return encodedCertText;
    }

    public static String BytesToString(byte[] c) throws CertificateEncodingException {
        String LINE_SEPERATOR = System.getProperty("line.separator");
        final Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPERATOR.getBytes());
        final byte[] rawCrtText = c;
        final String encodedCertText = new String(encoder.encode(rawCrtText));
        return encodedCertText;
    }

    X509Certificate stringToCert(String c) throws CertificateException {
        final Base64.Decoder decoder = Base64.getMimeDecoder();
        byte[] decoded = decoder.decode(c);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate nxCert = cf.generateCertificate(new ByteArrayInputStream(decoded));
        return (X509Certificate) nxCert;
    }


}
