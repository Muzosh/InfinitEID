package be.msec.client;

/**
 * Created by Nassim on 20/04/2017.
 */


import java.io.*;
import java.net.*;


public class SPRequestTest {
        public static void main(String argv[]) throws Exception
        {
            String sentence;
            String modifiedSentence;
            BufferedReader inFromUser = new BufferedReader( new InputStreamReader(System.in));
            Socket clientSocket = new Socket("localhost", 2234);
            DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
            BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            sentence = inFromUser.readLine();
            outToServer.writeBytes(sentence + '\n');
            modifiedSentence = inFromServer.readLine();
            System.out.println("FROM SERVER: " + modifiedSentence);
            //clientSocket.close();
        }
}
