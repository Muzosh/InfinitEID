package com.company;


import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;


public class Main {


   static int intSSLport = 4443; // Port where the SSL Server needs to listen for new requests from the client

    public static void main(String[] args) {
        System.setProperty("javax.net.ssl.keyStoreType","JCEKS");
        System.setProperty("javax.net.ssl.keyStorePassword", "SICKS");
        System.setProperty("javax.net.ssl.keyStore", "serverKS.jceks");
        SSLServerSocket sslServerSocket = null;
        SSLSocket sslSocket = null;

        try {
            // Initialize the Server Socket
            SSLServerSocketFactory sslServerSocketfactory = (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();
            sslServerSocket = (SSLServerSocket)sslServerSocketfactory.createServerSocket(intSSLport);

        } catch (IOException e) {
            e.printStackTrace();
        }
        while (true) {
            try {
                 sslSocket = (SSLSocket)sslServerSocket.accept();
            } catch (IOException e) {
                e.printStackTrace();
            }
            // new thread for a client

            new SSLServerThread(sslSocket).start();
        }
    }
}

