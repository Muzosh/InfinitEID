package be.msec.client;


import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

import static be.msec.client.SPRequestServer.log_loc;


public class SPRequestServer  {
    static public PrintStream log_loc = System.out;
    static int ServerPort =2234;
    public static void main(String[] args) throws Exception {
        ServerSocket m_ServerSocket = new ServerSocket(ServerPort);
        int id = 0;
        while (true) {
            Socket clientSocket = m_ServerSocket.accept();
            ClientServiceThread cliThread = new ClientServiceThread(clientSocket, id++);
            cliThread.start();
        }
    }
}

class ClientServiceThread extends Thread {
    Socket clientSocket;
    int clientID = -1;
    boolean running = true;

    ClientServiceThread(Socket s, int i) {
        clientSocket = s;
        clientID = i;
    }

    public void run() {
        log_loc.println("Accepted Client : ID - " + clientID + " : Address - "
                + clientSocket.getInetAddress().getHostName());
        try {
        	PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        	BufferedReader in = new BufferedReader( new InputStreamReader(clientSocket.getInputStream()));
            while (running) {
                String clientCommand = in.readLine();
                //log_loc.println("Client Says :" + clientCommand);
                JSONParser parser = new JSONParser();
                JSONObject req = (JSONObject) parser.parse(clientCommand);
                Client iDClient = new Client();
                String Response = Client.handleJSONSPauthenticate(req);
                out.println(Response);
                out.flush();
              
                clientCommand = in.readLine();
                boolean authenticated = Client.handleJSONSPauthenticateFinal(req,clientCommand);
                if (authenticated){
                	out.println("authenticated");
                	clientCommand = in.readLine();
                	Client.authenticate(req,clientCommand);
                }
                log_loc.println(req.toJSONString());
                if (clientCommand.equalsIgnoreCase("quit")) {
                    running = false;
                    log_loc.print("Stopping client thread for client : " + clientID);
                } else {
                    out.println(clientCommand);
                    out.flush();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}