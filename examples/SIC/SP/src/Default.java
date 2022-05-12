import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;

/**
 * Created by Nassim on 20/04/2017.
 */
@WebServlet(name = "Default")
public class Default extends HttpServlet {


    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String clientIp = request.getRemoteAddr();

        String[] selectedService = request.getParameterValues("serviceSelection");
        String[] selectedData = request.getParameterValues("eIDdataSelector");
        ArrayList<String> sd=new ArrayList<String>();

        for(String s :selectedData){  //stupid stuff to use a parser
            sd.add("\""+s+"\"");
        }
        String service = selectedService[0];
        String servicekey = null;

        System.out.println(service);
        System.out.println("Selected eID Data: "+ sd.toString());

        JSONObject jo = new JSONObject();
        JSONParser parser = new JSONParser();
        JSONArray eIDData= null;
        try {
            eIDData = (JSONArray)parser.parse(sd.toString());
        } catch (ParseException e) {
            e.printStackTrace();
        }
        MiddlewareComm comm = new MiddlewareComm();


        switch (service) {
            case "firstExample":
                servicekey = "default1";
                break;
            case "secondExample":
                servicekey = "default2";
                break;
        }

        Certificate cert = null;
        String sCert = null;
        try {
            cert = getCertFromKeyStore(servicekey);
            sCert = comm.certToString(cert);
        }
        catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        catch (Exception e) {
            e.printStackTrace();
        }


        jo.put("selectedData", eIDData);
        jo.put("domain","Default");
        jo.put("service",service);
        jo.put("cert", getCert());
        // jo.put("cert", sCert);



        // System.out.println("cert: " +sCert);
        System.out.println(jo.toJSONString());
        comm.sendCert(clientIp,jo.toJSONString());



        response.setContentType("text/html");
        response.setCharacterEncoding("UTF-8");


        PrintWriter writer = response.getWriter();
        writer.println("<!DOCTYPE html><html>");
        writer.println("<head>");
        writer.println("<meta charset=\"UTF-8\" />");
        writer.println("<Title>Default Service Providors Demo</Title>");
        writer.println("</head>");
        writer.println("<body>");

        writer.println("<h1>Sent request for "+selectedService[0]+" </h1>");
        writer.println("</body>");
        writer.println("</html>");



    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html");
        response.setCharacterEncoding("UTF-8");


        try (PrintWriter writer = response.getWriter()) {
            String clientIp = request.getRemoteAddr();
            writer.println("<!DOCTYPE html><html>");
            writer.println("<head>");
            writer.println("<meta charset=\"UTF-8\" />");
            writer.println("<Title>Default Service Providors Demo</Title>");
            writer.println("</head>");
            writer.println("<body>");

            writer.println("<h1>These are the Default services.</h1>");
            writer.println("<h4>Please select a service.</h4>");
            writer.println("<Form method=\"post\">");
            writer.println("<input type=\"checkbox\" name=\"serviceSelection\" value=\"firstExample\">example 1<br>");
            writer.println("<input type=\"checkbox\" name=\"serviceSelection\" value=\"secondExample\">example 2<br>");
            writer.println("<br><br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"name\">Name<br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"address\">Address<br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"country\">Country<br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"birth_date\">Birth Date<br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"age\">Age<br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"gender\">Gender<br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"picture\">Picture<br>");
            writer.println("<input type=\"submit\" name=\"submit\" value=\"Submit\">");
            writer.println("</Form>");
            writer.println("</body>");
            writer.println("</html>");
        }
    }


    private KeyPair getKeyPairFromKeyStore(String service) throws Exception {

        ServletContext context = this.getServletContext();

        InputStream ins = context.getResourceAsStream("/WEB-INF/default.jks");

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(ins, "SICKS".toCharArray());   //Keystore password
        KeyStore.PasswordProtection keyPassword =       //Key password
                new KeyStore.PasswordProtection("SICKS".toCharArray());

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(service+"pk", keyPassword);

        java.security.cert.Certificate cert = keyStore.getCertificate(service+" cert");
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }

    private String getCert( ) {
        byte[] cert = new byte[]{1,0,19,0,4,0,20,0,27,0,64,0,3,-44,104,46,-36,6,124,-72,35,-75,3,-78,60,66,20,-10,74,18,70,10,5,10,-117,16,-48,-88,108,-64,-124,95,117,-71,40,108,-118,-86,-24,6,104,-127,119,20,-53,67,89,92,-3,6,124,-122,-6,-47,-103,-66,-34,-125,70,121,17,89,21,-48,71,68,7,1,0,1,117,27,-126,12,-120,107,-116,75,-103,-3,94,-65,-17,32,-90,-117,-5,50,-69,106,72,53,-20,-4,17,-71,-92,109,70,-74,-81,122,-77,101,99,102,123,-99,-30,108,-43,54,-24,126,-106,-91,41,65,57,59,-12,-87,16,-34,-96,-71,61,-86,52,-86,-102,-102,119,124};
        String encoded = null;
        try {
            encoded = MiddlewareComm.BytesToString(cert);
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }




        return encoded;
    }

    private Certificate getCertFromKeyStore(String service) throws Exception {



        ServletContext context = this.getServletContext();

        InputStream ins = context.getResourceAsStream("/WEB-INF/default.jks");
        //InputStream ins = new FileInputStream("/default.jks");

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(ins, "SICKS".toCharArray());   //Keystore password
        KeyStore.PasswordProtection keyPassword =       //Key password
                new KeyStore.PasswordProtection("SICKS".toCharArray());


        java.security.cert.Certificate cert = keyStore.getCertificate(service+" cert");

        return cert;
    }
}
