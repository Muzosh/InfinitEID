import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;


/**
 * Created by Nassim on 20/04/2017.
 */
public class eGov extends javax.servlet.http.HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html");
        response.setCharacterEncoding("UTF-8");

        try (PrintWriter writer = response.getWriter()) {
            String clientIp = request.getRemoteAddr();

            writer.println("<!DOCTYPE html><html>");
            writer.println("<head>");
            writer.println("<meta charset=\"UTF-8\" />");
            writer.println("<Title>eGov Service Providors Demo</Title>");
            writer.println("</head>");
            writer.println("<body>");

            writer.println("<h1>These are the eGOV services.</h1>");

            writer.println("</body>");
            writer.println("</html>");
        }
    }
}
