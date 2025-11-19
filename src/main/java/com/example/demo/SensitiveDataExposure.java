package com.example.demo;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Logger;

// CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere
public class SensitiveDataExposure {
    
    private static final Logger logger = Logger.getLogger(SensitiveDataExposure.class.getName());
    private String apiKey = "fake_api_key_1234567890abcdefghij";
    private String databasePassword = "MyS3cr3tP@ssw0rd!";
    
    public void handleRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        // CWE-497: Exposing sensitive system information
        response.setContentType("text/html");
        response.getWriter().println("<html><body>");
        response.getWriter().println("<h1>System Information</h1>");
        response.getWriter().println("<p>Java Version: " + System.getProperty("java.version") + "</p>");
        response.getWriter().println("<p>OS Name: " + System.getProperty("os.name") + "</p>");
        response.getWriter().println("<p>User Home: " + System.getProperty("user.home") + "</p>");
        response.getWriter().println("<p>User Directory: " + System.getProperty("user.dir") + "</p>");
        response.getWriter().println("<p>API Key: " + apiKey + "</p>");
        response.getWriter().println("<p>Database Password: " + databasePassword + "</p>");
        response.getWriter().println("</body></html>");
    }
    
    public void logSensitiveData(String userId, String creditCard, String ssn) {
        // CWE-497: Logging sensitive information
        logger.info("User login attempt - UserID: " + userId);
        logger.info("Credit Card: " + creditCard);
        logger.info("SSN: " + ssn);
        logger.info("API Key used: " + apiKey);
    }
    
    public String getSystemInfo() {
        // CWE-497: Returning sensitive system information
        StringBuilder info = new StringBuilder();
        info.append("System Properties:\n");
        info.append("Java Home: ").append(System.getProperty("java.home")).append("\n");
        info.append("Java Classpath: ").append(System.getProperty("java.class.path")).append("\n");
        info.append("User Name: ").append(System.getProperty("user.name")).append("\n");
        info.append("Temp Directory: ").append(System.getProperty("java.io.tmpdir")).append("\n");
        info.append("API Key: ").append(apiKey).append("\n");
        info.append("DB Password: ").append(databasePassword).append("\n");
        return info.toString();
    }
    
    public void debugMode(HttpServletResponse response) throws IOException {
        // CWE-497: Exposing internal system state
        response.getWriter().println("Debug Mode Active");
        response.getWriter().println("Environment Variables:");
        System.getenv().forEach((key, value) -> {
            try {
                response.getWriter().println(key + "=" + value);
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    }
}
