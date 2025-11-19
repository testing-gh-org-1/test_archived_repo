package com.example.demo;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// CWE-116: Improper Encoding or Escaping of Output
// CWE-117: Improper Output Neutralization for Logs
public class ImproperEncodingVulnerabilities {
    
    // CWE-116: Missing HTML encoding
    public void displayUserInput(HttpServletResponse response, String userInput) throws IOException {
        // Vulnerable: no HTML encoding
        response.getWriter().println("<div>" + userInput + "</div>");
    }
    
    // CWE-116: Missing URL encoding
    public String createURL(String param) {
        // Vulnerable: no URL encoding
        return "https://example.com/search?q=" + param;
    }
    
    // CWE-116: Missing JavaScript encoding
    public void embedInScript(HttpServletResponse response, String data) throws IOException {
        // Vulnerable: no JavaScript escaping
        response.getWriter().println("<script>");
        response.getWriter().println("var userData = '" + data + "';");
        response.getWriter().println("</script>");
    }
    
    // CWE-116: Missing attribute encoding
    public String createInputField(String value) {
        // Vulnerable: no attribute encoding
        return "<input type='text' value='" + value + "'>";
    }
    
    // CWE-117: Log injection
    public void logUserActivity(String username, String activity, java.util.logging.Logger logger) {
        // Vulnerable: log forging
        logger.info("User " + username + " performed: " + activity);
    }
    
    // CWE-117: Log injection with user-controlled data
    public void logLoginAttempt(HttpServletRequest request, java.util.logging.Logger logger) {
        String username = request.getParameter("username");
        String ip = request.getRemoteAddr();
        // Vulnerable: log injection possible
        logger.warning("Failed login attempt for user: " + username + " from IP: " + ip);
    }
    
    // CWE-117: Multiline log injection
    public void logError(String errorMessage, java.util.logging.Logger logger) {
        // Vulnerable: newline injection in logs
        logger.severe("Error occurred: " + errorMessage);
    }
    
    // CWE-116: Missing SQL encoding
    public String buildQuery(String searchTerm) {
        // Vulnerable: no SQL escaping
        return "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
    }
    
    // CWE-116: Missing JSON encoding
    public String createJSONResponse(String message, String status) {
        // Vulnerable: no JSON escaping
        return "{\"message\": \"" + message + "\", \"status\": \"" + status + "\"}";
    }
    
    // CWE-117: Stack trace in logs
    public void logException(Exception e, java.util.logging.Logger logger) {
        // Vulnerable: exposing sensitive stack trace in logs
        logger.severe("Exception: " + e.toString());
        e.printStackTrace();
    }
}
