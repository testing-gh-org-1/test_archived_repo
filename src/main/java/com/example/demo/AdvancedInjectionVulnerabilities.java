package com.example.demo;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// CWE-91: XML Injection (aka Blind XPath Injection)
// CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')
// CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
// CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')
public class AdvancedInjectionVulnerabilities {
    
    // CWE-91: XML Injection
    public String createXMLUser(String username, String email, String role) {
        // Vulnerable: XML injection without escaping
        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.append("<user>\n");
        xml.append("  <username>").append(username).append("</username>\n");
        xml.append("  <email>").append(email).append("</email>\n");
        xml.append("  <role>").append(role).append("</role>\n");
        xml.append("</user>");
        return xml.toString();
    }
    
    // CWE-91: Blind XPath Injection
    public String xpathQuery(String username) {
        // Vulnerable: XPath injection
        String query = "//users/user[username='" + username + "']";
        return query;
    }
    
    // CWE-93: CRLF Injection in logs
    public void logUserAction(String username, String action, java.util.logging.Logger logger) {
        // Vulnerable: CRLF injection in log messages
        logger.info("User: " + username + " performed action: " + action);
    }
    
    // CWE-93: CRLF Injection in file writing
    public void writeToFile(String data, java.io.FileWriter writer) throws IOException {
        // Vulnerable: newline injection
        writer.write("Data: " + data + "\n");
    }
    
    // CWE-95: Eval injection using ScriptEngine
    public Object evaluateUserScript(String script) {
        try {
            javax.script.ScriptEngineManager manager = new javax.script.ScriptEngineManager();
            javax.script.ScriptEngine engine = manager.getEngineByName("JavaScript");
            // Vulnerable: evaluating user-provided code
            return engine.eval(script);
        } catch (Exception e) {
            return null;
        }
    }
    
    // CWE-95: Dynamic code evaluation
    public void executeUserCode(String code) {
        try {
            // Vulnerable: executing arbitrary user code
            javax.script.ScriptEngineManager manager = new javax.script.ScriptEngineManager();
            javax.script.ScriptEngine engine = manager.getEngineByName("groovy");
            engine.eval(code);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // CWE-113: HTTP Response Splitting
    public void setCustomHeader(HttpServletRequest request, HttpServletResponse response) {
        String value = request.getParameter("customValue");
        // Vulnerable: CRLF in HTTP header
        response.setHeader("X-Custom-Header", value);
    }
    
    // CWE-113: Response splitting in cookie
    public void setUserCookie(HttpServletRequest request, HttpServletResponse response) {
        String userData = request.getParameter("userData");
        // Vulnerable: user data in Set-Cookie header
        response.addHeader("Set-Cookie", "userData=" + userData);
    }
    
    // CWE-113: HTTP header injection
    public void redirectWithCustomHeader(HttpServletResponse response, String location) throws IOException {
        // Vulnerable: location header injection
        response.setHeader("Location", location);
        response.setStatus(302);
    }
}
