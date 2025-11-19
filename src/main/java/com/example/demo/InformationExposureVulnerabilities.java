package com.example.demo;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

// CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
// CWE-203: Observable Discrepancy
// CWE-208: Observable Timing Discrepancy
public class InformationExposureVulnerabilities {
    
    // CWE-200: Exposing internal paths
    public void displayErrorPath(HttpServletResponse response, Exception e) throws IOException {
        // Vulnerable: exposing file system paths
        response.getWriter().println("Error in file: " + e.getStackTrace()[0].getFileName());
        response.getWriter().println("Line: " + e.getStackTrace()[0].getLineNumber());
    }
    
    // CWE-200: Exposing database structure
    public void handleSQLError(SQLException e, HttpServletResponse response) throws IOException {
        // Vulnerable: exposing database details
        response.getWriter().println("SQL Error: " + e.getMessage());
        response.getWriter().println("SQL State: " + e.getSQLState());
        response.getWriter().println("Error Code: " + e.getErrorCode());
    }
    
    // CWE-200: Exposing configuration details
    public void showConfig(HttpServletResponse response) throws IOException {
        // Vulnerable: exposing system configuration
        response.getWriter().println("Java Version: " + System.getProperty("java.version"));
        response.getWriter().println("OS: " + System.getProperty("os.name"));
        response.getWriter().println("User: " + System.getProperty("user.name"));
        response.getWriter().println("Working Dir: " + System.getProperty("user.dir"));
    }
    
    // CWE-200: Exposing internal IPs
    public void displayServerInfo(HttpServletResponse response) throws IOException {
        // Vulnerable: exposing internal network information
        try {
            java.net.InetAddress localhost = java.net.InetAddress.getLocalHost();
            response.getWriter().println("Server IP: " + localhost.getHostAddress());
            response.getWriter().println("Hostname: " + localhost.getHostName());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // CWE-203: Observable response discrepancy in authentication
    public boolean authenticateUser(String username, String password) {
        // Vulnerable: different error messages reveal user existence
        if (!userExists(username)) {
            System.out.println("User not found");
            return false;
        }
        if (!checkPassword(username, password)) {
            System.out.println("Invalid password");
            return false;
        }
        return true;
    }
    
    // CWE-203: Username enumeration
    public String checkUsername(String username) {
        // Vulnerable: reveals if username exists
        if (userExists(username)) {
            return "Username already taken";
        }
        return "Username available";
    }
    
    // CWE-208: Timing attack in password comparison
    public boolean validatePassword(String provided, String stored) {
        // Vulnerable: timing-based attack possible
        return provided.equals(stored);
    }
    
    // CWE-208: Timing discrepancy in authentication
    public boolean authenticateWithTiming(String username, String password) {
        // Vulnerable: different execution time for valid vs invalid users
        String storedPassword = lookupPassword(username); // Slow DB lookup
        if (storedPassword == null) {
            return false; // Fast return
        }
        return storedPassword.equals(password); // Slower comparison
    }
    
    // CWE-200: Exposing version information
    public void showVersionInfo(HttpServletResponse response) throws IOException {
        // Vulnerable: exposing software versions
        response.getWriter().println("Application Version: 1.2.3");
        response.getWriter().println("Framework: Spring 5.3.0");
        response.getWriter().println("Database: MySQL 8.0.25");
    }
    
    // CWE-200: Exposing exception details
    public void handleException(Exception e, HttpServletResponse response) throws IOException {
        // Vulnerable: full stack trace to user
        response.setContentType("text/html");
        response.getWriter().println("<h1>Error</h1>");
        response.getWriter().println("<pre>");
        e.printStackTrace(response.getWriter());
        response.getWriter().println("</pre>");
    }
    
    private boolean userExists(String username) {
        return username != null && !username.isEmpty();
    }
    
    private boolean checkPassword(String username, String password) {
        return password != null && password.length() > 8;
    }
    
    private String lookupPassword(String username) {
        try {
            Thread.sleep(100); // Simulate DB lookup
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return "stored_password";
    }
}
