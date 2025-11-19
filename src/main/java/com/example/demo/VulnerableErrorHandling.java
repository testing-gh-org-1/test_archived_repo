package com.example.demo;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// CWE-209: Generation of Error Message Containing Sensitive Information
public class VulnerableErrorHandling {
    
    private static final String DB_URL = "jdbc:mysql://localhost:3306/secretdb";
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "super_secret_password";
    
    public void connectToDatabase(HttpServletResponse response) {
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            // Do something with connection
            conn.close();
        } catch (SQLException e) {
            // CWE-209: Exposing sensitive information in error messages
            try {
                response.getWriter().println("Database connection failed: " + e.getMessage());
                response.getWriter().println("Connection URL: " + DB_URL);
                response.getWriter().println("Stack trace: " + e.toString());
                e.printStackTrace(response.getWriter());
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }
    
    public void processUserLogin(String username, String password, HttpServletResponse response) {
        try {
            if (username == null || username.isEmpty()) {
                throw new IllegalArgumentException("Username cannot be empty");
            }
            if (password == null || password.length() < 8) {
                throw new IllegalArgumentException("Password must be at least 8 characters. Received: " + password);
            }
            // Authenticate user
        } catch (IllegalArgumentException e) {
            // CWE-209: Exposing sensitive data in error message
            try {
                response.getWriter().println("Login error: " + e.getMessage());
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }
    
    public String authenticateUser(String username, String password) {
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            // Authentication logic here
            conn.close();
            return "Success";
        } catch (SQLException e) {
            // CWE-209: Detailed error message with system information
            return "Authentication failed: " + e.getMessage() + 
                   " | SQL State: " + e.getSQLState() + 
                   " | Error Code: " + e.getErrorCode() +
                   " | Database: " + DB_URL;
        }
    }
}
