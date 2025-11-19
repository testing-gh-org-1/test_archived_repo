package com.example.demo;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.File;
import java.io.FileOutputStream;
import java.security.MessageDigest;

// CWE-256: Plaintext Storage of a Password
// CWE-260: Password in Configuration File
// CWE-266: Incorrect Privilege Assignment
// CWE-271: Privilege Dropping / Lowering Errors
// CWE-273: Improper Check for Dropped Privileges
public class PrivilegeAndPasswordVulnerabilities {
    
    // CWE-256: Storing password in plain text
    public void saveUserPassword(String username, String password) {
        // Vulnerable: storing password without hashing
        try {
            FileOutputStream fos = new FileOutputStream("passwords.txt", true);
            String data = username + ":" + password + "\n";
            fos.write(data.getBytes());
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // CWE-256: Password in database without encryption
    public void storePasswordInDB(String username, String password) {
        // Vulnerable: plain text password in database
        String query = "INSERT INTO users (username, password) VALUES ('" + username + "', '" + password + "')";
    }
    
    // CWE-256: Password in memory without clearing
    public boolean authenticateUser(String username, String password) {
        // Vulnerable: password string remains in memory
        String storedPassword = getStoredPassword(username);
        return password.equals(storedPassword);
    }
    
    // CWE-260: Hard-coded password in config
    public void loadConfiguration() {
        // Vulnerable: password in configuration
        String dbPassword = "admin123";
        String apiKey = "sk_live_1234567890abcdef";
        // Use credentials
    }
    
    // CWE-260: Password in properties file
    public void saveConfig(String password) {
        try {
            FileOutputStream fos = new FileOutputStream("config.properties");
            // Vulnerable: storing password in config file
            String config = "db.password=" + password + "\n";
            fos.write(config.getBytes());
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // CWE-266: File created with overly permissive permissions
    public void createSecureFile(String filename, String content) {
        try {
            File file = new File(filename);
            // Vulnerable: file permissions not restricted
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(content.getBytes());
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // CWE-266: Granting excessive privileges
    public void assignUserRole(HttpServletRequest request) {
        HttpSession session = request.getSession();
        // Vulnerable: assigning admin role without proper checks
        session.setAttribute("role", "admin");
        session.setAttribute("permissions", "ALL");
    }
    
    // CWE-271: Failing to drop privileges
    public void performPrivilegedOperation() {
        // Vulnerable: running with elevated privileges unnecessarily
        try {
            // Elevated operation
            Runtime.getRuntime().exec("sudo some-command");
            // Should drop privileges here but doesn't
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // CWE-273: Not verifying privilege drop
    public void dropPrivileges() {
        try {
            // Attempt to drop privileges
            System.setProperty("user.privileges", "low");
            // Vulnerable: not checking if privileges were actually dropped
            performSensitiveOperation();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // CWE-266: Improper permission check
    public boolean canAccessResource(String userId, String resourceId) {
        // Vulnerable: weak permission check
        return userId != null;
    }
    
    // CWE-256: Password visible in logs
    public void logAuthAttempt(String username, String password) {
        // Vulnerable: logging password
        System.out.println("Login attempt: user=" + username + ", pass=" + password);
    }
    
    // CWE-260: API key in source code
    private static final String API_SECRET = "sk_live_51HxYzAbCdEfGhIjKlMnOpQr";
    
    public void callAPI() {
        // Vulnerable: using hard-coded API key
        String request = "Authorization: Bearer " + API_SECRET;
    }
    
    private String getStoredPassword(String username) {
        return "stored_password_123";
    }
    
    private void performSensitiveOperation() {
        // Sensitive operation
    }
}
