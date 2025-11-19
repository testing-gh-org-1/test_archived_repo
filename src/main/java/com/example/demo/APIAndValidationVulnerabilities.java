package com.example.demo;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;

// CWE-185: Incorrect Regular Expression
// CWE-221: Information Loss or Omission
// CWE-227: API Abuse
// CWE-248: Uncaught Exception
// CWE-252: Unchecked Return Value
public class APIAndValidationVulnerabilities {
    
    // CWE-185: Incorrect regex for email validation
    public boolean validateEmail(String email) {
        // Vulnerable: weak regex, doesn't validate properly
        return email.matches(".*@.*");
    }
    
    // CWE-185: Regex that allows bypasses
    public boolean validateURL(String url) {
        // Vulnerable: incomplete URL validation
        return url.matches("http://.*");
    }
    
    // CWE-185: Overly permissive regex
    public boolean validatePhoneNumber(String phone) {
        // Vulnerable: accepts invalid formats
        return phone.matches("\\d+");
    }
    
    // CWE-221: Information loss in conversion
    public int convertToInt(String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            // Vulnerable: error information lost
            return 0;
        }
    }
    
    // CWE-221: Truncating error details
    public String processData(String data) {
        try {
            // Some processing
            return data.toUpperCase();
        } catch (Exception e) {
            // Vulnerable: exception details lost
            return "error";
        }
    }
    
    // CWE-227: Incorrect use of equals() with arrays
    public boolean compareArrays(byte[] arr1, byte[] arr2) {
        // Vulnerable: using == instead of Arrays.equals()
        return arr1 == arr2;
    }
    
    // CWE-227: Misuse of String.replace()
    public String sanitizeInput(String input) {
        // Vulnerable: replace() only replaces first occurrence
        return input.replace("<script>", "");
    }
    
    // CWE-227: Incorrect thread synchronization
    private int counter = 0;
    
    public void incrementCounter() {
        // Vulnerable: not synchronized
        counter++;
    }
    
    // CWE-248: Uncaught exception in file operations
    public String readFile(String filename) {
        // Vulnerable: IOException not caught
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(filename);
            // Read file
            return "content";
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    // Exception in finally block
                }
            }
        }
    }
    
    // CWE-248: Uncaught RuntimeException
    public void processUserInput(String input) {
        // Vulnerable: NullPointerException not handled
        int length = input.length();
    }
    
    // CWE-252: Ignoring return value of delete()
    public void deleteFile(String filename) {
        File file = new File(filename);
        // Vulnerable: not checking if delete succeeded
        file.delete();
    }
    
    // CWE-252: Ignoring return value of mkdir()
    public void createDirectory(String path) {
        File dir = new File(path);
        // Vulnerable: not checking if mkdir succeeded
        dir.mkdirs();
    }
    
    // CWE-252: Ignoring return value from read()
    public void readData(FileInputStream fis) throws IOException {
        byte[] buffer = new byte[1024];
        // Vulnerable: not checking bytes actually read
        fis.read(buffer);
    }
    
    // CWE-252: Ignoring connection errors
    public void connectToDatabase(String url) {
        try {
            Connection conn = DriverManager.getConnection(url);
            // Vulnerable: not checking if connection is valid
        } catch (Exception e) {
            // Ignoring exception
        }
    }
}
