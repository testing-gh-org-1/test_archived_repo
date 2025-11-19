package com.example.demo;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

// CWE-311: Missing Encryption of Sensitive Data
// CWE-312: Cleartext Storage of Sensitive Information
// CWE-315: Cleartext Storage of Sensitive Information in a Cookie
// CWE-319: Cleartext Transmission of Sensitive Information
// CWE-326: Inadequate Encryption Strength
public class CryptographicStorageVulnerabilities {
    
    // CWE-312: Storing sensitive data in cleartext
    public void saveCreditCard(String cardNumber, String cvv, String expiryDate) {
        try {
            FileOutputStream fos = new FileOutputStream("payment_data.txt");
            // Vulnerable: storing credit card in cleartext
            String data = "Card: " + cardNumber + ", CVV: " + cvv + ", Expiry: " + expiryDate + "\n";
            fos.write(data.getBytes());
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // CWE-312: Cleartext storage of SSN
    public void storePersonalInfo(String name, String ssn, String dateOfBirth) {
        try {
            FileOutputStream fos = new FileOutputStream("personal_info.txt");
            // Vulnerable: storing SSN without encryption
            String data = name + "," + ssn + "," + dateOfBirth + "\n";
            fos.write(data.getBytes());
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // CWE-315: Sensitive data in cookie without encryption
    public void storeSessionData(HttpServletResponse response, String userId, String accountBalance) {
        // Vulnerable: storing sensitive data in cleartext cookie
        Cookie userCookie = new Cookie("userId", userId);
        Cookie balanceCookie = new Cookie("balance", accountBalance);
        response.addCookie(userCookie);
        response.addCookie(balanceCookie);
    }
    
    // CWE-315: Credit card in cookie
    public void storeCreditCardInCookie(HttpServletResponse response, String cardNumber) {
        // Vulnerable: credit card number in cookie
        Cookie card = new Cookie("paymentMethod", cardNumber);
        card.setMaxAge(3600);
        response.addCookie(card);
    }
    
    // CWE-319: Transmitting password over HTTP
    public void sendPasswordOverHTTP(String username, String password) throws IOException {
        // Vulnerable: sending credentials over unencrypted connection
        java.net.URL url = new java.net.URL("http://example.com/login");
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        
        String data = "username=" + username + "&password=" + password;
        conn.getOutputStream().write(data.getBytes());
    }
    
    // CWE-319: Sending API key in cleartext
    public void sendAPIKey(String apiKey) throws IOException {
        // Vulnerable: transmitting API key over HTTP
        java.net.URL url = new java.net.URL("http://api.example.com/data");
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
        conn.setRequestProperty("Authorization", "Bearer " + apiKey);
    }
    
    // CWE-311: Missing encryption for database password
    public String getDatabaseConnection() {
        // Vulnerable: password stored in cleartext
        String dbPassword = "SuperSecret123!";
        return "jdbc:mysql://localhost:3306/mydb?user=admin&password=" + dbPassword;
    }
    
    // CWE-326: Using weak 56-bit DES key
    public byte[] encryptWithWeakKey(String data) {
        try {
            // Vulnerable: DES with 56-bit key (inadequate strength)
            byte[] keyBytes = "weakkey1".getBytes(); // 56-bit effective key
            SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // CWE-326: Short AES key (128-bit when 256-bit recommended)
    public byte[] encryptWithShortKey(String data) {
        try {
            // Vulnerable: using 128-bit key instead of 256-bit
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128); // Should be 256 for strong encryption
            SecretKey key = keyGen.generateKey();
            
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // CWE-312: Logging sensitive data
    public void logUserCredentials(String username, String password, String creditCard) {
        // Vulnerable: logging sensitive information
        System.out.println("Login attempt - User: " + username + ", Pass: " + password);
        System.out.println("Payment method: " + creditCard);
    }
    
    // CWE-311: Storing API keys without encryption
    public void saveAPIKey(String serviceName, String apiKey) {
        try {
            FileOutputStream fos = new FileOutputStream("api_keys.txt", true);
            // Vulnerable: storing API keys in cleartext
            String data = serviceName + "=" + apiKey + "\n";
            fos.write(data.getBytes());
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // CWE-319: Sending health data over HTTP
    public void transmitHealthData(String patientId, String diagnosis, String medications) throws IOException {
        // Vulnerable: transmitting PHI over unencrypted connection
        java.net.URL url = new java.net.URL("http://hospital.example.com/records");
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        
        String data = "patient=" + patientId + "&diagnosis=" + diagnosis + "&meds=" + medications;
        conn.getOutputStream().write(data.getBytes());
    }
    
    // CWE-326: Using RC4 (broken cipher)
    public byte[] encryptWithRC4(String data, String password) {
        try {
            // Vulnerable: RC4 is broken and should not be used
            SecretKeySpec key = new SecretKeySpec(password.getBytes(), "RC4");
            Cipher cipher = Cipher.getInstance("RC4");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // CWE-315: Session token in cookie without Secure flag
    public void createInsecureSessionCookie(HttpServletResponse response, String sessionToken) {
        Cookie session = new Cookie("JSESSIONID", sessionToken);
        // Vulnerable: no Secure flag, no HttpOnly flag
        session.setMaxAge(1800);
        response.addCookie(session);
    }
}
