package com.example.demo;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

// CWE-328: Use of Weak Hash
public class WeakHashFunction {
    
    // CWE-328: Using MD5 for password hashing
    public String createUserPasswordHash(String password) {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] hash = md5.digest(password.getBytes());
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    
    // CWE-328: Using SHA-1 for sensitive data
    public String hashCreditCard(String creditCardNumber) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] hash = sha1.digest(creditCardNumber.getBytes());
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    
    // CWE-328: Using MD5 for token generation
    public String generateAuthToken(String username, long timestamp) {
        try {
            String data = username + ":" + timestamp;
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] hash = md5.digest(data.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    
    // CWE-328: Using SHA-1 for session ID
    public String createSessionId(String userId) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA1");
            String sessionData = userId + System.currentTimeMillis();
            byte[] hash = sha1.digest(sessionData.getBytes());
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    
    // CWE-328: Using MD5 for API key hashing
    public String hashApiKey(String apiKey) {
        try {
            MessageDigest md = MessageDigest.getInstance("md5");
            byte[] digest = md.digest(apiKey.getBytes());
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }
    
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
    
    public static void main(String[] args) {
        WeakHashFunction hashFunc = new WeakHashFunction();
        
        // Demonstrating weak hash usage
        String password = "userPassword123";
        String hashedPassword = hashFunc.createUserPasswordHash(password);
        System.out.println("Password Hash (MD5): " + hashedPassword);
        
        String creditCard = "4532-1234-5678-9010";
        String hashedCC = hashFunc.hashCreditCard(creditCard);
        System.out.println("Credit Card Hash (SHA-1): " + hashedCC);
        
        String token = hashFunc.generateAuthToken("john.doe", System.currentTimeMillis());
        System.out.println("Auth Token (MD5): " + token);
    }
}
