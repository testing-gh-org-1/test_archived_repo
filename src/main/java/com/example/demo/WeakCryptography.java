package com.example.demo;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
public class WeakCryptography {
    
    // CWE-327: Using MD5 hash algorithm (broken)
    public String hashPasswordMD5(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // CWE-327: Using SHA-1 hash algorithm (weak)
    public String hashPasswordSHA1(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] hash = md.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // CWE-327: Using DES encryption (insecure)
    public String encryptWithDES(String data, String key) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "DES");
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // CWE-327: Using RC4 encryption (broken)
    public String encryptWithRC4(String data) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("RC4");
            keyGen.init(128);
            SecretKey secretKey = keyGen.generateKey();
            Cipher cipher = Cipher.getInstance("RC4");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // CWE-327: Using ECB mode (insecure)
    public String encryptWithAESECB(String data, byte[] key) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    public static void main(String[] args) {
        WeakCryptography crypto = new WeakCryptography();
        String password = "MySecretPassword123!";
        
        System.out.println("MD5 Hash: " + crypto.hashPasswordMD5(password));
        System.out.println("SHA-1 Hash: " + crypto.hashPasswordSHA1(password));
        System.out.println("DES Encrypted: " + crypto.encryptWithDES("sensitive data", "12345678"));
    }
}
