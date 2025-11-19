package com.example.demo;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

// CWE-327: Use of Broken or Risky Cryptographic Algorithm (Additional Examples)
// CWE-328: Use of Weak Hash (Additional Examples)
public class AdditionalCryptographicVulnerabilities {
    
    // CWE-327: Using DES with static key
    public byte[] encryptWithStaticDES(String data) {
        try {
            byte[] keyBytes = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
            SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // CWE-327: Using 3DES (deprecated)
    public byte[] encryptWith3DES(String data, byte[] keyBytes) {
        try {
            // Vulnerable: 3DES is deprecated and considered weak
            SecretKeySpec key = new SecretKeySpec(keyBytes, "DESede");
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // CWE-327: AES with static IV
    public byte[] encryptWithStaticIV(String data, SecretKey key) {
        try {
            // Vulnerable: using static IV
            byte[] staticIV = new byte[16]; // All zeros
            IvParameterSpec ivSpec = new IvParameterSpec(staticIV);
            
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            return cipher.doFinal(data.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // CWE-327: Using Blowfish (64-bit block size, vulnerable to birthday attacks)
    public byte[] encryptWithBlowfish(String data, byte[] keyBytes) {
        try {
            // Vulnerable: Blowfish has 64-bit blocks
            SecretKeySpec key = new SecretKeySpec(keyBytes, "Blowfish");
            Cipher cipher = Cipher.getInstance("Blowfish");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // CWE-328: Using MD5 for file integrity
    public String calculateFileHash(byte[] fileData) {
        try {
            // Vulnerable: MD5 for integrity checking
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(fileData);
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // CWE-328: SHA-1 for digital signatures
    public byte[] signData(byte[] data) {
        try {
            // Vulnerable: SHA-1 is broken for signatures
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // CWE-328: Using MD5 for HMAC
    public String generateHMAC(String message, String key) {
        try {
            // Vulnerable: MD5-based HMAC
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] keyBytes = key.getBytes();
            byte[] messageBytes = message.getBytes();
            
            md.update(keyBytes);
            md.update(messageBytes);
            return bytesToHex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // CWE-327: Using ECB mode for multiple blocks
    public byte[] encryptMultipleBlocks(String data) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey key = keyGen.generateKey();
            
            // Vulnerable: ECB mode reveals patterns
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // CWE-328: Truncated hash for comparison
    public boolean comparePasswordHash(String password, byte[] storedHash) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] inputHash = md.digest(password.getBytes());
            
            // Vulnerable: comparing only first 8 bytes
            return Arrays.equals(
                Arrays.copyOf(inputHash, 8),
                Arrays.copyOf(storedHash, 8)
            );
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    // CWE-327: Using RSA with small key size
    public void generateWeakRSAKey() {
        try {
            java.security.KeyPairGenerator keyGen = 
                java.security.KeyPairGenerator.getInstance("RSA");
            // Vulnerable: 1024-bit RSA is weak
            keyGen.initialize(1024);
            java.security.KeyPair pair = keyGen.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // CWE-328: Using CRC32 for security purposes
    public long calculateChecksum(byte[] data) {
        // Vulnerable: CRC32 is not cryptographic
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(data);
        return crc.getValue();
    }
    
    // CWE-327: Null cipher (no encryption)
    public byte[] encryptWithNullCipher(String data) {
        try {
            // Vulnerable: NullCipher provides no encryption
            Cipher cipher = Cipher.getInstance("AES");
            // Using uninitialized cipher or null transformation
            return data.getBytes();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // CWE-328: Using Adler32 for integrity
    public int calculateAdler32(byte[] data) {
        // Vulnerable: Adler32 is not cryptographic
        java.util.zip.Adler32 adler = new java.util.zip.Adler32();
        adler.update(data);
        return (int) adler.getValue();
    }
    
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}
