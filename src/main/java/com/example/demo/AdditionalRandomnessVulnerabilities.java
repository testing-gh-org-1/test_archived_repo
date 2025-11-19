package com.example.demo;

import java.security.SecureRandom;
import java.util.Random;
import java.util.UUID;

// CWE-330: Use of Insufficiently Random Values
// CWE-337: Predictable Seed in Pseudo-Random Number Generator (PRNG)
public class AdditionalRandomnessVulnerabilities {
    
    private static Random random = new Random();
    
    // CWE-337: Using current time as seed
    public String generateTokenWithTimeSeed() {
        // Vulnerable: predictable seed based on system time
        Random rng = new Random(System.currentTimeMillis());
        return String.valueOf(rng.nextLong());
    }
    
    // CWE-337: Using fixed seed
    public int generateRandomNumberWithFixedSeed() {
        // Vulnerable: always using the same seed
        Random rng = new Random(12345);
        return rng.nextInt();
    }
    
    // CWE-330: Math.random() for security token
    public String generateSecurityToken() {
        // Vulnerable: using Math.random() for security
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            token.append((int) (Math.random() * 10));
        }
        return token.toString();
    }
    
    // CWE-337: Seed derived from predictable value
    public String generateKeyWithPredictableSeed(String username) {
        // Vulnerable: seed based on username hashCode
        Random rng = new Random(username.hashCode());
        return String.valueOf(rng.nextLong());
    }
    
    // CWE-330: Using UUID version 3 (MD5-based, not random)
    public String generateSessionIdWithMD5UUID(String name) {
        // Vulnerable: MD5-based UUID, not cryptographically secure
        UUID uuid = UUID.nameUUIDFromBytes(name.getBytes());
        return uuid.toString();
    }
    
    // CWE-337: Reusing same Random instance without reseeding
    public String generateMultipleTokens() {
        // Vulnerable: using same Random instance, predictable sequence
        StringBuilder tokens = new StringBuilder();
        for (int i = 0; i < 5; i++) {
            tokens.append(random.nextInt()).append(",");
        }
        return tokens.toString();
    }
    
    // CWE-330: Weak random for password reset
    public String generatePasswordResetCode() {
        // Vulnerable: weak random for security-critical operation
        Random rng = new Random();
        int code = 100000 + rng.nextInt(900000);
        return String.valueOf(code);
    }
    
    // CWE-337: Seed based on counter
    private static int counter = 0;
    
    public long generateIdWithCounterSeed() {
        // Vulnerable: predictable seed from counter
        Random rng = new Random(counter++);
        return rng.nextLong();
    }
    
    // CWE-330: Using Random instead of SecureRandom for encryption key
    public byte[] generateEncryptionKey(int keySize) {
        // Vulnerable: weak random for encryption key
        Random rng = new Random();
        byte[] key = new byte[keySize];
        rng.nextBytes(key);
        return key;
    }
    
    // CWE-337: Seed from user input
    public int generateRandomFromUserInput(String userInput) {
        // Vulnerable: attacker-controlled seed
        long seed = userInput.hashCode();
        Random rng = new Random(seed);
        return rng.nextInt();
    }
    
    // CWE-330: Weak random for lottery/gambling
    public int[] generateLotteryNumbers() {
        // Vulnerable: predictable random for financial application
        Random rng = new Random();
        int[] numbers = new int[6];
        for (int i = 0; i < 6; i++) {
            numbers[i] = rng.nextInt(49) + 1;
        }
        return numbers;
    }
    
    // CWE-337: Using thread ID as seed
    public String generateTokenWithThreadSeed() {
        // Vulnerable: thread ID is predictable
        long seed = Thread.currentThread().getId();
        Random rng = new Random(seed);
        return String.valueOf(rng.nextLong());
    }
    
    // CWE-330: Weak random for challenge-response
    public String generateChallenge() {
        // Vulnerable: predictable challenge in authentication
        Random rng = new Random();
        return String.format("%08d", rng.nextInt(100000000));
    }
    
    // CWE-337: Combining weak seeds doesn't make it strong
    public String generateTokenWithCombinedSeeds() {
        // Vulnerable: still predictable even with combined seeds
        long seed = System.currentTimeMillis() + Thread.currentThread().getId();
        Random rng = new Random(seed);
        return String.valueOf(rng.nextLong());
    }
    
    // CWE-330: Using Random for nonce generation
    public byte[] generateNonce() {
        // Vulnerable: weak random for cryptographic nonce
        Random rng = new Random();
        byte[] nonce = new byte[16];
        rng.nextBytes(nonce);
        return nonce;
    }
}
