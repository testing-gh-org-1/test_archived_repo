package com.example.demo;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

// CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
public class RaceConditionVulnerabilities {
    
    // CWE-367: Classic TOCTOU in file operations
    public void writeToFileWithTOCTOU(String filename, String content) {
        File file = new File(filename);
        
        // Vulnerable: check and use are separate operations
        if (!file.exists()) {
            // Time gap - file could be created/modified here by attacker
            try {
                FileOutputStream fos = new FileOutputStream(file);
                fos.write(content.getBytes());
                fos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    
    // CWE-367: TOCTOU in permission check
    public String readFileWithPermissionCheck(String filename, String user) {
        File file = new File(filename);
        
        // Check permission
        if (hasReadPermission(user, filename)) {
            // Time gap - permissions could change here
            try {
                FileInputStream fis = new FileInputStream(file);
                byte[] data = new byte[(int) file.length()];
                fis.read(data);
                fis.close();
                return new String(data);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return null;
    }
    
    // CWE-367: TOCTOU in file deletion
    public boolean deleteFileIfEmpty(String filename) {
        File file = new File(filename);
        
        // Check if empty
        if (file.length() == 0) {
            // Time gap - file content could change
            return file.delete();
        }
        return false;
    }
    
    // CWE-367: TOCTOU with symbolic links
    public void processFileWithSymlinkCheck(String filename) {
        File file = new File(filename);
        
        try {
            // Check if it's a symbolic link
            if (!isSymbolicLink(file)) {
                // Time gap - file could be replaced with symlink
                FileOutputStream fos = new FileOutputStream(file);
                fos.write("sensitive data".getBytes());
                fos.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // CWE-367: TOCTOU in directory traversal check
    public byte[] readSecureFile(String filename) {
        File file = new File(filename);
        
        try {
            // Check if file is in safe directory
            if (file.getCanonicalPath().startsWith("/safe/directory/")) {
                // Time gap - file/symlink could be swapped
                FileInputStream fis = new FileInputStream(file);
                byte[] data = new byte[(int) file.length()];
                fis.read(data);
                fis.close();
                return data;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
    
    // CWE-367: Race condition in temp file creation
    public File createTempFile(String prefix) {
        File tempFile = new File(System.getProperty("java.io.tmpdir"), prefix + ".tmp");
        
        // Check if exists
        if (!tempFile.exists()) {
            // Time gap - attacker could create file here
            try {
                tempFile.createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return tempFile;
    }
    
    // CWE-367: TOCTOU in file ownership check
    public void modifyFileWithOwnershipCheck(String filename, String expectedOwner) {
        File file = new File(filename);
        
        // Check ownership
        if (checkOwnership(file, expectedOwner)) {
            // Time gap - ownership could change
            try {
                FileOutputStream fos = new FileOutputStream(file, true);
                fos.write("appended data".getBytes());
                fos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    
    // CWE-367: Race condition in file rename
    public boolean renameFileWithCheck(String oldName, String newName) {
        File oldFile = new File(oldName);
        File newFile = new File(newName);
        
        // Check if target doesn't exist
        if (!newFile.exists()) {
            // Time gap - target file could be created
            return oldFile.renameTo(newFile);
        }
        return false;
    }
    
    // CWE-367: TOCTOU in access control
    private static boolean accessGranted = false;
    
    public void performPrivilegedOperation(String operation) {
        // Check access
        if (accessGranted) {
            // Time gap - accessGranted could be changed by another thread
            executeOperation(operation);
        }
    }
    
    // CWE-367: Race condition with shared resource
    private static int balance = 1000;
    
    public void withdrawMoney(int amount) {
        // Check balance
        if (balance >= amount) {
            // Time gap - another thread could withdraw
            try {
                Thread.sleep(10); // Simulating processing time
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            balance -= amount;
        }
    }
    
    // CWE-367: TOCTOU in session validation
    private static boolean sessionValid = true;
    
    public void processRequest(String data) {
        // Check session
        if (sessionValid) {
            // Time gap - session could be invalidated
            processSensitiveData(data);
        }
    }
    
    // CWE-367: File existence check before creation
    public void createConfigFile(String filename, String config) {
        File file = new File(filename);
        
        // Check existence
        if (!file.exists()) {
            // Time gap - attacker could create malicious file
            try {
                FileOutputStream fos = new FileOutputStream(file);
                fos.write(config.getBytes());
                fos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    
    private boolean hasReadPermission(String user, String filename) {
        return true; // Simplified
    }
    
    private boolean isSymbolicLink(File file) throws IOException {
        return !file.getAbsolutePath().equals(file.getCanonicalPath());
    }
    
    private boolean checkOwnership(File file, String expectedOwner) {
        return true; // Simplified
    }
    
    private void executeOperation(String operation) {
        System.out.println("Executing: " + operation);
    }
    
    private void processSensitiveData(String data) {
        System.out.println("Processing: " + data);
    }
}
