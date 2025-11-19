package com.example.demo;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

// CWE-284: Improper Access Control
public class AccessControlVulnerabilities {
    
    // CWE-284: Missing access control check
    public void deleteUser(String userId) {
        // Vulnerable: no check if current user has permission
        // Delete user logic
        System.out.println("Deleting user: " + userId);
    }
    
    // CWE-284: Insecure direct object reference
    public String viewDocument(HttpServletRequest request) {
        String docId = request.getParameter("docId");
        // Vulnerable: no ownership or permission check
        return readDocument(docId);
    }
    
    // CWE-284: Missing function-level access control
    public void adminFunction(HttpServletRequest request) {
        // Vulnerable: no admin check
        String action = request.getParameter("action");
        if ("deleteAll".equals(action)) {
            deleteAllUsers();
        }
    }
    
    // CWE-284: Trusting client-side access control
    public void updateProfile(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        String isAdmin = request.getParameter("isAdmin");
        
        // Vulnerable: trusting client-provided admin flag
        if ("true".equals(isAdmin)) {
            updateAdminProfile(userId);
        }
    }
    
    // CWE-284: Missing authorization in API
    public String getPrivateData(String dataId) {
        // Vulnerable: no authorization check
        return "Sensitive data for: " + dataId;
    }
    
    // CWE-284: Horizontal privilege escalation
    public void changeUserEmail(String targetUserId, String newEmail) {
        // Vulnerable: user can change any user's email
        updateEmail(targetUserId, newEmail);
    }
    
    // CWE-284: Vertical privilege escalation
    public void grantAdminAccess(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        // Vulnerable: any user can grant admin access
        grantRole(userId, "ADMIN");
    }
    
    // CWE-284: File access without permission check
    public byte[] downloadFile(String filename) {
        try {
            // Vulnerable: no check if user can access file
            File file = new File("/data/" + filename);
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();
            return data;
        } catch (Exception e) {
            return null;
        }
    }
    
    // CWE-284: Resource access without authentication
    public void accessProtectedResource(String resourceId) {
        // Vulnerable: no authentication check
        System.out.println("Accessing resource: " + resourceId);
    }
    
    // CWE-284: Missing ownership verification
    public void modifyRecord(String recordId, String newData) {
        // Vulnerable: no check if user owns the record
        updateRecord(recordId, newData);
    }
    
    // CWE-284: Session-based access control bypass
    public boolean hasAccess(HttpServletRequest request, String resource) {
        HttpSession session = request.getSession();
        // Vulnerable: weak access control
        return session.getAttribute("userId") != null;
    }
    
    // CWE-284: Unrestricted file upload
    public void uploadFile(HttpServletRequest request, byte[] fileData, String filename) {
        try {
            // Vulnerable: no restriction on file type or size
            FileOutputStream fos = new FileOutputStream("/uploads/" + filename);
            fos.write(fileData);
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // CWE-284: Missing rate limiting
    public void processRequest(HttpServletRequest request) {
        // Vulnerable: no rate limiting
        String action = request.getParameter("action");
        executeAction(action);
    }
    
    private String readDocument(String docId) {
        return "Document content";
    }
    
    private void deleteAllUsers() {
        // Delete all users
    }
    
    private void updateAdminProfile(String userId) {
        // Update admin profile
    }
    
    private void updateEmail(String userId, String email) {
        // Update email
    }
    
    private void grantRole(String userId, String role) {
        // Grant role
    }
    
    private void updateRecord(String recordId, String data) {
        // Update record
    }
    
    private void executeAction(String action) {
        // Execute action
    }
}
