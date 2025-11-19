package com.example.demo;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

// CWE-285: Improper Authorization
public class AdditionalAuthorizationVulnerabilities {
    
    private Map<String, String> userRoles = new HashMap<>();
    
    // CWE-285: Missing role-based access control
    public void performAdminAction(HttpServletRequest request) {
        // Vulnerable: no check if user has admin role
        String action = request.getParameter("action");
        executeAdminCommand(action);
    }
    
    // CWE-285: Insufficient authorization check
    public String viewSalaryData(String employeeId, String requesterId) {
        // Vulnerable: only checking if requester is authenticated, not authorized
        if (requesterId != null && !requesterId.isEmpty()) {
            return getSalaryInfo(employeeId);
        }
        return null;
    }
    
    // CWE-285: Authorization based on client input
    public void updateUserProfile(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        String role = request.getParameter("role");
        
        // Vulnerable: trusting client-provided role
        if ("admin".equals(role)) {
            updateWithAdminPrivileges(userId);
        } else {
            updateWithUserPrivileges(userId);
        }
    }
    
    // CWE-285: Missing authorization for API endpoint
    public void deleteAllRecords(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Vulnerable: no authorization check before dangerous operation
        String confirmDelete = request.getParameter("confirm");
        if ("yes".equals(confirmDelete)) {
            deleteAllData();
            response.getWriter().println("All records deleted");
        }
    }
    
    // CWE-285: Weak authorization logic
    public boolean canAccessFinancialReports(String userId) {
        // Vulnerable: weak logic, anyone with "admin" in username gets access
        return userId != null && userId.toLowerCase().contains("admin");
    }
    
    // CWE-285: Path-based authorization bypass
    public void serveRestrictedFile(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filePath = request.getParameter("file");
        
        // Vulnerable: weak path check
        if (!filePath.startsWith("/admin/")) {
            // Bypassed with /admin/../sensitive.txt
            java.io.File file = new java.io.File(filePath);
            if (file.exists()) {
                java.nio.file.Files.copy(file.toPath(), response.getOutputStream());
            }
        }
    }
    
    // CWE-285: Time-based authorization flaw
    public boolean canAccessResource(String userId, long timestamp) {
        // Vulnerable: accepting client-provided timestamp
        long currentTime = System.currentTimeMillis();
        long timeDiff = currentTime - timestamp;
        
        // Anyone can send old timestamp to bypass
        return timeDiff < 3600000; // 1 hour
    }
    
    // CWE-285: Missing ownership check
    public void modifyDocument(String documentId, String content, String userId) {
        // Vulnerable: not checking if user owns the document
        updateDocument(documentId, content);
    }
    
    // CWE-285: Group-based authorization bypass
    public boolean hasGroupAccess(String userId, String groupId) {
        // Vulnerable: weak group membership check
        return userRoles.containsKey(userId);
    }
    
    // CWE-285: State-based authorization flaw
    public void approveRequest(HttpServletRequest request) {
        String requestId = request.getParameter("requestId");
        HttpSession session = request.getSession();
        
        // Vulnerable: not checking if user has approval authority
        if (session.getAttribute("userId") != null) {
            approveInternalRequest(requestId);
        }
    }
    
    // CWE-285: Authorization via HTTP method
    public void handleRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String method = request.getMethod();
        
        // Vulnerable: assuming GET is safe, but allows parameter-based actions
        if ("GET".equals(method)) {
            String action = request.getParameter("action");
            if ("delete".equals(action)) {
                deleteResource(request.getParameter("id"));
            }
        }
    }
    
    // CWE-285: Missing re-authorization for privilege escalation
    public void changeUserRole(String targetUserId, String newRole) {
        // Vulnerable: no re-authentication required for sensitive operation
        userRoles.put(targetUserId, newRole);
    }
    
    // CWE-285: Authorization check after use
    public String getConfidentialData(String userId, String dataId) {
        // Vulnerable: fetching data before checking authorization
        String data = fetchData(dataId);
        
        if (isAuthorized(userId, dataId)) {
            return data;
        }
        // Data already loaded into memory
        return null;
    }
    
    // CWE-285: Client-side authorization
    public void processRequest(HttpServletRequest request) {
        String authorized = request.getParameter("authorized");
        
        // Vulnerable: trusting client-side authorization flag
        if ("true".equals(authorized)) {
            performSensitiveOperation();
        }
    }
    
    private void executeAdminCommand(String command) {
        System.out.println("Executing: " + command);
    }
    
    private String getSalaryInfo(String employeeId) {
        return "Salary: $100,000";
    }
    
    private void updateWithAdminPrivileges(String userId) {
        System.out.println("Admin update for: " + userId);
    }
    
    private void updateWithUserPrivileges(String userId) {
        System.out.println("User update for: " + userId);
    }
    
    private void deleteAllData() {
        System.out.println("Deleting all data");
    }
    
    private void updateDocument(String docId, String content) {
        System.out.println("Updating document: " + docId);
    }
    
    private void approveInternalRequest(String requestId) {
        System.out.println("Approving request: " + requestId);
    }
    
    private void deleteResource(String id) {
        System.out.println("Deleting resource: " + id);
    }
    
    private String fetchData(String dataId) {
        return "Confidential data for: " + dataId;
    }
    
    private boolean isAuthorized(String userId, String dataId) {
        return false;
    }
    
    private void performSensitiveOperation() {
        System.out.println("Performing sensitive operation");
    }
}
