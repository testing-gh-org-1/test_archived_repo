package com.example.demo;

import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

// CWE-382: J2EE Bad Practices: Use of System.exit()
// CWE-398: Poor Code Quality
// CWE-400: Uncontrolled Resource Consumption (Additional Examples)
public class CodeQualityAndResourceVulnerabilities {
    
    // CWE-382: Using System.exit() in J2EE application
    public void handleFatalError(Exception e) {
        // Vulnerable: System.exit() in application server
        System.err.println("Fatal error: " + e.getMessage());
        System.exit(1); // Crashes entire application server
    }
    
    // CWE-382: System.exit() in servlet
    public void processRequest(HttpServletRequest request) {
        String action = request.getParameter("action");
        if ("shutdown".equals(action)) {
            // Vulnerable: allows remote shutdown
            System.exit(0);
        }
    }
    
    // CWE-382: Runtime.halt() in application
    public void emergencyShutdown() {
        // Vulnerable: forces JVM termination
        Runtime.getRuntime().halt(1);
    }
    
    // CWE-398: Empty catch block
    public String readFile(String filename) {
        try {
            java.io.FileInputStream fis = new java.io.FileInputStream(filename);
            // Read file
            return "content";
        } catch (Exception e) {
            // Vulnerable: silently swallowing exception
        }
        return null;
    }
    
    // CWE-398: Catching generic Exception
    public void processData(String data) {
        try {
            // Some processing
            Integer.parseInt(data);
        } catch (Exception e) {
            // Vulnerable: too broad exception handling
            System.out.println("Error occurred");
        }
    }
    
    // CWE-398: Magic numbers without constants
    public boolean validateInput(String input) {
        // Vulnerable: magic numbers
        if (input.length() > 255) {
            return false;
        }
        if (input.length() < 8) {
            return false;
        }
        return true;
    }
    
    // CWE-398: Deeply nested code
    public void processNestedLogic(String type, String action, String user, boolean allowed) {
        // Vulnerable: poor code structure
        if (type != null) {
            if (type.equals("admin")) {
                if (action != null) {
                    if (action.equals("delete")) {
                        if (user != null) {
                            if (allowed) {
                                System.out.println("Processing");
                            }
                        }
                    }
                }
            }
        }
    }
    
    // CWE-398: God class with too many responsibilities
    private Map<String, Object> data = new HashMap<>();
    private List<String> logs = new ArrayList<>();
    
    public void performMultipleOperations() {
        // Vulnerable: class doing too many things
        connectDatabase();
        sendEmail();
        processPayment();
        generateReport();
        updateCache();
    }
    
    // CWE-400: Unbounded memory allocation from user input
    public byte[] allocateBuffer(HttpServletRequest request) {
        String sizeParam = request.getParameter("size");
        int size = Integer.parseInt(sizeParam);
        // Vulnerable: attacker can specify huge size
        return new byte[size];
    }
    
    // CWE-400: Unbounded collection growth
    private List<String> requestLog = new ArrayList<>();
    
    public void logRequest(String request) {
        // Vulnerable: list grows without bound
        requestLog.add(request);
    }
    
    // CWE-400: Resource-intensive regex
    public boolean validateComplexPattern(String input) {
        // Vulnerable: catastrophic backtracking
        String regex = "(a+)+b";
        return Pattern.matches(regex, input);
    }
    
    // CWE-400: Nested loops with user-controlled bounds
    public void processMatrix(int rows, int cols) {
        // Vulnerable: user controls loop bounds
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                // Processing
                System.out.println(i + "," + j);
            }
        }
    }
    
    // CWE-400: Reading entire file into memory
    public String readLargeFile(String filename) throws IOException {
        // Vulnerable: no size limit
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(new java.io.FileInputStream(filename))
        );
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line);
        }
        reader.close();
        return content.toString();
    }
    
    // CWE-400: Unlimited socket connections
    private List<Socket> connections = new ArrayList<>();
    
    public void acceptConnection(Socket socket) {
        // Vulnerable: no connection limit
        connections.add(socket);
    }
    
    // CWE-398: Method with too many parameters
    public void createUser(String username, String password, String email, 
                          String firstName, String lastName, String address,
                          String city, String state, String zip, String country,
                          String phone, int age, String gender) {
        // Vulnerable: poor method design
    }
    
    // CWE-398: Duplicated code
    public void sendEmailToAdmin(String message) {
        String from = "system@example.com";
        String to = "admin@example.com";
        String subject = "System notification";
        // Send email logic
        System.out.println("Sending from " + from + " to " + to);
    }
    
    public void sendEmailToUser(String userEmail, String message) {
        String from = "system@example.com";
        String to = userEmail;
        String subject = "System notification";
        // Send email logic (duplicated)
        System.out.println("Sending from " + from + " to " + to);
    }
    
    // CWE-398: Commented out code
    public void processOrder(String orderId) {
        // validateOrder(orderId);
        // checkInventory(orderId);
        // processPayment(orderId);
        
        System.out.println("Processing order: " + orderId);
        
        // sendConfirmation(orderId);
    }
    
    // CWE-400: Creating many threads without limit
    public void processRequests(List<String> requests) {
        // Vulnerable: no thread pool, unlimited threads
        for (String request : requests) {
            new Thread(() -> processRequest(request)).start();
        }
    }
    
    // CWE-398: Long method
    public void processCompleteWorkflow(String data) {
        // Vulnerable: method too long (100+ lines)
        // Line 1-10: validation
        // Line 11-20: parsing
        // Line 21-30: database operations
        // Line 31-40: business logic
        // Line 41-50: more processing
        // ... and so on
        System.out.println("Processing: " + data);
    }
    
    private void connectDatabase() {}
    private void sendEmail() {}
    private void processPayment() {}
    private void generateReport() {}
    private void updateCache() {}
    private void processRequest(String request) {}
}
